//! The actor that runs network probes and publishes a [`Report`].
//!
//! [`NetReportActor`] runs in the background for as long as the endpoint is
//! alive. It learns about the network in three ways and writes what it finds
//! into a [`Report`] that callers watch:
//!
//! - QAD (QUIC Address Discovery) opens a QUIC connection to a relay. The
//!   relay reports the public address it sees us coming from, and the round
//!   trip measures our latency to that relay.
//! - An HTTPS probe measures latency to a relay with a plain GET request. It
//!   finds no address, but it still works on networks that block QUIC.
//! - The captive portal check looks for a network that intercepts HTTP.
//!
//! QAD connections are long-lived, and that shapes the rest. For each
//! address family the actor races a probe to several relays, keeps the
//! connection that answers first, and closes the others. It then holds that
//! connection open. The relay only sees our address from the packets we
//! send, so a change is not reported the instant it happens: the
//! connection's keep-alive prompts the relay to re-observe within seconds,
//! and a network change we notice ourselves starts a fresh probe at once.
//! Either way the update arrives on the same [`ProbeEvent`] channel as probe
//! results, so everything the actor learns lands in one place.
//!
//! A probe cycle is a round of probing triggered by a request. Because the
//! open QAD connections already keep addresses current, a cycle is mostly
//! about the rest: measuring latency to every relay over HTTPS, picking the
//! preferred relay, and checking for a captive portal. [`ProbeScope`] sets
//! how much of that a cycle does, and [`ProbeCycle`] holds the one in
//! flight. A cycle publishes a first report within [`FIRST_REPORT_TIMEOUT`]
//! even while probes are still running, and gives up on any stragglers after
//! [`ABORT_TIMEOUT`].

use std::{collections::BTreeSet, future::Future, sync::Arc};

#[cfg(not(wasm_browser))]
use iroh_dns::dns::DnsResolver;
use iroh_relay::RelayMap;
#[cfg(not(wasm_browser))]
use iroh_relay::quic::{QUIC_ADDR_DISC_CLOSE_CODE, QUIC_ADDR_DISC_CLOSE_REASON, QuicClient};
use n0_future::{
    MaybeFuture,
    task::JoinSet,
    time::{self, Duration, Instant},
};
use n0_watcher::Watchable;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, Span, debug, error, info_span, trace};

#[cfg(not(wasm_browser))]
use super::captive_portal::CaptivePortalError;
#[cfg(not(wasm_browser))]
use super::qad::{AddrFamily, QadConn, QadProbeError, QadProbeReport};
use super::{
    IfState, Options, Report,
    defaults::timeouts::{
        ABORT_TIMEOUT, CAPTIVE_PORTAL_DELAY, CAPTIVE_PORTAL_TIMEOUT, FIRST_REPORT_TIMEOUT,
        FULL_REPORT_INTERVAL, HTTPS_PROBE_TIMEOUT,
    },
    https::{HttpsProbeReport, MeasureHttpsLatencyError},
    metrics::Metrics,
    probes::{Probe, ProbePlan},
    report::RelayLatencies,
};
#[cfg(not(wasm_browser))]
use super::{NetReportConfig, defaults::timeouts::QAD_PROBE_TIMEOUT};

/// Capacity of the actor's event channel.
const EVENT_CHANNEL_CAP: usize = 64;

/// The outcome of running a probe under a timeout and a cancellation token: it
/// succeeded, failed with the probe's own error, timed out, or was cancelled.
/// Keeping timeout and cancellation out of the probe's error type lets each
/// error stay a pure domain error.
pub(super) enum ProbeOutcome<T, E> {
    Ok(T),
    Err(E),
    Timeout,
    Cancelled,
}

/// `Send` on native targets, no bound in the browser, where tasks run on a
/// single thread and browser futures are not `Send`. Lets a spawn helper be
/// generic over both.
#[cfg(not(wasm_browser))]
trait MaybeSend: Send {}
#[cfg(not(wasm_browser))]
impl<T: Send + ?Sized> MaybeSend for T {}
#[cfg(wasm_browser)]
trait MaybeSend {}
#[cfg(wasm_browser)]
impl<T: ?Sized> MaybeSend for T {}

/// A probe request waiting for the actor to pick it up.
///
/// Several [`Client::run_probes`](super::Client::run_probes) calls can
/// arrive before the actor handles them. They collapse into this one
/// request, which takes the most urgent [`ProbeScope`] of the batch and
/// waits here until the actor takes it.
pub(super) struct ProbeRequest {
    pub if_state: IfState,
    pub scope: ProbeScope,
}

/// A one-slot mailbox that carries a [`ProbeRequest`] from a
/// [`Client`](super::Client) to the [`NetReportActor`].
///
/// It holds at most one request. A second request that arrives before the
/// actor has taken the first does not queue behind it; it merges into it,
/// raising the [`ProbeScope`] to the more urgent of the two and keeping the
/// newer interface state. This is why it is a hand-written slot and not a
/// channel: a channel would queue the requests, and probing twice in a row
/// wastes work when one probe with the combined scope would do.
pub(super) struct RequestSlot {
    slot: std::sync::Mutex<Option<ProbeRequest>>,
    notify: tokio::sync::Notify,
}

impl std::fmt::Debug for RequestSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestSlot").finish_non_exhaustive()
    }
}

impl RequestSlot {
    pub(super) fn new() -> Self {
        Self {
            slot: std::sync::Mutex::new(None),
            notify: tokio::sync::Notify::new(),
        }
    }

    /// Merges a probe request into the slot.
    ///
    /// If a request is already pending, the scope is escalated to the more
    /// urgent of the two and `if_state` is overwritten with the latest
    /// value. If no request is pending, a new one is created.
    pub(super) fn request(&self, if_state: IfState, scope: ProbeScope) {
        let mut guard = self.slot.lock().expect("not poisoned");
        match guard.as_mut() {
            Some(pending) => {
                pending.scope = pending.scope.max(scope);
                pending.if_state = if_state;
            }
            None => {
                *guard = Some(ProbeRequest { if_state, scope });
            }
        }
        drop(guard);
        self.notify.notify_one();
    }

    /// Takes the pending request, leaving the slot empty.
    fn take(&self) -> Option<ProbeRequest> {
        self.slot.lock().expect("not poisoned").take()
    }
}

/// A message from a probe task to the [`NetReportActor`].
///
/// Each probe a cycle starts sends exactly one final result: `QadResult`,
/// `Https`, or `CaptivePortal`. The actor counts these to know when the
/// cycle is done. An open QAD connection is different: it sends a
/// `QadObservation` every time our address changes, for as long as it stays
/// open, and those belong to no cycle.
pub(super) enum ProbeEvent {
    /// A QAD probe finished. On success it carries the connection to keep
    /// open.
    #[cfg(not(wasm_browser))]
    QadResult(
        AddrFamily,
        ProbeOutcome<(QadProbeReport, QadConn), QadProbeError>,
    ),
    /// An open QAD connection reported an address, possibly a new one.
    #[cfg(not(wasm_browser))]
    QadObservation(AddrFamily, QadProbeReport),
    /// An HTTPS latency probe finished.
    Https(ProbeOutcome<HttpsProbeReport, MeasureHttpsLatencyError>),
    /// The captive portal check finished.
    #[cfg(not(wasm_browser))]
    CaptivePortal(ProbeOutcome<bool, CaptivePortalError>),
}

/// How much of the probe set a cycle runs.
///
/// The scope plays two roles. On the request that starts a cycle it says how
/// urgent the trigger is: a `Full` request comes from a real network change,
/// so it aborts any cycle in progress and starts over, while a `Refresh`
/// request waits for the current cycle to finish. On the cycle itself it
/// says how much to probe.
///
/// The open QAD connections keep our address up to date on their own, within
/// their keep-alive interval (see the [module docs](self)), so neither scope
/// has to probe QAD just to stay current. The difference is what else a cycle
/// does:
///
/// - `Full` throws away the open QAD connections and starts from nothing. It
///   opens a fresh QAD connection for every available family, measures
///   latency to every relay over HTTPS, and runs the captive portal check.
///   This is what a real network change calls for.
/// - `Refresh` keeps the open QAD connections and only does the work they do
///   not cover. It re-measures relay latency over HTTPS and re-picks the
///   preferred relay, and it opens a QAD connection only for a family that
///   has none, because its connection dropped or its interface just came up.
///   It skips the captive portal check.
///
/// A `Refresh` request can still turn into a `Full` cycle: the actor forces
/// one when the full-report interval has elapsed, or when the last report
/// found a captive portal and no working UDP.
///
/// The variants order `Refresh < Full` so that merging two pending requests
/// can just take the more urgent one with `max`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ProbeScope {
    /// Keep the open QAD connections. Re-measure relay latency and reconnect
    /// any family that has no open connection.
    Refresh,
    /// Close the open QAD connections and run every probe from scratch.
    Full,
}

impl ProbeScope {
    /// Maps a netmon "is major change" flag to a [`ProbeScope`].
    pub(crate) fn from_major(is_major: bool) -> Self {
        if is_major { Self::Full } else { Self::Refresh }
    }
}

/// Per-family QAD progress within a cycle.
#[derive(Debug, Clone, Copy, Default)]
struct QadFamily {
    /// This cycle is probing the family.
    probing: bool,
    /// The family is determined: it has an address, or all of its probes have
    /// finished (so the family is genuinely down).
    determined: bool,
    /// QAD probes still outstanding for the family.
    #[cfg(not(wasm_browser))]
    outstanding: usize,
}

impl QadFamily {
    /// State for a family with `probes` QAD probes started.
    fn new(probes: usize) -> Self {
        QadFamily {
            probing: probes > 0,
            determined: false,
            #[cfg(not(wasm_browser))]
            outstanding: probes,
        }
    }
}

/// QAD progress for both address families within a cycle.
#[derive(Debug, Clone, Copy, Default)]
struct QadState {
    v4: QadFamily,
    v6: QadFamily,
}

impl QadState {
    /// Builds the cycle's QAD gate state from the number of probes started per
    /// family.
    fn new(v4_probes: usize, v6_probes: usize) -> Self {
        QadState {
            v4: QadFamily::new(v4_probes),
            v6: QadFamily::new(v6_probes),
        }
    }

    /// Returns `true` once every family this cycle is probing is determined.
    /// The first report is held until this holds (or [`FIRST_REPORT_TIMEOUT`]
    /// fires), so consumers do not see a v4-only report a moment before v6.
    fn all_determined(&self) -> bool {
        (!self.v4.probing || self.v4.determined) && (!self.v6.probing || self.v6.determined)
    }

    /// Records that one of `family`'s probes finished with `outcome`.
    ///
    /// The family becomes determined on its first success or once all of its
    /// probes are done, so a fast failure does not gate a premature
    /// family-negative first report.
    #[cfg(not(wasm_browser))]
    fn record_result<T, E>(&mut self, family: AddrFamily, outcome: &ProbeOutcome<T, E>) {
        let fam = self.family_mut(family);
        fam.outstanding = fam.outstanding.saturating_sub(1);
        if matches!(outcome, ProbeOutcome::Ok(_)) || fam.outstanding == 0 {
            fam.determined = true;
        }
    }

    #[cfg(not(wasm_browser))]
    fn family_mut(&mut self, family: AddrFamily) -> &mut QadFamily {
        match family {
            AddrFamily::V4 => &mut self.v4,
            AddrFamily::V6 => &mut self.v6,
        }
    }
}

/// Tracks recent reports for preferred-relay selection and full-cycle
/// cadence.
#[derive(Debug)]
struct ReportHistory {
    /// When true, the next cycle is forced to be `Full` rather than `Refresh`.
    next_full: bool,
    /// Reports from the last five minutes, keyed by completion time.
    prev: std::collections::BTreeMap<Instant, Report>,
    /// The most recent completed report.
    last: Option<Report>,
    /// Time of the last `Full` report.
    last_full: Instant,
}

impl Default for ReportHistory {
    fn default() -> Self {
        Self {
            next_full: true,
            prev: Default::default(),
            last: Default::default(),
            last_full: Instant::now(),
        }
    }
}

impl ReportHistory {
    /// Records `r` and sets `r.preferred_relay` to the best candidate
    /// across the last five minutes of reports.
    ///
    /// Applies hysteresis: the preferred relay only changes when the new
    /// candidate is at least 33% faster than the current one.
    fn record(&mut self, r: &mut Report) {
        let mut prev_relay = None;
        if let Some(ref last) = self.last {
            prev_relay.clone_from(&last.preferred_relay);

            if r.mapping_varies_by_dest_ipv4.is_none() {
                r.mapping_varies_by_dest_ipv4 = last.mapping_varies_by_dest_ipv4;
            }
            if r.mapping_varies_by_dest_ipv6.is_none() {
                r.mapping_varies_by_dest_ipv6 = last.mapping_varies_by_dest_ipv6;
            }
        }

        let now = Instant::now();
        const MAX_AGE: Duration = Duration::from_secs(5 * 60);

        let mut best_recent = RelayLatencies::default();

        let mut to_remove = Vec::new();
        for (t, pr) in self.prev.iter() {
            if now.duration_since(*t) > MAX_AGE {
                to_remove.push(*t);
                continue;
            }
            best_recent.merge(&pr.relay_latency);
        }
        best_recent.merge(&r.relay_latency);

        for t in to_remove {
            self.prev.remove(&t);
        }

        let mut best_any = Duration::default();
        let mut old_relay_cur_latency = Duration::default();
        for (_, url, duration) in r.relay_latency.iter() {
            if Some(url) == prev_relay.as_ref() {
                old_relay_cur_latency = duration;
            }
            if let Some(best) = best_recent.get(url)
                && (r.preferred_relay.is_none() || best < best_any)
            {
                best_any = best;
                r.preferred_relay.replace(url.clone());
            }
        }

        // Hysteresis: don't switch if the new relay isn't much better.
        if prev_relay.is_some()
            && r.preferred_relay != prev_relay
            && !old_relay_cur_latency.is_zero()
            && best_any > old_relay_cur_latency / 3 * 2
        {
            r.preferred_relay = prev_relay;
        }

        self.prev.insert(now, r.clone());
        self.last = Some(r.clone());
    }

    /// Decides the scope of the next cycle.
    ///
    /// A `Full` request always yields a `Full` cycle. A `Refresh` request is
    /// promoted to `Full` on the first cycle, once the full-report interval has
    /// elapsed, or when the last report saw a captive portal without UDP.
    fn scope_for(&self, request: ProbeScope, now: Instant) -> ProbeScope {
        let full = request == ProbeScope::Full
            || self.next_full
            || now.duration_since(self.last_full) > FULL_REPORT_INTERVAL
            || self
                .last
                .as_ref()
                .is_some_and(|r| !r.has_udp() && r.captive_portal == Some(true));
        ProbeScope::from_major(full)
    }
}

/// State of the currently running probe cycle.
struct ProbeCycle {
    started: Instant,
    /// Probe tasks that have not yet reported a terminal result.
    pending: usize,
    /// Per-family QAD progress, used to gate the first report.
    qad: QadState,
    /// Whether the first report of this cycle has been published yet.
    published: bool,
    /// A `Refresh` request that arrived mid-cycle, run when this one ends.
    rerun: Option<ProbeRequest>,
    /// Fires at [`FIRST_REPORT_TIMEOUT`]; `None` once fired.
    report_deadline: Option<Instant>,
    /// Fires at [`ABORT_TIMEOUT`]; `None` once fired.
    abort_deadline: Option<Instant>,
}

/// Actor that owns all probe state and emits report updates via
/// `report_out` as probe results arrive.
///
/// See the [module documentation](self) for an overview.
pub(super) struct NetReportActor {
    probe_requests: Arc<RequestSlot>,
    shutdown: CancellationToken,
    metrics: Arc<Metrics>,

    relay_map: RelayMap,
    /// QUIC client for QAD probes; `None` when QAD is disabled. Cloned into
    /// each QAD probe task.
    #[cfg(not(wasm_browser))]
    quic_client: Option<QuicClient>,
    /// DNS resolver, cloned into each probe task that resolves relay hosts.
    #[cfg(not(wasm_browser))]
    dns_resolver: DnsResolver,
    #[cfg(not(wasm_browser))]
    tls_config: rustls::ClientConfig,
    protocols: BTreeSet<Probe>,
    /// User-facing configuration: whether to run captive portal detection, and
    /// the QAD probe stagger delay. (`https_probes` is already resolved into
    /// `protocols`.)
    #[cfg(not(wasm_browser))]
    user_config: NetReportConfig,

    /// Owns every one-shot probe task so shutdown aborts them all. Results
    /// arrive through `events`, not `join_next`; this only reaps finished
    /// handles and surfaces panics.
    tasks: JoinSet<()>,
    events_tx: mpsc::Sender<ProbeEvent>,
    events: mpsc::Receiver<ProbeEvent>,
    /// The open QAD connection kept for each family, reused across cycles.
    /// Each one owns its observer task through an `AbortOnDropHandle`, so
    /// dropping or replacing a connection stops that task.
    #[cfg(not(wasm_browser))]
    qad_conns: super::qad::QadConns,
    /// Cancelled when every relay has at least one latency sample.
    cancel_https: CancellationToken,
    /// Cancelled when a QAD probe confirms UDP works.
    #[cfg(not(wasm_browser))]
    cancel_captive_portal: CancellationToken,

    /// The report we are building. It is cleared at the start of each cycle
    /// and refilled from the open QAD connections; between cycles, address
    /// observations update it in place.
    report: Report,
    reports: ReportHistory,
    report_out: Watchable<Option<Report>>,
    /// The in-flight cycle, or `None` when idle.
    cycle: Option<ProbeCycle>,
}

impl NetReportActor {
    pub(super) fn new(
        probe_requests: Arc<RequestSlot>,
        report_out: Watchable<Option<Report>>,
        relay_map: RelayMap,
        opts: Options,
        #[cfg(not(wasm_browser))] dns_resolver: DnsResolver,
        shutdown: CancellationToken,
        metrics: Arc<Metrics>,
    ) -> Self {
        let protocols = opts.as_protocols();
        let (events_tx, events) = mpsc::channel(EVENT_CHANNEL_CAP);

        #[cfg(not(wasm_browser))]
        let quic_client = opts
            .quic_config
            .map(|c| QuicClient::new(c.ep, c.client_config));

        Self {
            probe_requests,
            shutdown,
            metrics,
            relay_map,
            #[cfg(not(wasm_browser))]
            quic_client,
            #[cfg(not(wasm_browser))]
            dns_resolver,
            #[cfg(not(wasm_browser))]
            tls_config: opts.tls_config,
            protocols,
            #[cfg(not(wasm_browser))]
            user_config: opts.user_config,
            tasks: JoinSet::new(),
            events_tx,
            events,
            #[cfg(not(wasm_browser))]
            qad_conns: super::qad::QadConns::default(),
            cancel_https: CancellationToken::new(),
            #[cfg(not(wasm_browser))]
            cancel_captive_portal: CancellationToken::new(),
            report: Report::default(),
            reports: ReportHistory::default(),
            report_out,
            cycle: None,
        }
    }

    /// Runs the actor until the shutdown token is cancelled.
    ///
    /// On shutdown, dropping `self` drops the [`JoinSet`] and the QAD
    /// connections, aborting every task the actor owns.
    pub(super) async fn run(mut self) {
        loop {
            let report_deadline = match self.cycle.as_ref().and_then(|c| c.report_deadline) {
                Some(t) => MaybeFuture::Some(time::sleep_until(t)),
                None => MaybeFuture::None,
            };
            let abort_deadline = match self.cycle.as_ref().and_then(|c| c.abort_deadline) {
                Some(t) => MaybeFuture::Some(time::sleep_until(t)),
                None => MaybeFuture::None,
            };
            n0_future::pin!(report_deadline);
            n0_future::pin!(abort_deadline);

            tokio::select! {
                biased;

                _ = self.shutdown.cancelled() => break,

                _ = self.probe_requests.notify.notified() => {
                    if let Some(req) = self.probe_requests.take() {
                        self.handle_request(req);
                    }
                }

                Some(ev) = self.events.recv() => self.handle_event(ev),

                Some(joined) = self.tasks.join_next() => {
                    if let Err(err) = joined {
                        // A task that panicked never sent its terminal
                        // event, so account for it here and let the cycle
                        // finalize. (Aborted tasks live in a dropped
                        // JoinSet and are never yielded here.)
                        if err.is_panic() {
                            error!("probe task panicked: {err:#}");
                        }
                        self.probe_finished();
                        self.advance();
                    }
                }

                _ = &mut report_deadline => self.on_report_deadline(),
                _ = &mut abort_deadline => self.on_abort_deadline(),
            }
        }
    }

    /// Handles a probe request: defer it, restart the cycle, or start one.
    fn handle_request(&mut self, req: ProbeRequest) {
        if self.relay_map.is_empty() {
            debug!("skipping net_report, empty RelayMap");
            return;
        }

        if let Some(cycle) = &mut self.cycle {
            match req.scope {
                ProbeScope::Refresh => {
                    // Defer: run right after the current cycle finishes so
                    // the trigger is not lost (the old DirectAddrUpdateState
                    // remembered this via `want_update`). Only `Refresh`
                    // requests are deferred, so the remembered scope stays
                    // `Refresh`; just take the latest interface state.
                    match &mut cycle.rerun {
                        Some(pending) => pending.if_state = req.if_state,
                        None => cycle.rerun = Some(req),
                    }
                    debug!("deferring probe request until current cycle finishes");
                    return;
                }
                // Full: abort the current cycle and start fresh.
                ProbeScope::Full => self.abort_cycle(),
            }
        }

        self.start_cycle(req);
    }

    /// Aborts the current cycle's probe tasks and swaps in a fresh event
    /// channel, so any results those tasks already queued are dropped instead
    /// of leaking into the next cycle. Only a `Full` restart does this, and a
    /// `Full` restart also closes the open QAD connections, so no observer
    /// task is left running without an owner.
    fn abort_cycle(&mut self) {
        self.tasks = JoinSet::new();
        let (tx, rx) = mpsc::channel(EVENT_CHANNEL_CAP);
        self.events_tx = tx;
        self.events = rx;
        self.cycle = None;
    }

    /// Starts a new probe cycle.
    fn start_cycle(&mut self, req: ProbeRequest) {
        let ProbeRequest {
            if_state,
            scope: request_scope,
        } = req;
        let now = Instant::now();
        let scope = self.reports.scope_for(request_scope, now);

        debug!(?request_scope, ?scope, "starting probe cycle");

        if scope == ProbeScope::Full {
            #[cfg(not(wasm_browser))]
            self.qad_conns.clear();
            self.reports.last = None;
            self.reports.next_full = false;
            self.reports.last_full = now;
            self.metrics.reports_full.inc();
        }
        self.metrics.reports.inc();

        // Start the report from scratch. spawn_qad_probes copies the last
        // address from each still-open QAD connection back in.
        self.report = Report::default();
        self.cancel_https = CancellationToken::new();

        #[cfg(not(wasm_browser))]
        let (qad_v4, qad_v6) = self.spawn_qad_probes(&if_state);
        #[cfg(wasm_browser)]
        let (qad_v4, qad_v6) = (0usize, 0usize);
        let qad = QadState::new(qad_v4, qad_v6);
        let mut pending = qad_v4 + qad_v6 + self.spawn_https_probes();
        #[cfg(not(wasm_browser))]
        if scope == ProbeScope::Full && self.user_config.captive_portal_check {
            self.spawn_captive_portal();
            pending += 1;
        }

        self.cycle = Some(ProbeCycle {
            started: now,
            pending,
            qad,
            published: false,
            rerun: None,
            report_deadline: Some(now + FIRST_REPORT_TIMEOUT),
            abort_deadline: Some(now + ABORT_TIMEOUT),
        });

        // A cycle can start with no probes at all: every family already has
        // an open connection and HTTPS is off. It is already complete, so
        // finalize now to still update history and the preferred relay.
        self.advance();
    }

    /// Applies one event to the report and drives the cycle forward.
    fn handle_event(&mut self, ev: ProbeEvent) {
        match ev {
            #[cfg(not(wasm_browser))]
            ProbeEvent::QadResult(family, run) => {
                if let Some(c) = &mut self.cycle {
                    c.qad.record_result(family, &run);
                }
                self.probe_finished();
                match run {
                    ProbeOutcome::Ok((report, conn)) => {
                        debug!(?family, ?report, "QAD probe completed");
                        // Accumulate: the first result sets the global
                        // address; a second result from a different relay
                        // decides mapping-varies-by-destination.
                        self.report.apply_qad_result(family, &report);
                        if self.qad_conns.slot(family).is_none() {
                            // First result for this family: keep this
                            // connection open, but let the other probes run
                            // so a second result can decide mapping-varies.
                            *self.qad_conns.slot_mut(family) = Some((report.relay_url, conn));
                        } else {
                            // Second result: mapping-varies is decided, so
                            // stop the family's remaining probes and drop
                            // this connection.
                            conn.conn
                                .close(QUIC_ADDR_DISC_CLOSE_CODE, QUIC_ADDR_DISC_CLOSE_REASON);
                            self.qad_conns.cancel(family).cancel();
                        }
                        // UDP works, so skip captive portal detection.
                        self.cancel_captive_portal.cancel();
                    }
                    ProbeOutcome::Err(e) => debug!(?family, "QAD probe failed: {e:#}"),
                    ProbeOutcome::Timeout => debug!(?family, "QAD probe timed out"),
                    ProbeOutcome::Cancelled => {}
                }
                self.publish();
                self.advance();
            }
            #[cfg(not(wasm_browser))]
            ProbeEvent::QadObservation(family, obs) => {
                // Take observations only from the connection we kept for this
                // family. A probe we dropped may still send one last
                // observation before its task ends; ignore it.
                let is_current = self
                    .qad_conns
                    .slot(family)
                    .is_some_and(|(url, _)| *url == obs.relay_url);
                if is_current {
                    trace!(?family, ?obs, "QAD address observation");
                    if let Some((_, conn)) = self.qad_conns.slot_mut(family) {
                        conn.last = obs.clone();
                    }
                    self.report.apply_qad_observation(family, &obs);
                    self.publish();
                }
            }
            ProbeEvent::Https(run) => {
                self.probe_finished();
                match run {
                    ProbeOutcome::Ok(report) => {
                        debug!(?report, "HTTPS probe completed");
                        self.report.apply_https_result(&report);
                        if self.have_all_relay_latencies() {
                            self.cancel_https.cancel();
                        }
                    }
                    ProbeOutcome::Err(e) => debug!("HTTPS probe failed: {e:#}"),
                    ProbeOutcome::Timeout => debug!("HTTPS probe timed out"),
                    ProbeOutcome::Cancelled => {}
                }
                self.publish();
                self.advance();
            }
            #[cfg(not(wasm_browser))]
            ProbeEvent::CaptivePortal(run) => {
                self.probe_finished();
                match run {
                    ProbeOutcome::Ok(found) => {
                        debug!(found, "captive portal check completed");
                        self.report.captive_portal = Some(found);
                    }
                    ProbeOutcome::Err(e) => debug!("captive portal check failed: {e:#}"),
                    ProbeOutcome::Timeout => debug!("captive portal check timed out"),
                    // Cancelled is expected: a successful QAD cancels this check.
                    ProbeOutcome::Cancelled => {}
                }
                self.publish();
                self.advance();
            }
        }
    }

    /// Records that one cycle probe has finished (however it exited).
    fn probe_finished(&mut self) {
        if let Some(c) = &mut self.cycle {
            c.pending = c.pending.saturating_sub(1);
        }
    }

    /// Publishes the current report, unless a guard holds it back.
    ///
    /// Two guards apply. An empty report is never published, since it would
    /// overwrite addresses a caller has already seen. And the first report of
    /// a cycle waits until every family the cycle probed has a result, so a
    /// caller does not briefly see an IPv4-only report just before the IPv6
    /// address arrives.
    fn publish(&mut self) {
        if !self.report.has_data() {
            return;
        }
        if let Some(c) = &self.cycle
            && !c.published
            && !c.qad.all_determined()
        {
            return;
        }
        if let Some(c) = &mut self.cycle {
            c.published = true;
        }
        self.report_out.set(Some(self.report.clone())).ok();
    }

    /// Finalizes the cycle if all its probes have finished.
    fn advance(&mut self) {
        if self.cycle.as_ref().is_some_and(|c| c.pending == 0) {
            self.finish_cycle();
        }
    }

    /// Commits the cycle to history, selects the preferred relay, and emits
    /// the final report. Then applies any deferred rerun request.
    fn finish_cycle(&mut self) {
        let Some(cycle) = self.cycle.take() else {
            return;
        };
        self.reports.record(&mut self.report);
        // Emit the final report, now stamped with the preferred relay. This
        // often repeats the last incremental value; `Watchable::set` only
        // notifies watchers on change, so an identical final emit is a no-op.
        // Keep the last good report rather than overwriting it with an empty
        // one when a cycle discovered nothing.
        if self.report.has_data() {
            self.report_out.set(Some(self.report.clone())).ok();
        }
        debug!(
            report = ?self.report,
            duration = ?cycle.started.elapsed(),
            "net_report cycle complete",
        );
        if let Some(rerun) = cycle.rerun {
            self.handle_request(rerun);
        }
    }

    /// The first-report deadline fired. Publish what we have now, even if
    /// some probed families have not answered yet.
    fn on_report_deadline(&mut self) {
        debug!("report deadline fired");
        if let Some(c) = &mut self.cycle {
            c.report_deadline = None;
            c.published = true;
        }
        self.publish();
    }

    /// Abort deadline: stop remaining probes and finalize with what we have.
    fn on_abort_deadline(&mut self) {
        debug!("abort deadline fired, finalizing cycle");
        // Aborting drops the tasks, so they send no further events.
        self.tasks = JoinSet::new();
        if let Some(c) = &mut self.cycle {
            c.abort_deadline = None;
            c.pending = 0;
        }
        self.finish_cycle();
    }

    /// Returns `true` when every relay has at least one latency sample.
    /// Used to cancel remaining HTTPS probes once coverage is complete.
    fn have_all_relay_latencies(&self) -> bool {
        let num_relays = self.relay_map.len();
        if num_relays == 0 {
            return true;
        }
        let mut seen = BTreeSet::new();
        for (_, url, _) in self.report.relay_latency.iter() {
            seen.insert(url);
        }
        seen.len() >= num_relays
    }

    /// Starts a QAD probe for each family that needs one, and returns how many
    /// it started per family (v4, v6).
    ///
    /// A family needs a probe only when it has no open connection. Before
    /// deciding, any connection that has since closed is dropped, and the
    /// last address of each surviving connection is copied into the report.
    #[cfg(not(wasm_browser))]
    fn spawn_qad_probes(&mut self, if_state: &IfState) -> (usize, usize) {
        let Some(quic_client) = self.quic_client.clone() else {
            return (0, 0);
        };

        // Drop any connection that has closed, then copy the last address of
        // each surviving one into the report.
        for family in [AddrFamily::V4, AddrFamily::V6] {
            if let Some((url, conn)) = self.qad_conns.slot(family)
                && let Some(reason) = conn.conn.close_reason()
            {
                trace!(?family, ?url, "QAD conn closed: {reason}");
                self.qad_conns.slot_mut(family).take();
            }
            if let Some(r) = self.qad_conns.current(family) {
                self.report.apply_qad_observation(family, &r);
            }
        }

        self.qad_conns.reset_cancels();

        let families = [
            (
                AddrFamily::V4,
                self.qad_conns.v4.is_none() && if_state.have_v4,
            ),
            (
                AddrFamily::V6,
                self.qad_conns.v6.is_none() && if_state.have_v6,
            ),
        ];

        const MAX_RELAYS: usize = 5;
        let mut spawned = 0;
        let mut count_v4 = 0;
        let mut count_v6 = 0;
        for relay in self
            .relay_map
            .relays::<Vec<_>>()
            .into_iter()
            .take(MAX_RELAYS)
        {
            for (family, needed) in families {
                if needed {
                    // Stagger successive probes so they do not all fire at
                    // once. The first probe (spawned == 0) starts immediately.
                    let delay = self.user_config.qad_stagger * spawned as u32;
                    self.spawn_qad_probe(family, relay.clone(), quic_client.clone(), delay);
                    spawned += 1;
                    match family {
                        AddrFamily::V4 => count_v4 += 1,
                        AddrFamily::V6 => count_v6 += 1,
                    }
                }
            }
        }
        (count_v4, count_v6)
    }

    #[cfg(not(wasm_browser))]
    fn spawn_qad_probe(
        &mut self,
        family: AddrFamily,
        relay: Arc<iroh_relay::RelayConfig>,
        quic_client: iroh_relay::quic::QuicClient,
        delay: Duration,
    ) {
        self.spawn_probe_task(
            info_span!("QAD", ?family, relay_url=%relay.url),
            self.qad_conns.cancel(family).child_token(),
            delay,
            QAD_PROBE_TIMEOUT,
            super::qad::run_probe(
                family,
                relay,
                quic_client,
                self.dns_resolver.clone(),
                self.shutdown.child_token(),
                self.events_tx.clone(),
            ),
            move |outcome| ProbeEvent::QadResult(family, outcome),
        );
    }

    /// Spawns HTTPS latency probes according to the current [`ProbePlan`].
    /// Returns the number spawned.
    fn spawn_https_probes(&mut self) -> usize {
        let plan = match self.reports.last {
            Some(ref report) => {
                ProbePlan::with_last_report(&self.relay_map, report, &self.protocols)
            }
            None => ProbePlan::initial(&self.relay_map, &self.protocols),
        };
        trace!(%plan, "HTTPS probe plan");

        let mut count = 0;
        for probe_set in plan.iter() {
            for (delay, relay) in probe_set.params() {
                self.spawn_https_probe(*delay, Arc::clone(relay));
                count += 1;
            }
        }
        count
    }

    fn spawn_https_probe(&mut self, delay: Duration, relay: Arc<iroh_relay::RelayConfig>) {
        self.spawn_probe_task(
            info_span!("HTTPS", relay_url=%relay.url),
            self.cancel_https.child_token(),
            delay,
            HTTPS_PROBE_TIMEOUT,
            super::https::run_probe(
                #[cfg(not(wasm_browser))]
                self.dns_resolver.clone(),
                relay.url.clone(),
                #[cfg(not(wasm_browser))]
                self.tls_config.clone(),
            ),
            ProbeEvent::Https,
        );
    }

    /// Spawns a captive portal detection check, delayed by
    /// [`CAPTIVE_PORTAL_DELAY`] to give QAD probes time to succeed first, and
    /// cancelled if QAD confirms UDP connectivity.
    #[cfg(not(wasm_browser))]
    fn spawn_captive_portal(&mut self) {
        self.cancel_captive_portal = CancellationToken::new();
        let preferred = self
            .reports
            .last
            .as_ref()
            .and_then(|r| r.preferred_relay.clone());
        self.spawn_probe_task(
            info_span!("captive-portal"),
            self.cancel_captive_portal.child_token(),
            CAPTIVE_PORTAL_DELAY,
            CAPTIVE_PORTAL_TIMEOUT,
            super::captive_portal::check(
                self.dns_resolver.clone(),
                self.relay_map.clone(),
                preferred,
                self.tls_config.clone(),
            ),
            ProbeEvent::CaptivePortal,
        );
    }

    /// Spawns a probe task into the actor's [`JoinSet`].
    ///
    /// The task waits out `delay`, runs `work` with a `timeout`, and can be
    /// aborted at any point through `cancel`. However the probe ends, the
    /// result becomes a [`ProbeOutcome`]; `to_event` maps it into a
    /// [`ProbeEvent`], which the task sends on the actor's channel. The delay
    /// sits outside the timeout, so a staggered probe still gets its full
    /// timeout once it starts.
    fn spawn_probe_task<T: MaybeSend, E: MaybeSend>(
        &mut self,
        span: Span,
        cancel: CancellationToken,
        delay: Duration,
        timeout: Duration,
        work: impl 'static + MaybeSend + Future<Output = Result<T, E>>,
        to_event: impl 'static + MaybeSend + FnOnce(ProbeOutcome<T, E>) -> ProbeEvent,
    ) {
        let events = self.events_tx.clone();
        self.tasks.spawn(
            async move {
                let outcome = cancel
                    .run_until_cancelled(async move {
                        if !delay.is_zero() {
                            time::sleep(delay).await;
                        }
                        time::timeout(timeout, work).await
                    })
                    .await;
                let outcome = match outcome {
                    Some(Ok(Ok(value))) => ProbeOutcome::Ok(value),
                    Some(Ok(Err(err))) => ProbeOutcome::Err(err),
                    Some(Err(_elapsed)) => ProbeOutcome::Timeout,
                    None => ProbeOutcome::Cancelled,
                };
                let event = to_event(outcome);
                events.send(event).await.ok();
            }
            .instrument(span),
        );
    }
}

#[cfg(all(test, with_crypto_provider))]
mod tests {
    use std::time::Duration;

    use iroh_base::RelayUrl;
    use n0_error::Result;

    use super::*;
    use crate::net_report::probes::Probe;

    #[test]
    fn test_qad_gate() {
        // Nothing being probed: the gate never blocks.
        assert!(QadState::default().all_determined());

        // A probed family blocks until it is determined.
        let mut qad = QadState::default();
        qad.v4.probing = true;
        assert!(!qad.all_determined());
        qad.v4.determined = true;
        assert!(qad.all_determined());

        // Both probed: both must be determined.
        let mut qad = QadState::default();
        qad.v4.probing = true;
        qad.v6.probing = true;
        qad.v4.determined = true;
        assert!(!qad.all_determined());
        qad.v6.determined = true;
        assert!(qad.all_determined());

        // A family that is not being probed does not block, even if another
        // probed family has determined.
        let mut qad = QadState::default();
        qad.v6.probing = true;
        qad.v4.determined = true;
        assert!(!qad.all_determined());
        qad.v6.determined = true;
        assert!(qad.all_determined());
    }

    fn relay_url(i: u16) -> RelayUrl {
        format!("http://{i}.com").parse().unwrap()
    }

    fn report(a: impl IntoIterator<Item = (&'static str, u64)>) -> Option<Report> {
        let mut report = Report::default();
        for (s, d) in a {
            assert!(s.starts_with('d'), "invalid relay server key");
            let id: u16 = s[1..].parse().unwrap();
            report.relay_latency.update_relay(
                relay_url(id),
                Duration::from_secs(d),
                Probe::QadIpv4,
            );
        }
        Some(report)
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn test_report_history_and_preferred_relay() -> Result {
        struct Step {
            after: u64,
            r: Option<Report>,
        }
        struct Test {
            name: &'static str,
            steps: Vec<Step>,
            want_relay: Option<RelayUrl>,
            want_prev_len: usize,
        }

        let tests = [
            Test {
                name: "first_reading",
                steps: vec![Step {
                    after: 0,
                    r: report([("d1", 2), ("d2", 3)]),
                }],
                want_prev_len: 1,
                want_relay: Some(relay_url(1)),
            },
            Test {
                name: "with_two",
                steps: vec![
                    Step {
                        after: 0,
                        r: report([("d1", 2), ("d2", 3)]),
                    },
                    Step {
                        after: 1,
                        r: report([("d1", 4), ("d2", 3)]),
                    },
                ],
                want_prev_len: 2,
                want_relay: Some(relay_url(1)),
            },
            Test {
                name: "but_now_d1_gone",
                steps: vec![
                    Step {
                        after: 0,
                        r: report([("d1", 2), ("d2", 3)]),
                    },
                    Step {
                        after: 1,
                        r: report([("d1", 4), ("d2", 3)]),
                    },
                    Step {
                        after: 2,
                        r: report([("d2", 3)]),
                    },
                ],
                want_prev_len: 3,
                want_relay: Some(relay_url(2)),
            },
            Test {
                name: "d1_is_back",
                steps: vec![
                    Step {
                        after: 0,
                        r: report([("d1", 2), ("d2", 3)]),
                    },
                    Step {
                        after: 1,
                        r: report([("d1", 4), ("d2", 3)]),
                    },
                    Step {
                        after: 2,
                        r: report([("d2", 3)]),
                    },
                    Step {
                        after: 3,
                        r: report([("d1", 4), ("d2", 3)]),
                    },
                ],
                want_prev_len: 4,
                want_relay: Some(relay_url(1)),
            },
            Test {
                name: "things_clean_up",
                steps: vec![
                    Step {
                        after: 0,
                        r: report([("d1", 1), ("d2", 2)]),
                    },
                    Step {
                        after: 1,
                        r: report([("d1", 1), ("d2", 2)]),
                    },
                    Step {
                        after: 2,
                        r: report([("d1", 1), ("d2", 2)]),
                    },
                    Step {
                        after: 3,
                        r: report([("d1", 1), ("d2", 2)]),
                    },
                    Step {
                        after: 10 * 60,
                        r: report([("d3", 3)]),
                    },
                ],
                want_prev_len: 1,
                want_relay: Some(relay_url(3)),
            },
            Test {
                name: "preferred_relay_hysteresis_no_switch",
                steps: vec![
                    Step {
                        after: 0,
                        r: report([("d1", 4), ("d2", 5)]),
                    },
                    Step {
                        after: 1,
                        r: report([("d1", 4), ("d2", 3)]),
                    },
                ],
                want_prev_len: 2,
                want_relay: Some(relay_url(1)),
            },
            Test {
                name: "preferred_relay_hysteresis_do_switch",
                steps: vec![
                    Step {
                        after: 0,
                        r: report([("d1", 4), ("d2", 5)]),
                    },
                    Step {
                        after: 1,
                        r: report([("d1", 4), ("d2", 1)]),
                    },
                ],
                want_prev_len: 2,
                want_relay: Some(relay_url(2)),
            },
        ];

        for mut tt in tests {
            println!("test: {}", tt.name);
            let mut reports = ReportHistory::default();
            for s in &mut tt.steps {
                tokio::time::advance(Duration::from_secs(s.after)).await;
                reports.record(s.r.as_mut().unwrap());
            }
            let last_report = tt.steps.last().unwrap().r.clone().unwrap();
            assert_eq!(reports.prev.len(), tt.want_prev_len, "prev length");
            assert_eq!(
                &last_report.preferred_relay, &tt.want_relay,
                "preferred_relay"
            );
        }

        Ok(())
    }
}
