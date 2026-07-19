use std::{
    collections::{BTreeSet, VecDeque},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::Poll,
};

use iroh_base::{CustomAddr, EndpointId, RelayUrl, TransportAddr};
use n0_error::StackResultExt;
use n0_future::{
    FuturesUnordered, MaybeFuture, MergeUnbounded, Stream, StreamExt,
    boxed::BoxStream,
    task::JoinSet,
    time::{self, Duration, Instant},
};
use n0_watcher::Watcher;
use noq::{Closed, PathStats, PathStatus, WeakConnectionHandle};
use noq_proto::{PathError, PathEvent as NoqPathEvent, PathId, n0_nat_traversal};
use rustc_hash::FxHashMap;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};
use tracing::{Instrument, Level, Span, debug, error, event, info_span, instrument, trace, warn};

use self::path_state::RemotePathState;
pub(crate) use self::path_watcher::PathStateReceiver;
pub use self::{
    path_watcher::{Path, PathEvent, PathEventStream, PathList, PathListIter, PathListStream},
    remote_info::{RemoteInfo, TransportAddrInfo, TransportAddrUsage},
};
use super::{BootstrapAuthority, Source};
use crate::{
    address_lookup::{AddressLookupFailed, AddressLookupServices, Item as AddressLookupItem},
    endpoint::DirectAddr,
    socket::{
        Metrics as SocketMetrics, RELAY_PATH_MAX_IDLE_TIMEOUT,
        mapped_addrs::{AddrMap, CustomMappedAddr, RelayMappedAddr},
        remote_map::remote_state::path_watcher::PathStateSender,
        transports::{self, OwnedTransmit, TransportsSender},
    },
};

mod path_state;
mod path_watcher;
mod remote_info;

/// How often to attempt holepunching.
///
/// If there have been no changes to the NAT address candidates, holepunching will not be
/// attempted more frequently than at this interval.
const HOLEPUNCH_ATTEMPTS_INTERVAL: Duration = Duration::from_secs(5);

/// The latency at or under which we don't try to upgrade to a better path.
const GOOD_ENOUGH_LATENCY: Duration = Duration::from_millis(10);

/// Maximum number of distinct paths waiting for a path-open retry.
///
/// A failed retry is attempted on every connection to the remote. Bounding and
/// deduplicating this queue prevents that fan-out from growing it indefinitely.
const MAX_PENDING_OPEN_PATHS: usize = 64;

#[derive(Default)]
struct PendingOpenPaths {
    entries: VecDeque<transports::FourTuple>,
}

impl PendingOpenPaths {
    fn enqueue(&mut self, addr: transports::FourTuple) {
        if self.entries.contains(&addr) {
            return;
        }
        if self.entries.len() >= MAX_PENDING_OPEN_PATHS {
            self.entries.pop_front();
        }
        self.entries.push_back(addr);
    }

    fn pop_front(&mut self) -> Option<transports::FourTuple> {
        self.entries.pop_front()
    }

    #[cfg(test)]
    fn contains(&self, addr: &transports::FourTuple) -> bool {
        self.entries.contains(addr)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

// TODO: use this
// /// How long since the last activity we try to keep an established endpoint peering alive.
// ///
// /// It's also the idle time at which we stop doing QAD queries to keep NAT mappings alive.
// pub(super) const SESSION_ACTIVE_TIMEOUT: Duration = Duration::from_secs(45);

/// How often we try to upgrade to a better path.
///
/// Even if we have some non-relay route that works.
const UPGRADE_INTERVAL: Duration = Duration::from_secs(60);

/// The time after which an idle [`RemoteStateActor`] stops.
///
/// The actor only enters the idle state if no connections are active and no inbox senders exist
/// apart from the one stored in the endpoint map. Stopping and restarting the actor in this state
/// is not an issue; a timeout here serves the purpose of not stopping-and-recreating actors
/// in a high frequency, and to keep data about previous path around for subsequent connections.
const ACTOR_MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// A stream of events from all paths for all connections.
///
/// The connection is identified using [`ConnId`].  The event `Err` variant happens when the
/// actor has lagged processing the events, which is rather critical for us.
type PathEvents = MergeUnbounded<
    Pin<Box<dyn Stream<Item = (ConnId, Result<NoqPathEvent, noq::Lagged>)> + Send + Sync>>,
>;

/// A stream of events of announced NAT traversal candidate addresses for all connections.
///
/// The connection is identified using [`ConnId`].
type AddrEvents = MergeUnbounded<
    Pin<
        Box<
            dyn Stream<Item = (ConnId, Result<n0_nat_traversal::Event, noq::Lagged>)> + Send + Sync,
        >,
    >,
>;

/// The state we need to know about a single remote endpoint.
///
/// This actor manages all connections to the remote endpoint.  It will trigger holepunching
/// and select the best path etc.
pub(super) struct RemoteStateActor {
    /// All connections we have to this remote endpoint.
    connections: FxHashMap<ConnId, ConnectionState>,
    /// State of the actor and hooks into the rest of the remote endpoint.
    ///
    /// This is on a separate struct so that we can have parallel mutable borrows to `connections` and `state`.
    state: State,
}

/// State of the [`RemoteStateActor`] and hooks into the rest of the remote endpoint.
struct State {
    /// The endpoint ID of the remote endpoint.
    endpoint_id: EndpointId,

    // Hooks into the rest of the Socket.
    //
    /// Metrics.
    metrics: Arc<SocketMetrics>,
    /// Our local addresses.
    ///
    /// These are our local addresses and any reflexive transport addresses.
    local_direct_addrs: n0_watcher::Direct<BTreeSet<DirectAddr>>,
    /// The mapping between endpoints via a relay and their [`RelayMappedAddr`]s.
    relay_mapped_addrs: AddrMap<(RelayUrl, EndpointId), RelayMappedAddr>,
    /// The mapping between custom transport addresses and their [`CustomMappedAddr`]s.
    custom_mapped_addrs: AddrMap<CustomAddr, CustomMappedAddr>,
    /// Address lookup service, cloned from the socket.
    address_lookup: AddressLookupServices,
    /// Whether each connection requires application authorization before NAT traversal.
    defer_nat_traversal_until_authorized: bool,
    // Internal state - Noq Connections we are managing.
    //
    /// Notifications when connections are closed.
    connections_close: FuturesUnordered<OnClosed>,
    /// Events emitted by Noq about path changes, for all paths, all connections.
    path_events: PathEvents,
    /// A stream of events of announced NAT traversal candidate addresses for all connections.
    addr_events: AddrEvents,

    // Internal state - Holepunching and path state.
    //
    /// All possible paths we are aware of.
    ///
    /// These paths might be entirely impossible to use, since they are added by Address Lookup
    /// mechanisms.  The are only potentially usable.
    paths: RemotePathState,
    /// Information about the last holepunching attempt.
    last_holepunch: Option<HolepunchAttempt>,

    /// The path we currently consider the preferred path to the remote endpoint.
    ///
    /// **We expect this path to work.** If we become aware this path is broken then it is
    /// set back to `None`.  Having a selected path does not mean we may not be able to get
    /// a better path: e.g. when the selected path is a relay path we still need to trigger
    /// holepunching regularly.
    ///
    /// We only select a path once the path is functional in Noq.
    selected_path: Option<transports::FourTuple>,
    /// Time at which we should schedule the next holepunch attempt.
    scheduled_holepunch: Option<Instant>,
    /// When to next attempt opening paths in [`Self::pending_open_paths`].
    scheduled_open_path: Option<Instant>,
    /// Paths which we still need to open.
    ///
    /// They failed to open because we did not have enough CIDs issued by the remote.
    pending_open_paths: PendingOpenPaths,

    // Internal state - address lookup
    //
    /// Stream of Address Lookup results, or always pending if Address Lookup is not running.
    address_lookup_stream: Option<BoxStream<Result<AddressLookupItem, AddressLookupFailed>>>,

    /// Cancellation notifications for callers waiting on Address Lookup.
    address_lookup_cancellations: FuturesUnordered<WaitForCancellationFutureOwned>,

    /// The path selector used to pick the preferred path among the candidates.
    path_selector: Arc<dyn PathSelector>,
}

impl RemoteStateActor {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        endpoint_id: EndpointId,
        local_direct_addrs: n0_watcher::Direct<BTreeSet<DirectAddr>>,
        relay_mapped_addrs: AddrMap<(RelayUrl, EndpointId), RelayMappedAddr>,
        custom_mapped_addrs: AddrMap<CustomAddr, CustomMappedAddr>,
        metrics: Arc<SocketMetrics>,
        address_lookup: AddressLookupServices,
        path_selector: Arc<dyn PathSelector>,
        defer_nat_traversal_until_authorized: bool,
    ) -> Self {
        Self {
            connections: FxHashMap::default(),
            state: State {
                endpoint_id,
                metrics: metrics.clone(),
                local_direct_addrs,
                relay_mapped_addrs,
                custom_mapped_addrs,
                address_lookup,
                defer_nat_traversal_until_authorized,
                connections_close: Default::default(),
                path_events: Default::default(),
                addr_events: Default::default(),
                paths: RemotePathState::new(metrics),
                last_holepunch: None,
                selected_path: Default::default(),
                scheduled_holepunch: None,
                scheduled_open_path: None,
                pending_open_paths: PendingOpenPaths::default(),
                address_lookup_stream: None,
                address_lookup_cancellations: FuturesUnordered::new(),
                path_selector,
            },
        }
    }

    pub(super) fn start(
        self,
        initial_msgs: Vec<RemoteStateMessage>,
        tasks: &mut JoinSet<(EndpointId, Vec<RemoteStateMessage>)>,
        shutdown_token: CancellationToken,
        parent_span: Span,
    ) -> mpsc::Sender<RemoteStateMessage> {
        let (tx, rx) = mpsc::channel(16);
        let endpoint_id = self.state.endpoint_id;

        // Ideally we'd use the endpoint span as parent.  We'd have to plug that span into
        // here somehow.  Instead we have no parent and explicitly set the me attribute.  If
        // we don't explicitly set a span we get the spans from whatever call happens to
        // first create the actor, which is often very confusing as it then keeps those
        // spans for all logging of the actor.
        tasks.spawn(
            self.run(initial_msgs, rx, shutdown_token)
                .instrument(info_span!(
                    parent: parent_span,
                    "RemoteStateActor",
                    remote = %endpoint_id.fmt_short(),
                )),
        );
        tx
    }

    /// Runs the main loop of the actor.
    ///
    /// Note that the actor uses async handlers for tasks from the main loop.  The actor is
    /// not processing items from the inbox while waiting on any async calls.  So some
    /// discipline is needed to not turn pending for a long time.
    async fn run(
        mut self,
        initial_msgs: Vec<RemoteStateMessage>,
        mut inbox: mpsc::Receiver<RemoteStateMessage>,
        shutdown_token: CancellationToken,
    ) -> (EndpointId, Vec<RemoteStateMessage>) {
        trace!("actor started");
        for msg in initial_msgs {
            self.handle_message(msg).await;
        }
        let idle_timeout = time::sleep(ACTOR_MAX_IDLE_TIMEOUT);
        n0_future::pin!(idle_timeout);

        let check_connections = time::interval(UPGRADE_INTERVAL);
        n0_future::pin!(check_connections);

        loop {
            let scheduled_path_open = match self.state.scheduled_open_path {
                Some(when) => MaybeFuture::Some(time::sleep_until(when)),
                None => MaybeFuture::None,
            };
            n0_future::pin!(scheduled_path_open);
            let scheduled_holepunch = self.next_scheduled_holepunch();
            let scheduled_hp = match scheduled_holepunch {
                Some((_, when)) => MaybeFuture::Some(time::sleep_until(when)),
                None => MaybeFuture::None,
            };
            n0_future::pin!(scheduled_hp);
            if !self.is_idle(&inbox) {
                idle_timeout
                    .as_mut()
                    .reset(Instant::now() + ACTOR_MAX_IDLE_TIMEOUT);
            }

            tokio::select! {
                biased;

                _ = shutdown_token.cancelled() => {
                    trace!("actor cancelled");
                    break;
                }
                Some(()) = self.state.address_lookup_cancellations.next(), if !self.state.address_lookup_cancellations.is_empty() => {
                    self.state.handle_resolve_cancellation(self.connections.is_empty());
                }
                msg = inbox.recv() => {
                    match msg {
                        Some(msg) => self.handle_message(msg).await,
                        None => break,
                    }
                }
                Some((id, evt)) = self.state.path_events.next() => {
                    self.handle_path_event(id, evt);
                }
                Some((id, evt)) = self.state.addr_events.next() => {
                    if let Some(state) = self
                        .connections
                        .get_mut(&id)
                        .filter(|state| state.nat_traversal_authorized)
                    {
                        if state.handle.upgrade().is_some_and(|conn| {
                            conn.get_remote_nat_traversal_addresses()
                                .is_ok_and(|addrs| !addrs.is_empty())
                        }) {
                            state.peer_candidates_observed = true;
                        }
                        trace!(?id, ?evt, "remote addrs updated, triggering holepunching");
                        self.select_path();
                        self.trigger_holepunching_for(Some(id));
                    } else {
                        trace!(?id, ?evt, "ignoring remote addrs before authorization");
                    }
                }
                Some((conn_id, closed)) = self.state.connections_close.next(), if !self.state.connections_close.is_empty() => {
                    self.handle_connection_close(conn_id, closed);
                }
                res = self.state.local_direct_addrs.updated() => {
                    if let Err(n0_watcher::Disconnected) = res {
                        trace!("direct address watcher disconnected, shutting down");
                        break;
                    }
                    self.update_local_direct_address();
                    trace!("local addrs updated, triggering holepunching");
                    self.trigger_holepunching_all();
                }
                _ = &mut scheduled_path_open => {
                    trace!("triggering scheduled path_open");
                    self.state.scheduled_open_path = None;
                    let mut addrs = std::mem::take(&mut self.state.pending_open_paths);
                    while let Some(addr) = addrs.pop_front() {
                        self.open_path_on_all_conns(&addr);
                    }
                }
                _ = &mut scheduled_hp => {
                    trace!("triggering scheduled holepunching");
                    let conn_id = scheduled_holepunch.and_then(|(conn_id, _)| conn_id);
                    if let Some(conn_id) = conn_id {
                        if let Some(state) = self.connections.get_mut(&conn_id) {
                            state.scheduled_holepunch = None;
                        }
                    } else {
                        self.state.scheduled_holepunch = None;
                    }
                    self.trigger_holepunching_for(conn_id);
                }
                Some(item) = maybe_next(self.state.address_lookup_stream.as_mut()), if self.state.address_lookup_stream.is_some() => {
                    self.state.handle_address_lookup_item(item);
                }
                _ = check_connections.tick() => {
                    self.check_connections();
                }
                _ = &mut idle_timeout => {
                    if self.is_idle(&inbox) {
                        trace!("idle timeout expired and still idle: terminate actor");
                        break;
                    } else {
                        // Seems like we weren't really idle, so we reset
                        idle_timeout.as_mut().reset(Instant::now() + ACTOR_MAX_IDLE_TIMEOUT);
                    }
                }
            }
        }

        inbox.close();
        // There might be a race between checking `inbox.is_empty()` and `inbox.close()`,
        // so we pull out all messages that are left over.
        let mut leftover_msgs = Vec::with_capacity(inbox.len());
        inbox.recv_many(&mut leftover_msgs, inbox.len()).await;

        trace!("actor terminating");
        (self.state.endpoint_id, leftover_msgs)
    }

    /// Returns `true` if the actor is fully idle.
    fn is_idle(&self, inbox: &mpsc::Receiver<RemoteStateMessage>) -> bool {
        self.connections.is_empty()
            && inbox.is_empty()
            && self.state.paths.resolve_requests_is_empty()
    }

    /// Handles an actor message.
    ///
    /// Error returns are fatal and kill the actor.
    #[instrument(skip(self))]
    async fn handle_message(&mut self, msg: RemoteStateMessage) {
        // trace!("handling message");
        match msg {
            RemoteStateMessage::SendDatagram(authority, sender, transmit) => {
                self.state
                    .handle_msg_send_datagram(authority, sender, transmit)
                    .await;
            }
            RemoteStateMessage::AddConnection(handle, tx) => {
                self.handle_msg_add_connection(handle, tx);
            }
            RemoteStateMessage::AuthorizeNatTraversal {
                connection_id,
                reply,
            } => {
                reply
                    .send(self.handle_msg_authorize_nat_traversal(ConnId(connection_id)))
                    .ok();
            }
            RemoteStateMessage::ResolveRemote(addrs, tx, cancellation) => {
                self.state
                    .handle_msg_resolve_remote(addrs, tx, cancellation);
            }
            RemoteStateMessage::RemoteInfo(tx) => {
                let addrs = self.state.paths.to_remote_addrs();
                let info = RemoteInfo {
                    endpoint_id: self.state.endpoint_id,
                    addrs,
                };
                tx.send(info).ok();
            }
            RemoteStateMessage::NetworkChange { is_major } => {
                self.handle_msg_network_change(is_major);
            }
        }
    }

    /// Handles [`RemoteStateMessage::AddConnection`].
    ///
    /// Error returns are fatal and kill the actor.
    fn handle_msg_add_connection(
        &mut self,
        conn: noq::Connection,
        tx: oneshot::Sender<PathStateReceiver>,
    ) {
        let (path_state_sender, path_state_receiver) = PathStateSender::new();
        self.state.metrics.num_conns_opened.inc();
        // Remove any conflicting stable_ids from the local state.
        let conn_id = ConnId(conn.stable_id());
        self.connections.remove(&conn_id);

        // Hook up paths, NAT addresses and connection closed event streams.
        self.state
            .path_events
            .push(Box::pin(conn.path_events().map(move |evt| (conn_id, evt))));
        self.state.addr_events.push(Box::pin(
            conn.nat_traversal_updates().map(move |evt| (conn_id, evt)),
        ));
        self.state.connections_close.push(OnClosed::new(&conn));

        // Add local addrs to the connection
        let nat_traversal_authorized = !self.state.defer_nat_traversal_until_authorized;
        if nat_traversal_authorized {
            let local_addrs = self.state.local_candidates();
            update_qnt_candidates(&conn, &local_addrs);
        }

        // Store the connection
        let conn_state = self
            .connections
            .entry(conn_id)
            .insert_entry(ConnectionState {
                handle: conn.weak_handle(),
                path_state: path_state_sender,
                paths: Default::default(),
                has_been_direct: false,
                nat_traversal_authorized,
                peer_candidates_observed: nat_traversal_authorized,
                last_holepunch: None,
                scheduled_holepunch: None,
            })
            .into_mut();

        // Store PathId(0), set path_status and select best path, check if holepunching
        // is needed.
        if let Some(path) = conn.path(PathId::ZERO) {
            let path_remote = self
                .state
                .register_and_configure_path(conn_id, conn_state, &path);

            if let Some(path_remote) = path_remote.as_ref() {
                conn_state.record_deferred_bootstrap_selection(PathId::ZERO, path_remote);
            }

            if let Some(path_remote) = path_remote
                && !path_remote.is_relay()
                && conn.side().is_client()
                && conn_state.nat_traversal_authorized
            {
                // We may have raced this with a relay address.  Try and add any
                // relay addresses we have back.
                let relays = self
                    .state
                    .paths
                    .addrs()
                    .filter(|addr| addr.is_relay())
                    .map(|addr| transports::FourTuple::from_remote(addr.clone()))
                    .collect::<Vec<_>>();
                for open_addr in relays {
                    self.state
                        .open_path_on_conn(conn_id, conn_state, &conn, &open_addr);
                }
            }
        }
        if nat_traversal_authorized {
            self.trigger_holepunching();
        }
        self.select_path();
        tx.send(path_state_receiver).ok();
    }

    /// Authorizes noq first, then releases Iroh's per-connection path-management gate.
    fn handle_msg_authorize_nat_traversal(&mut self, conn_id: ConnId) -> bool {
        let Some(conn_state) = self.connections.get_mut(&conn_id) else {
            return false;
        };
        let Some(conn) = conn_state.handle.upgrade() else {
            return false;
        };
        if conn.close_reason().is_some() {
            return false;
        }
        if conn_state.nat_traversal_authorized {
            return true;
        }

        conn.authorize_nat_traversal();
        conn_state.nat_traversal_authorized = true;

        let local_addrs = self.state.local_candidates();
        update_qnt_candidates(&conn, &local_addrs);

        // A prior connection's attempt must not delay this exact connection's activation.
        conn_state.last_holepunch = None;
        conn_state.scheduled_holepunch = None;
        self.select_path();
        self.trigger_holepunching_for(Some(conn_id));
        true
    }

    /// Handles [`RemoteStateMessage::NetworkChange`].
    fn handle_msg_network_change(&mut self, is_major: bool) {
        // Ping all the paths so loss-detection starts ASAP.
        for conn in self
            .connections
            .values()
            .filter(|state| state.nat_traversal_authorized)
        {
            if let Some(noq_conn) = conn.handle.upgrade() {
                for (path_id, addr) in &conn.paths {
                    if let Some(path) = noq_conn.path(*path_id) {
                        // Ping the current path
                        if let Err(err) = path.ping() {
                            warn!(%err, %path_id, ?addr, "failed to ping path");
                        }
                    }
                }
            }
        }

        if is_major {
            self.trigger_holepunching_all();
        }
    }

    fn handle_connection_close(&mut self, conn_id: ConnId, closed: Closed) {
        event!(
            target: "iroh::_events::conn::closed",
            Level::DEBUG,
            %conn_id,
            remote_id = %self.state.endpoint_id.fmt_short(),
            reason=?closed.reason,
        );

        if let Some(conn_state) = self.connections.remove(&conn_id) {
            self.state.metrics.num_conns_closed.inc();
            conn_state.path_state.close(closed);
        }
        if self
            .connections
            .values()
            .all(|state| !state.nat_traversal_authorized)
        {
            trace!("last authorized connection closed - clearing selected_path");
            self.state.selected_path = None;
        }
    }

    /// Updates the local [`DirectAddr`]s to all connections.
    ///
    /// Each connection needs to have the local direct addresses to use as QNT address
    /// candidates.
    fn update_local_direct_address(&mut self) {
        let local_addrs = self.state.local_candidates();
        for conn in self
            .connections
            .values()
            .filter(|state| state.nat_traversal_authorized)
            .filter_map(|state| state.handle.upgrade())
        {
            update_qnt_candidates(&conn, &local_addrs);
        }
        // todo: trace
    }

    fn next_scheduled_holepunch(&self) -> Option<(Option<ConnId>, Instant)> {
        if self.state.defer_nat_traversal_until_authorized {
            self.connections
                .iter()
                .filter_map(|(id, state)| state.scheduled_holepunch.map(|when| (*id, when)))
                .min_by_key(|(_, when)| *when)
                .map(|(id, when)| (Some(id), when))
        } else {
            self.state.scheduled_holepunch.map(|when| (None, when))
        }
    }

    /// Triggers all exact deferred client connections, while preserving the upstream
    /// lowest-client behavior when the gate is disabled.
    fn trigger_holepunching_all(&mut self) {
        if !self.state.defer_nat_traversal_until_authorized {
            self.trigger_holepunching();
            return;
        }
        let connection_ids = self
            .connections
            .iter()
            .filter(|(_, state)| state.nat_traversal_authorized)
            .filter_map(|(id, state)| {
                state
                    .handle
                    .upgrade()
                    .filter(|conn| conn.side().is_client())
                    .map(|_| *id)
            })
            .collect::<Vec<_>>();
        for conn_id in connection_ids {
            self.trigger_holepunching_for(Some(conn_id));
        }
    }

    /// Triggers holepunching to the remote endpoint.
    fn trigger_holepunching(&mut self) {
        self.trigger_holepunching_for(None);
    }

    /// Triggers holepunching on an exact deferred connection when supplied.
    fn trigger_holepunching_for(&mut self, preferred: Option<ConnId>) {
        if self.connections.is_empty() {
            trace!("not holepunching: no connections");
            return;
        }

        let preferred = self
            .state
            .defer_nat_traversal_until_authorized
            .then_some(preferred)
            .flatten();
        let selected = if let Some(id) = preferred {
            (|| {
                let state = self.connections.get(&id)?;
                if !state.nat_traversal_authorized {
                    return None;
                }
                let conn = state.handle.upgrade()?;
                conn.side().is_client().then_some((id, conn))
            })()
        } else {
            self.connections
                .iter()
                .filter(|(_, state)| state.nat_traversal_authorized)
                .filter_map(|(id, state)| state.handle.upgrade().map(|conn| (*id, conn)))
                .filter(|(_, conn)| conn.side().is_client())
                .min_by_key(|(id, _)| *id)
        };
        let Some((conn_id, conn)) = selected else {
            trace!("not holepunching: no client connection");
            return;
        };
        let remote_candidates = match conn.get_remote_nat_traversal_addresses() {
            Ok(addrs) => BTreeSet::from_iter(addrs),
            Err(err) => {
                warn!("failed to get nat candidate addresses: {err:#}");
                return;
            }
        };
        let local_candidates = self.state.local_candidates();
        let last_holepunch = if self.state.defer_nat_traversal_until_authorized {
            self.connections
                .get(&conn_id)
                .and_then(|state| state.last_holepunch.as_ref())
        } else {
            self.state.last_holepunch.as_ref()
        };
        let new_candidates = last_holepunch
            .map(|last_hp| {
                // Addrs are allowed to disappear, but if there are new ones we need to
                // holepunch again.
                trace!(
                    ?last_hp,
                    ?local_candidates,
                    ?remote_candidates,
                    "candidates to holepunch?"
                );
                !remote_candidates.is_subset(&last_hp.remote_candidates)
                    || !local_candidates.is_subset(&last_hp.local_candidates)
            })
            .unwrap_or(true);
        if !new_candidates && let Some(last_hp) = last_holepunch {
            let next_hp = last_hp.when + HOLEPUNCH_ATTEMPTS_INTERVAL;
            let now = Instant::now();
            if next_hp > now {
                trace!(scheduled_in = ?(next_hp - now), "not holepunching: no new addresses");
                if self.state.defer_nat_traversal_until_authorized {
                    if let Some(state) = self.connections.get_mut(&conn_id) {
                        state.scheduled_holepunch = Some(next_hp);
                    }
                } else {
                    self.state.scheduled_holepunch = Some(next_hp);
                }
                return;
            }
        }

        self.state.metrics.holepunch_attempts.inc();
        match conn.initiate_nat_traversal_round() {
            Ok(remote_candidates) => {
                let remote_candidates = remote_candidates
                    .iter()
                    .map(|addr| SocketAddr::new(addr.ip().to_canonical(), addr.port()))
                    .collect();
                event!(
                    target: "iroh::_events::qnt::init",
                    Level::DEBUG,
                    remote = %self.state.endpoint_id.fmt_short(),
                    ?local_candidates,
                    ?remote_candidates,
                );
                let attempt = HolepunchAttempt {
                    when: Instant::now(),
                    local_candidates,
                    remote_candidates,
                };
                if self.state.defer_nat_traversal_until_authorized {
                    if let Some(state) = self.connections.get_mut(&conn_id) {
                        state.last_holepunch = Some(attempt);
                        state.scheduled_holepunch = None;
                    }
                } else {
                    self.state.last_holepunch = Some(attempt);
                    self.state.scheduled_holepunch = None;
                }
            }
            Err(err) => {
                debug!(%conn_id, "failed to initiate NAT traversal: {err:#}");
                use noq_proto::n0_nat_traversal::Error;
                let retry = matches!(err, Error::Multipath(_) | Error::NotEnoughAddresses);
                if retry {
                    let next_hp = Instant::now() + Duration::from_millis(100);
                    trace!(scheduled_in = ?Duration::from_millis(100), "holepunching retry");
                    if self.state.defer_nat_traversal_until_authorized {
                        if let Some(state) = self.connections.get_mut(&conn_id) {
                            state.scheduled_holepunch = Some(next_hp);
                        }
                    } else {
                        self.state.scheduled_holepunch = Some(next_hp);
                    }
                }
            }
        }
    }

    #[instrument(skip(self))]
    fn handle_path_event(&mut self, conn_id: ConnId, event: Result<NoqPathEvent, noq::Lagged>) {
        let Ok(event) = event else {
            warn!("missed a PathEvent, RemoteStateActor lagging");
            // TODO: Is it possible to recover using the sync APIs to figure out what the
            //    state of the connection and it's paths are?
            return;
        };
        let Some(conn_state) = self.connections.get_mut(&conn_id) else {
            trace!("event for removed connection");
            return;
        };
        let Some(conn) = conn_state.handle.upgrade() else {
            trace!("event for closed connection");
            return;
        };
        if !conn_state.nat_traversal_authorized
            && matches!(
                &event,
                NoqPathEvent::Established { id, .. }
                    | NoqPathEvent::Abandoned { id, .. }
                    | NoqPathEvent::Discarded { id, .. }
                    if *id != PathId::ZERO
            )
        {
            trace!(%conn_id, ?event, "ignoring non-bootstrap path event before authorization");
            return;
        }
        trace!("path event");
        match event {
            NoqPathEvent::Established { id: path_id, .. } => {
                let Some(path) = conn.path(path_id) else {
                    trace!("path open event for unknown path");
                    return;
                };

                if let Some(path_remote) = self
                    .state
                    .register_and_configure_path(conn_id, conn_state, &path)
                {
                    conn_state.record_deferred_bootstrap_selection(path_id, &path_remote);
                }
                self.select_path();
            }
            NoqPathEvent::Abandoned { id, reason, .. } => {
                // Remove abandoned path from the conn state.
                let Some(network_path) = conn_state.remove_path(&id, &conn) else {
                    debug!(%id, "path not in path_id_map");
                    return;
                };

                // We track all known remote addresses for the peer in `State::paths`. The paths are tracked
                // by remote address only (we ignore the local IP). Therefore, we mark a remote addr as abandoned
                // in the remote-global state only once no connections have any path to that remote addr.
                if !conn_state
                    .paths
                    .values()
                    .any(|tuple| tuple.remote() == network_path.remote())
                {
                    self.state.paths.abandoned_path(&network_path.remote());
                }

                event!(
                    target: "iroh::_events::path::abandoned",
                    Level::DEBUG,
                    remote = %self.state.endpoint_id.fmt_short(),
                    %conn_id,
                    path_id = %id,
                    %network_path,
                    ?reason
                );

                // If the remote closed our selected path, select a new one.
                self.select_path();
            }
            NoqPathEvent::Discarded { id, path_stats, .. } => {
                trace!(%id, ?path_stats, "path discarded");
            }
            NoqPathEvent::RemoteStatus { .. } | NoqPathEvent::ObservedAddr { .. } => {
                // Nothing to do for these events.
            }
            _ => {
                // We expect to keep noq and iroh in sync in all test setups, but in production it's totally possible
                // that iroh itself is linked against a newer version of noq with additional events we don't yet
                // know how to handle.
                #[cfg(test)]
                panic!("Unhandled path event: {event:?}");
            }
        }
    }

    /// Selects the preferred path by invoking the configured [`PathSelector`].
    ///
    /// The selected path is added to any connections which do not yet have it.  Any unused
    /// direct paths are closed for all connections.
    #[instrument(skip_all)]
    fn select_path(&mut self) {
        let current_path = self.state.selected_path.as_ref();
        let selected_addr = {
            let ctx = PathSelectionContext::new(current_path, &self.connections);
            self.state.path_selector.select(&ctx).selected().cloned()
        };

        if let Some(addr) = selected_addr
            && self.state.selected_path.as_ref() != Some(&addr)
        {
            let prev_remote = self.state.selected_path.replace(addr.clone());
            event!(
                target: "iroh::_events::path::selected",
                Level::DEBUG,
                remote = %self.state.endpoint_id.fmt_short(),
                network_path = %addr,
                prev_network_path = %prev_remote.map(|p| format!("{p}")).unwrap_or("None".to_string()),
            );
        } else {
            trace!(?current_path, "keeping current path");
        }

        self.apply_selected_path();
    }

    /// Propagates a change of [`State::selected_path`] to noq.
    ///
    /// Iterates over all connections and applies the selected path as follows:
    /// - Closes non-selected IP paths (but keeps one IP path open still)
    /// - Sets all non-selected paths to [`PathStatus::Backup`]
    /// - Opens the selected path if it does not exist on the connection
    /// - Sets the selected path to [`PathStatus::Available`]
    fn apply_selected_path(&mut self) {
        let Some(selected) = self.state.selected_path.clone() else {
            // We can't open the selected path on all paths if we don't have one yet.
            // And we can't close all "unselected" paths either, because we don't know which one is selected.
            return;
        };

        for (conn_id, conn_state) in self.connections.iter() {
            if !conn_state.nat_traversal_authorized {
                continue;
            }
            let Some(conn) = conn_state.handle.upgrade() else {
                continue;
            };
            if self.state.defer_nat_traversal_until_authorized
                && !conn_state.peer_candidates_observed
            {
                self.state
                    .apply_existing_selected_path(*conn_id, conn_state, &conn, &selected);
                continue;
            }

            // Open path if it doesn't exist yet.
            self.state
                .open_path_on_conn(*conn_id, conn_state, &conn, &selected);

            for (path_id, path_remote) in conn_state.paths.iter() {
                let Some(path) = conn.path(*path_id) else {
                    continue;
                };

                // Closes redundant IP paths so that at most one remains per connection.
                //
                // Relay and custom paths are kept open. Only the client closes paths,
                // to avoid the client and server independently closing different paths
                // and racing to abandon the last one.
                if conn.side().is_client()
                    && path_remote.is_ip()
                    && path_remote != &selected
                    && conn_state.paths.values().filter(|a| a.is_ip()).count() > 1
                {
                    trace!(?path_remote, %conn_id, %path_id, "closing direct path");
                    match path.close() {
                        Err(noq_proto::ClosePathError::MultipathNotNegotiated) => {
                            error!("multipath not negotiated");
                        }
                        Err(noq_proto::ClosePathError::LastOpenPath) => {
                            error!("could not close last open path");
                        }
                        Err(noq_proto::ClosePathError::ClosedPath) => {
                            // We already closed this.
                        }
                        Ok(()) => {}
                    }
                    continue;
                }

                // Set path status: The selected path becomes Available, all other paths become Backup.
                self.state.set_path_status(*conn_id, &path, path_remote);
            }

            // Record the new selected path in the path watcher.
            conn_state.path_state.record_selected(&selected);
        }
    }

    fn open_path_on_all_conns(&mut self, open_addr: &transports::FourTuple) {
        for (conn_id, conn_state) in self.connections.iter() {
            if !conn_state.nat_traversal_authorized {
                continue;
            }
            if self.state.defer_nat_traversal_until_authorized
                && !conn_state.peer_candidates_observed
            {
                continue;
            }
            let Some(conn) = conn_state.handle.upgrade() else {
                continue;
            };
            self.state
                .open_path_on_conn(*conn_id, conn_state, &conn, open_addr);
        }
    }

    /// Handles regularly checking if any paths need hole punching currently
    ///
    /// Currently we need to have 1 IP path, with a good enough latency.
    fn check_connections(&mut self) {
        let mut is_goodenough = true;
        for conn_state in self
            .connections
            .values()
            .filter(|state| state.nat_traversal_authorized)
        {
            let mut is_conn_goodenough = false;
            if let Some(conn) = conn_state.handle.upgrade() {
                let min_ip_rtt = conn_state
                    .paths
                    .iter()
                    .filter_map(|(path_id, addr)| {
                        if addr.is_ip() {
                            conn.path_stats(*path_id).map(|stats| stats.rtt)
                        } else {
                            None
                        }
                    })
                    .min();

                if let Some(min_ip_rtt) = min_ip_rtt {
                    let is_latency_goodenough = min_ip_rtt <= GOOD_ENOUGH_LATENCY;
                    is_conn_goodenough = is_latency_goodenough;
                } else {
                    // No IP transport found
                    is_conn_goodenough = false;
                }
            }
            is_goodenough &= is_conn_goodenough;
        }

        if !is_goodenough {
            debug!("connections are not good enough, triggering holepunching");
            self.trigger_holepunching_all();
        }
    }
}

impl State {
    /// Handles [`RemoteStateMessage::SendDatagram`].
    async fn handle_msg_send_datagram(
        &mut self,
        authority: BootstrapAuthority,
        mut sender: Box<TransportsSender>,
        transmit: OwnedTransmit,
    ) {
        // Sending datagrams might fail, e.g. because we don't have the right transports set
        // up to handle sending this owned transmit to.
        // After all, we try every single path that we know (relay URL, IP address), even
        // though we might not have a relay transport or ip-capable transport set up.
        // So these errors must not be fatal for this actor (or even this operation).

        if let Some(addr) = self
            .selected_path
            .as_ref()
            .filter(|addr| self.bootstrap_path_allowed(&authority, &addr.remote()))
        {
            trace!(?addr, "sending datagram to selected path");

            // TODO(Frando): We might want to include a local IP here in the future, if we confidently
            // know that it is the correct one.
            // See https://github.com/n0-computer/iroh/issues/4280.
            let four_tuple = transports::FourTuple::from_remote(addr.remote());
            if let Err(err) = send_datagram(&mut sender, four_tuple, transmit).await {
                debug!(?addr, "failed to send datagram on selected_path: {err:#}");
            }
        } else {
            trace!(
                paths = ?self.paths.addrs().collect::<Vec<_>>(),
                "sending datagram to all known paths",
            );
            if self.paths.is_empty() {
                warn!("Cannot send datagrams: No paths to remote endpoint known");
            }

            let bootstrap_paths = self
                .paths
                .addrs()
                .filter(|addr| self.bootstrap_path_allowed(&authority, addr))
                .cloned()
                .collect::<Vec<_>>();
            for addr in bootstrap_paths {
                // We never want to send to our local addresses.
                // The local address set is updated in the main loop so we can use `peek` here.
                if let transports::Addr::Ip(sockaddr) = &addr
                    && self
                        .local_direct_addrs
                        .peek()
                        .iter()
                        .any(|a| a.addr == *sockaddr)
                {
                    trace!(%sockaddr, "not sending datagram to our own address");

                // TODO(Frando): We might want to include a local IP here in the future, if we confidently
                // know that it is the correct one.
                // See https://github.com/n0-computer/iroh/issues/4280.
                } else if let Err(err) = send_datagram(
                    &mut sender,
                    transports::FourTuple::from_remote(addr.clone()),
                    transmit.clone(),
                )
                .await
                {
                    debug!(?addr, "failed to send datagram: {err:#}");
                }
            }
            // This message is received *before* a connection is added.  So we do
            // not yet have a connection to holepunch.  Instead we trigger
            // holepunching when AddConnection is received.
        }
    }

    /// Handles [`RemoteStateMessage::ResolveRemote`].
    fn handle_msg_resolve_remote(
        &mut self,
        addrs: BTreeSet<TransportAddr>,
        tx: oneshot::Sender<Result<(), AddressLookupFailed>>,
        cancellation: CancellationToken,
    ) {
        let addrs = to_transports_addr(self.endpoint_id, addrs).collect::<Vec<_>>();
        self.paths.insert_multiple(addrs.into_iter(), Source::App);
        if self.paths.resolve_remote(tx, cancellation.clone()) {
            self.address_lookup_cancellations
                .push(cancellation.cancelled_owned());
        }
        // Start Address Lookup if we have no selected path.
        self.trigger_address_lookup();
    }

    /// Releases a lookup once every caller waiting on an address has cancelled.
    fn handle_resolve_cancellation(&mut self, connections_are_empty: bool) {
        self.paths.prune_cancelled_resolve_requests();
        if connections_are_empty
            && self.selected_path.is_none()
            && self.paths.is_empty()
            && self.paths.resolve_requests_is_empty()
        {
            self.address_lookup_stream = None;
        }
    }

    /// Triggers Address Lookup for the remote endpoint, if needed.
    ///
    /// Does not start Address Lookup if we have a selected path or if Address Lookup is
    /// currently running.
    fn trigger_address_lookup(&mut self) {
        if self.selected_path.is_some() || self.address_lookup_stream.is_some() {
            return;
        }
        let stream = self.address_lookup.resolve(self.endpoint_id);
        let stream = stream.filter_map(|item| match item {
            // We don't care about errors from individual services, we just continue.
            // Individual errors are buffered into the final error by `AddressLookupServices::resolve`,
            // and if the lookup fails we return them upstream with the final `AddressLookupFailed` error.
            Ok(Err(_err)) => None,
            Ok(Ok(item)) => Some(Ok(item)),
            Err(err) => Some(Err(err)),
        });
        self.address_lookup_stream = Some(Box::pin(stream));
    }

    /// Handles an address lookup result.
    ///
    /// All address lookup results end up being sent here. It takes care of updating the
    /// [`RemotePathState`] with the results.
    fn handle_address_lookup_item(
        &mut self,
        item: Option<Result<AddressLookupItem, AddressLookupFailed>>,
    ) {
        match item {
            None => {
                self.paths.address_lookup_finished(Ok(()));
                self.address_lookup_stream = None;
            }
            Some(Err(err)) => {
                if let AddressLookupFailed::NoServiceConfigured { .. } = err {
                    trace!("Address Lookup not configured");
                } else {
                    debug!("Address Lookup failed: {err:#}");
                }
                self.paths.address_lookup_finished(Err(err));
                self.address_lookup_stream = None;
            }
            Some(Ok(item)) => {
                if item.endpoint_id() != self.endpoint_id {
                    warn!(
                        ?item,
                        "Address Lookup emitted item for wrong remote endpoint"
                    );
                } else {
                    let source = Source::AddressLookup {
                        name: item.provenance().to_string(),
                    };
                    let addrs =
                        to_transports_addr(self.endpoint_id, item.into_endpoint_addr().addrs);
                    self.paths.insert_multiple(addrs, source);
                }
            }
        }
    }

    /// Register a path with our state and configure path-specific settings.
    ///
    /// This inserts the path in the [`ConnectionState`] and [`Self::paths`].
    ///
    /// It configures the path with the correct path status (see [`Self::set_path_status`]),
    /// and applies path-type-specific settings:
    /// Relay paths get a longer idle timeout to accommodate transparent reconnection
    /// by the relay actor (see [`RELAY_PATH_MAX_IDLE_TIMEOUT`]).
    fn register_and_configure_path(
        &mut self,
        conn_id: ConnId,
        conn_state: &mut ConnectionState,
        path: &noq::Path,
    ) -> Option<transports::FourTuple> {
        let network_path = self.transport_tuple_for_path(path)?;
        event!(
            target: "iroh::_events::path::open",
            Level::DEBUG,
            remote = %self.endpoint_id.fmt_short(),
            %conn_id,
            path_id=%path.id(),
            %network_path,
        );
        conn_state.add_open_path(network_path.clone(), path.id(), &self.metrics);
        if network_path.is_relay()
            && let Err(e) = path.set_max_idle_timeout(Some(RELAY_PATH_MAX_IDLE_TIMEOUT))
        {
            debug!(?e, "failed to set relay path idle timeout");
        }

        if conn_state.nat_traversal_authorized {
            self.set_path_status(conn_id, path, &network_path);
        }
        self.paths
            .insert_open_path(network_path.remote(), Source::Connection);
        Some(network_path)
    }

    fn set_path_status(
        &mut self,
        conn_id: ConnId,
        path: &noq::Path,
        network_path: &transports::FourTuple,
    ) {
        let status = self.path_status_for_addr(network_path);
        match path.set_status(status) {
            Err(error) => warn!(?error, ?network_path, ?status, "set_status failed"),
            Ok(prev_status) if prev_status != status => {
                event!(
                    target: "iroh::_events::path::set_status",
                    Level::DEBUG,
                    remote = %self.endpoint_id.fmt_short(),
                    %conn_id,
                    path_id=%path.id(),
                    %network_path,
                    ?status,
                    ?prev_status,
                );
            }
            Ok(_) => {}
        }
    }

    fn open_path_on_conn(
        &mut self,
        conn_id: ConnId,
        conn_state: &ConnectionState,
        conn: &noq::Connection,
        open_addr: &transports::FourTuple,
    ) {
        // Only the client opens paths; the server receives them via
        // QUIC frames and reacts to PathOpened events.
        if conn.side().is_server() {
            return;
        }
        // Already open on this connection; nothing to do.
        if conn_state.paths.values().any(|a| a == open_addr) {
            return;
        }

        let quic_addr =
            open_addr.to_noq_four_tuple(&self.relay_mapped_addrs, &self.custom_mapped_addrs);
        let path_status = self.path_status_for_addr(open_addr);

        let fut = conn.open_path_ensure(quic_addr, path_status);
        match fut.path_id() {
            Some(path_id) => {
                trace!(%conn_id, %path_id, ?path_status, "opening new path");
            }
            None => {
                let ret = now_or_never(fut);
                match ret {
                    Some(Err(PathError::RemoteCidsExhausted))
                    | Some(Err(PathError::MaxPathIdReached)) => {
                        self.scheduled_open_path =
                            Some(Instant::now() + Duration::from_millis(333));
                        self.pending_open_paths.enqueue(open_addr.clone());
                        trace!(?open_addr, ?ret, "scheduling open_path");
                    }
                    _ => warn!(?ret, "Opening path failed"),
                }
            }
        }
    }

    /// Returns the [`PathStatus`] for `addr`.
    ///
    /// Returns [`PathStatus::Available`] if `addr` is the currently-selected path,
    /// or [`PathStatus::Backup`] otherwise.
    fn path_status_for_addr(&self, addr: &transports::FourTuple) -> PathStatus {
        if Some(addr) == self.selected_path.as_ref() {
            PathStatus::Available
        } else {
            PathStatus::Backup
        }
    }

    /// Selects a path Noq has already established without opening any other path.
    ///
    /// Before peer candidates reach the actor, applying the normal selection could disclose a
    /// path learned from another connection. An exact path already open on this connection is
    /// safe to select after local authorization because it has completed Noq path validation.
    fn apply_existing_selected_path(
        &mut self,
        conn_id: ConnId,
        conn_state: &ConnectionState,
        conn: &noq::Connection,
        selected: &transports::FourTuple,
    ) {
        if !conn_state.paths.values().any(|path| path == selected) {
            return;
        }
        for (path_id, path_remote) in &conn_state.paths {
            if let Some(path) = conn.path(*path_id) {
                self.set_path_status(conn_id, &path, path_remote);
            }
        }
        conn_state.path_state.record_selected(selected);
    }

    /// Returns the [`transports::FourTuple] for a path.
    fn transport_tuple_for_path(&self, path: &noq::Path) -> Option<transports::FourTuple> {
        let noq_network_path = path.network_path().ok()?;
        transports::FourTuple::from_noq(
            noq_network_path,
            &self.relay_mapped_addrs,
            &self.custom_mapped_addrs,
        )
    }

    /// Returns the current set of local direct addresses.
    fn local_candidates(&mut self) -> BTreeSet<SocketAddr> {
        self.local_direct_addrs
            .get()
            .iter()
            .map(|d| d.addr)
            .collect()
    }

    fn bootstrap_path_allowed(
        &self,
        authority: &BootstrapAuthority,
        addr: &transports::Addr,
    ) -> bool {
        authority.endpoint_id() == self.endpoint_id
            && (!self.defer_nat_traversal_until_authorized
                || authority.permits(self.endpoint_id, addr))
    }
}

/// Updates QNT's candidate addresses to be the current set of direct addresses.
///
/// `direct_addrs` must be a set of addresses extracted from the endpoint's current
/// [`DirectAddr`]s.
fn update_qnt_candidates(conn: &noq::Connection, direct_addrs: &BTreeSet<SocketAddr>) {
    let noq_candidates = match conn.get_local_nat_traversal_addresses() {
        Ok(addrs) => BTreeSet::from_iter(addrs),
        Err(err) => {
            warn!("failed to get local nat candidates: {err:#}");
            return;
        }
    };
    for addr in direct_addrs.difference(&noq_candidates) {
        if let Err(err) = conn.add_nat_traversal_address(*addr) {
            warn!("failed adding local addr: {err:#}",);
        }
    }
    for addr in noq_candidates.difference(direct_addrs) {
        if let Err(err) = conn.remove_nat_traversal_address(*addr) {
            warn!("failed removing local addr: {err:#}");
        }
    }
    trace!(?direct_addrs, "updated local QNT addresses");
}

fn send_datagram<'a>(
    sender: &'a mut TransportsSender,
    addr: transports::FourTuple,
    owned_transmit: OwnedTransmit,
) -> impl Future<Output = n0_error::Result<()>> + 'a {
    std::future::poll_fn(move |cx| {
        let transmit = transports::Transmit {
            ecn: owned_transmit.ecn,
            contents: owned_transmit.contents.as_ref(),
            segment_size: owned_transmit.segment_size,
        };

        Pin::new(&mut *sender)
            .poll_send(cx, &addr, &transmit)
            .map(|res| res.with_context(|_| format!("failed to send datagram to {:?}", addr)))
    })
}

/// Messages to send to the [`RemoteStateActor`].
#[derive(derive_more::Debug)]
pub(crate) enum RemoteStateMessage {
    /// Sends a datagram to all known paths.
    ///
    /// Used to send QUIC Initial packets.  If there is no working direct path this will
    /// trigger holepunching.
    ///
    /// This is not acceptable to use on the normal send path, as it is an async send
    /// operation with a bunch more copying.  So it should only be used for sending QUIC
    /// Initial packets.
    #[debug("SendDatagram(..)")]
    SendDatagram(BootstrapAuthority, Box<TransportsSender>, OwnedTransmit),
    /// Adds an active connection to this remote endpoint.
    ///
    /// The actor will downgrade the connection to a [`noq::WeakConnectionHandle`] as soon
    /// as it processes the message. It will keep hold of the weak handle until it closes,
    /// but only update to a strong [`noq::Connection`] for brief moments.
    ///
    /// The actor will actively manage paths on the connection and start holepunching as needed.
    #[debug("AddConnection({})", _0.stable_id())]
    AddConnection(noq::Connection, oneshot::Sender<PathStateReceiver>),
    /// Authorizes NAT traversal for one exact active connection.
    AuthorizeNatTraversal {
        connection_id: usize,
        reply: oneshot::Sender<bool>,
    },
    /// Asks if there is any possible path that could be used.
    ///
    /// This adds the provided transport addresses to the list of potential paths for this
    /// remote and starts Address Lookup if needed.
    ///
    /// Sends back `Ok` immediately if the provided address list is non-empy or we have are
    /// other known paths.  Otherwise sends back `Ok` once Address Lookup produces a result,
    /// or the Address Lookup error if Address Lookup fails or produces no results,
    #[debug("ResolveRemote(..)")]
    ResolveRemote(
        BTreeSet<TransportAddr>,
        oneshot::Sender<Result<(), AddressLookupFailed>>,
        CancellationToken,
    ),
    /// Returns information about the remote.
    ///
    /// This currently only includes a list of all known transport addresses for the remote.
    RemoteInfo(oneshot::Sender<RemoteInfo>),
    /// The network status has changed in some way
    NetworkChange { is_major: bool },
}

/// Information about a holepunch attempt.
///
/// Addresses are always stored in canonical form.
#[derive(Debug)]
struct HolepunchAttempt {
    when: Instant,
    /// The set of local addresses which could take part in holepunching.
    ///
    /// This does not mean every address here participated in the holepunching.  E.g. we
    /// could have tried only a sub-set of the addresses because a previous attempt already
    /// covered part of the range.
    ///
    /// We do not store this as a [`DirectAddr`] because this is checked for equality and we
    /// do not want to compare the sources of these addresses.
    local_candidates: BTreeSet<SocketAddr>,
    /// The set of remote addresses which could take part in holepunching.
    ///
    /// Like [`Self::local_candidates`] we may not have used them.
    remote_candidates: BTreeSet<SocketAddr>,
}

/// Newtype to track Connections.
///
/// The wrapped value is the [`noq::Connection::stable_id`] value, and is thus only valid
/// for active connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, derive_more::Display)]
#[display("{_0}")]
struct ConnId(usize);

/// State about one connection.
#[derive(Debug)]
struct ConnectionState {
    /// Weak handle to the connection.
    handle: WeakConnectionHandle,
    /// Writer-side handle for the connection's path observation state.
    ///
    /// The matching [`PathStateReceiver`] is held by the [`Connection`].
    ///
    /// [`Connection`]: crate::endpoint::Connection
    path_state: PathStateSender,
    /// The open paths that exist on this connection.
    paths: FxHashMap<PathId, transports::FourTuple>,
    /// Whether this connection has ever had a direct path.
    ///
    /// Used for recording metrics.
    has_been_direct: bool,
    /// Whether application admission has authorized NAT traversal for this connection.
    nat_traversal_authorized: bool,
    /// Whether this connection has received candidates proving the peer released its gate.
    peer_candidates_observed: bool,
    /// Last NAT traversal round for this exact deferred connection.
    last_holepunch: Option<HolepunchAttempt>,
    /// Scheduled retry for this exact deferred connection.
    scheduled_holepunch: Option<Instant>,
}

impl ConnectionState {
    /// Publishes the already-active bootstrap path without releasing NAT traversal.
    ///
    /// Noq's path zero is the path established by the immutable authority of this exact dial.
    /// It already carries application data before admission. Recording it as selected only makes
    /// that existing fact observable; it does not open a path, expose candidates, or holepunch.
    fn record_deferred_bootstrap_selection(
        &self,
        path_id: PathId,
        network_path: &transports::FourTuple,
    ) {
        if !self.nat_traversal_authorized && path_id == PathId::ZERO {
            self.path_state.record_selected(network_path);
        }
    }

    /// Tracks an open path for the connection.
    fn add_open_path(
        &mut self,
        network_path: transports::FourTuple,
        path_id: PathId,
        metrics: &Arc<SocketMetrics>,
    ) {
        match network_path {
            transports::FourTuple::Ip { .. } => metrics.paths_direct.inc(),
            transports::FourTuple::Relay { .. } => metrics.paths_relay.inc(),
            transports::FourTuple::Custom { .. } => metrics.paths_custom.inc(),
        };
        if !self.has_been_direct && network_path.is_ip() {
            self.has_been_direct = true;
            metrics.num_conns_direct.inc();
        }

        self.paths.insert(path_id, network_path.clone());
        if let Some(conn) = self.handle.upgrade()
            && let Some(path) = conn.path(path_id)
        {
            let handle = path.weak_handle();
            self.path_state.record_opened(handle, network_path);
        }
    }

    /// Removes a path from this connection.
    fn remove_path(
        &mut self,
        path_id: &PathId,
        conn: &noq::Connection,
    ) -> Option<transports::FourTuple> {
        let addr = self.paths.remove(path_id)?;
        self.path_state.record_abandoned(*path_id, conn);
        Some(addr)
    }
}

/// State of the endpoint relevant for path selection.
///
/// Constructed by the endpoint and passed to [`PathSelector::select`].  Borrows from
/// the endpoint's internal data.
#[derive(Debug)]
#[cfg_attr(not(feature = "unstable-custom-transports"), allow(unreachable_pub))]
pub struct PathSelectionContext<'a> {
    current: Option<&'a transports::FourTuple>,
    source: PathsSource<'a>,
}

/// Either a reference to live connection state, or a synthesized list of paths
/// (for unit-testing selectors).
#[derive(Debug)]
enum PathsSource<'a> {
    Live(&'a FxHashMap<ConnId, ConnectionState>),
    #[cfg(test)]
    Test(Vec<PathSelectionData<'a>>),
}

#[cfg_attr(not(feature = "unstable-custom-transports"), allow(unreachable_pub))]
impl<'a> PathSelectionContext<'a> {
    fn new(
        current: Option<&'a transports::FourTuple>,
        connections: &'a FxHashMap<ConnId, ConnectionState>,
    ) -> Self {
        Self {
            current,
            source: PathsSource::Live(connections),
        }
    }

    /// Constructs a context with synthetic path data for testing.
    #[cfg(test)]
    pub(crate) fn for_test(
        current: Option<&'a transports::FourTuple>,
        paths: Vec<PathSelectionData<'a>>,
    ) -> Self {
        Self {
            current,
            source: PathsSource::Test(paths),
        }
    }

    /// The path currently considered the preferred path to the remote endpoint, if any.
    pub fn current(&self) -> Option<&transports::FourTuple> {
        self.current
    }

    /// Iterator over candidate paths.
    ///
    /// The same address may appear more than once when it is a path on multiple
    /// connections to the remote.  Selectors that care should aggregate as appropriate.
    pub fn paths(&self) -> Box<dyn Iterator<Item = PathSelectionData<'a>> + '_> {
        match &self.source {
            PathsSource::Live(connections) => Box::new(
                connections
                    .values()
                    .filter(|state| state.nat_traversal_authorized)
                    .filter_map(|state| state.handle.upgrade().map(|conn| (state, conn)))
                    .flat_map(|(state, conn)| {
                        state.paths.iter().map(move |(path_id, addr)| {
                            PathSelectionData::live(addr, *path_id, conn.clone())
                        })
                    }),
            ),
            #[cfg(test)]
            PathsSource::Test(paths) => Box::new(paths.iter().cloned()),
        }
    }
}

/// Data the selector sees about one candidate path.
//
// In production this borrows from a live connection and looks up stats from noq on
// demand.  In `#[cfg(test)]` builds it can also wrap synthesized stats so selectors
// can be unit-tested without standing up real connections.
#[cfg_attr(not(feature = "unstable-custom-transports"), allow(unreachable_pub))]
#[derive(derive_more::Debug, Clone)]
pub struct PathSelectionData<'a> {
    network_path: &'a transports::FourTuple,
    #[debug(skip)]
    source: StatsSource,
}

#[derive(Clone)]
enum StatsSource {
    Live {
        path_id: PathId,
        conn: noq::Connection,
    },
    /// Boxed so `PathStats` (100+ bytes, 14 fields) doesn't inflate the enum's
    /// size in production where only the `Live` variant is ever constructed.
    #[cfg(test)]
    Test(Option<Box<PathStats>>),
}

#[cfg_attr(not(feature = "unstable-custom-transports"), allow(unreachable_pub))]
impl<'a> PathSelectionData<'a> {
    fn live(
        network_path: &'a transports::FourTuple,
        path_id: PathId,
        conn: noq::Connection,
    ) -> Self {
        Self {
            network_path,
            source: StatsSource::Live { path_id, conn },
        }
    }

    /// Constructs a [`PathSelectionData`] with synthetic stats for testing.
    ///
    /// `PathStats` is `#[non_exhaustive]` so callers build it via
    /// `let mut s = PathStats::default(); s.rtt = ...;`.
    #[cfg(test)]
    pub(crate) fn for_test(
        network_path: &'a transports::FourTuple,
        stats: Option<PathStats>,
    ) -> Self {
        Self {
            network_path,
            source: StatsSource::Test(stats.map(Box::new)),
        }
    }

    /// The network path of the candidate path.
    pub fn network_path(&self) -> &transports::FourTuple {
        self.network_path
    }

    /// Returns path statistics if available.
    pub fn stats(&self) -> Option<PathStats> {
        match &self.source {
            StatsSource::Live { path_id, conn } => conn.path_stats(*path_id),
            #[cfg(test)]
            StatsSource::Test(stats) => stats.as_deref().copied(),
        }
    }
}

/// Trait to configure path selection.
///
/// Most users do not need to provide their own selector.
#[cfg_attr(not(feature = "unstable-custom-transports"), allow(unreachable_pub))]
pub trait PathSelector: Send + Sync + std::fmt::Debug + 'static {
    /// Pick the selected path to carry application data among the currently
    /// open network paths to the remote endpoint.
    ///
    /// Build the result by starting from [`PathSelection::none`] and calling
    /// [`PathSelection::set`] for the path the selector wants active.
    ///
    /// Returning an empty [`PathSelection`] keeps the current selection unchanged.
    fn select(&self, ctx: &PathSelectionContext<'_>) -> PathSelection;
}

/// The set of paths a [`PathSelector`] has chosen.
///
/// Today this holds at most one path.  Build via [`PathSelection::none`] +
/// [`PathSelection::set`].
#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "unstable-custom-transports"), allow(unreachable_pub))]
pub struct PathSelection {
    selection: Option<transports::FourTuple>,
}

#[cfg_attr(not(feature = "unstable-custom-transports"), allow(unreachable_pub))]
impl PathSelection {
    /// An empty selection.
    pub fn none() -> Self {
        Self { selection: None }
    }

    /// Sets the path as the selected path.
    ///
    /// This discards any previously selected path and sets this one as a single selected
    /// path.
    pub fn set(&mut self, path: &PathSelectionData<'_>) {
        if self.selection.is_some() {
            tracing::warn!(
                path = %path.network_path(),
                "PathSelection already contains a path; ignoring additional path"
            );
            return;
        }
        self.selection = Some(path.network_path.clone());
    }

    /// The selected path: the one data should be sent on. This is not public so
    /// we can later allow for selecting multiple paths without changing the
    /// public API of `PathSelection`.
    ///
    /// Returns `None` when nothing has been selected.
    pub(crate) fn selected(&self) -> Option<&transports::FourTuple> {
        self.selection.as_ref()
    }
}

/// Poll a future once, like n0_future::future::poll_once but sync.
fn now_or_never<T, F: Future<Output = T>>(fut: F) -> Option<T> {
    let fut = std::pin::pin!(fut);
    match fut.poll(&mut std::task::Context::from_waker(std::task::Waker::noop())) {
        Poll::Ready(res) => Some(res),
        Poll::Pending => None,
    }
}

/// Future that resolves to the `conn_id` once a connection is closed.
///
/// This uses [`noq::Connection::on_closed`], which does not keep the connection alive
/// while awaiting the future.
struct OnClosed {
    conn_id: ConnId,
    inner: noq::OnClosed,
}

impl OnClosed {
    fn new(conn: &noq::Connection) -> Self {
        Self {
            conn_id: ConnId(conn.stable_id()),
            inner: conn.on_closed(),
        }
    }
}

impl Future for OnClosed {
    type Output = (ConnId, Closed);

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let closed = std::task::ready!(Pin::new(&mut self.inner).poll(cx));
        Poll::Ready((self.conn_id, closed))
    }
}

/// Converts an iterator of [`TransportAddr'] into an iterator of [`transports::Addr`].
fn to_transports_addr(
    endpoint_id: EndpointId,
    addrs: impl IntoIterator<Item = TransportAddr>,
) -> impl Iterator<Item = transports::Addr> {
    addrs.into_iter().filter_map(move |addr| match addr {
        TransportAddr::Relay(relay_url) => Some(transports::Addr::from((relay_url, endpoint_id))),
        TransportAddr::Ip(sockaddr) => Some(transports::Addr::from(sockaddr)),
        TransportAddr::Custom(custom_addr) => Some(transports::Addr::from(custom_addr)),
        _ => {
            warn!(?addr, "Unsupported TransportAddr");
            None
        }
    })
}

/// Returns the next item if `maybe_stream` is `Some`, or `None` otherwise.
async fn maybe_next<S: Stream + Unpin>(maybe_stream: Option<&mut S>) -> Option<Option<S::Item>> {
    match maybe_stream {
        None => None,
        Some(s) => Some(s.next().await),
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::{MAX_PENDING_OPEN_PATHS, PendingOpenPaths};
    use crate::socket::transports::FourTuple;

    fn ip_path(port: u16) -> FourTuple {
        FourTuple::Ip {
            remote: SocketAddr::from(([192, 0, 2, 1], port)),
            local: None,
        }
    }

    #[test]
    fn pending_open_paths_are_bounded_across_multi_connection_retries() {
        let repeated_path = ip_path(1);
        let mut pending = PendingOpenPaths::default();

        // Each retry is fanned out to every connection. Two capped
        // connections must not double the queue on every retry cycle.
        for _ in 0..1_024 {
            for _connection in 0..2 {
                pending.enqueue(repeated_path.clone());
            }
        }
        assert_eq!(pending.len(), 1);
        assert!(pending.contains(&repeated_path));

        // A peer can advertise many distinct unreachable candidates. Retain
        // only a fixed working set and prefer newer observations when full.
        for port in 2..=(MAX_PENDING_OPEN_PATHS as u16 + 10) {
            pending.enqueue(ip_path(port));
        }
        assert_eq!(pending.len(), MAX_PENDING_OPEN_PATHS);
        assert!(!pending.contains(&ip_path(1)));
        assert!(pending.contains(&ip_path(MAX_PENDING_OPEN_PATHS as u16 + 10)));
    }
}
