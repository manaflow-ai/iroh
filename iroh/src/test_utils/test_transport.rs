//! In-memory test transport for testing.
//!
//! This module provides [`TestNetwork`] and [`TestTransport`] for testing
//! using in-memory channels instead of real network transports.

use std::{
    collections::BTreeMap,
    io,
    sync::{Arc, Mutex},
    task::Poll,
};

use bytes::Bytes;
use iroh_base::{CustomAddr, EndpointId, TransportAddr};
use tokio::sync::mpsc::{self, error::TrySendError};
use tracing::info;

use crate::{
    address_lookup::{AddressLookup, EndpointData, EndpointInfo, Item},
    endpoint::{
        Builder,
        presets::Preset,
        transports::{CustomEndpoint, CustomSender, CustomTransport, RecvInfo, Transmit},
    },
};

/// The transport ID used by [`TestNetwork`].
///
/// See `TRANSPORTS.md` for the registry of transport IDs.
pub const TEST_TRANSPORT_ID: u64 = 0x20;

/// An outgoing packet that can be sent across channels.
#[derive(Debug, Clone)]
pub(crate) struct Packet {
    pub(crate) data: Bytes,
    pub(crate) from: CustomAddr,
}

/// A test transport for use with [`TestNetwork`].
///
/// Implements [`CustomTransport`] and [`CustomEndpoint`] for testing.
#[derive(Debug, Clone)]
pub struct TestTransport {
    id: EndpointId,
    id_watchable: n0_watcher::Watchable<Vec<CustomAddr>>,
    network: TestNetwork,
}

impl Preset for Arc<TestTransport> {
    /// Configures the builder with this transport and the network's address lookup.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let network = TestNetwork::new();
    /// let transport = network.create_transport(secret_key.public())?;
    /// let ep = Endpoint::builder()
    ///     .secret_key(secret_key)
    ///     .preset(transport)
    ///     .bind()
    ///     .await?;
    /// ```
    fn apply(self, builder: Builder) -> Builder {
        builder
            .add_custom_transport(self.clone())
            .address_lookup(self.network.address_lookup())
    }
}

/// A simulated network for testing custom transports.
///
/// This allows creating multiple [`TestTransport`] instances that can communicate
/// with each other through in-memory channels.
///
/// # Example
///
/// ```ignore
/// use iroh::test_utils::custom_transport::TestNetwork;
///
/// let network = TestNetwork::new();
/// let transport1 = network.create_transport(endpoint_id1)?;
/// let transport2 = network.create_transport(endpoint_id2)?;
/// // transport1 and transport2 can now communicate via the network
/// ```
#[derive(Debug, Clone, Default)]
pub struct TestNetwork {
    inner: Arc<Mutex<TestNetworkInner>>,
}

impl TestNetwork {
    /// Creates a new empty test network.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an address lookup service for this network.
    pub fn address_lookup(&self) -> impl AddressLookup {
        TestAddrLookup {
            network: self.clone(),
        }
    }

    /// Starts or stops dropping every packet carried by this test transport.
    ///
    /// While enabled, sends still report success but nothing is delivered —
    /// exactly like a network path that went dark. Other transports on the
    /// same endpoints (relay, IP) are unaffected, so this simulates the field
    /// condition "the direct path is dead while the relay stays healthy".
    pub fn set_blackhole(&self, blackhole: bool) {
        self.inner.lock().expect("poisoned").blackhole = blackhole;
    }

    /// Creates a new test transport for the given endpoint ID.
    ///
    /// Returns an error if the ID already exists in the network.
    pub fn create_transport(&self, id: EndpointId) -> io::Result<Arc<TestTransport>> {
        let id_custom = to_custom_addr(id);
        let mut guard = self.inner.lock().expect("poisoned");
        if guard.channels.contains_key(&id) {
            return Err(io::Error::other("endpoint ID already exists in network"));
        }
        guard.channels.insert(id, mpsc::channel(256));
        drop(guard);
        Ok(Arc::new(TestTransport {
            id_watchable: n0_watcher::Watchable::new(vec![id_custom]),
            network: self.clone(),
            id,
        }))
    }
}

#[derive(Debug)]
struct TestAddrLookup {
    network: TestNetwork,
}

#[derive(Debug, Default)]
struct TestNetworkInner {
    channels: BTreeMap<EndpointId, (mpsc::Sender<Packet>, mpsc::Receiver<Packet>)>,
    /// When `true`, all packets are silently dropped (see [`TestNetwork::set_blackhole`]).
    blackhole: bool,
}

impl AddressLookup for TestAddrLookup {
    fn publish(&self, _data: &EndpointData) {}

    fn resolve(
        &self,
        endpoint_id: EndpointId,
    ) -> Option<n0_future::stream::Boxed<Result<Item, crate::address_lookup::Error>>> {
        if self
            .network
            .inner
            .lock()
            .expect("poisoned")
            .channels
            .contains_key(&endpoint_id)
        {
            Some(Box::pin(n0_future::stream::once(Ok(Item::new(
                EndpointInfo {
                    endpoint_id,
                    data: EndpointData::from_iter([TransportAddr::Custom(CustomAddr::from_parts(
                        TEST_TRANSPORT_ID,
                        endpoint_id.as_bytes(),
                    ))]),
                },
                "test discovery",
                None,
            )))))
        } else {
            None
        }
    }
}

#[derive(Debug, Clone)]
struct TestSender {
    id: EndpointId,
    network: TestNetwork,
}

/// Converts an endpoint ID to a custom address for this test transport.
pub fn to_custom_addr(endpoint: EndpointId) -> CustomAddr {
    CustomAddr::from((TEST_TRANSPORT_ID, &endpoint.as_bytes()[..]))
}

fn try_parse_custom_addr(addr: &CustomAddr) -> io::Result<EndpointId> {
    if addr.id() != TEST_TRANSPORT_ID {
        return Err(io::Error::other("unexpected transport id"));
    }
    let key_bytes: &[u8; 32] = addr
        .data()
        .try_into()
        .map_err(|_| io::Error::other("wrong key length"))?;
    EndpointId::from_bytes(key_bytes).map_err(|_| io::Error::other("KeyParseError"))
}

impl TestSender {
    fn send_sync(&self, dst: &CustomAddr, packets: Vec<Packet>) -> io::Result<()> {
        let to_id = try_parse_custom_addr(dst)?;
        let guard = self.network.inner.lock().expect("poisoned");
        if guard.blackhole {
            info!(
                "send {} -> {}: dropped {} packets (blackhole)",
                self.id.fmt_short(),
                to_id.fmt_short(),
                packets.len()
            );
            return Ok(());
        }
        let (s, _) = guard
            .channels
            .get(&to_id)
            .ok_or_else(|| io::Error::other("Unknown endpoint"))?;
        for packet in packets {
            let len = packet.data.len();
            match s.try_send(packet) {
                Ok(_) => info!(
                    "send {} -> {}: sent {} bytes",
                    self.id.fmt_short(),
                    to_id.fmt_short(),
                    len
                ),
                Err(TrySendError::Full(_)) => info!(
                    "send {} -> {}: dropped {} bytes",
                    self.id.fmt_short(),
                    to_id.fmt_short(),
                    len
                ),
                Err(TrySendError::Closed(_)) => return Err(io::Error::other("channel closed")),
            }
        }
        Ok(())
    }

    fn split(&self, transmit: &Transmit) -> impl Iterator<Item = Packet> {
        let from = to_custom_addr(self.id);
        let segment_size = transmit.segment_size.unwrap_or(transmit.contents.len());
        transmit
            .contents
            .chunks(segment_size)
            .map(move |slice| Packet {
                from: from.clone(),
                data: Bytes::copy_from_slice(slice),
            })
    }
}

impl CustomSender for TestSender {
    fn is_valid_send_addr(&self, addr: &CustomAddr) -> bool {
        addr.id() == TEST_TRANSPORT_ID
    }

    fn poll_send(
        &self,
        _cx: &mut std::task::Context,
        dst: &CustomAddr,
        _src: Option<&CustomAddr>,
        transmit: &Transmit<'_>,
    ) -> Poll<io::Result<()>> {
        let packets = self.split(transmit).collect();
        Poll::Ready(self.send_sync(dst, packets))
    }
}

impl CustomTransport for TestTransport {
    fn bind(&self) -> io::Result<Box<dyn CustomEndpoint>> {
        Ok(Box::new(self.clone()))
    }
}

impl CustomEndpoint for TestTransport {
    fn watch_local_addrs(&self) -> n0_watcher::Direct<Vec<CustomAddr>> {
        self.id_watchable.watch()
    }

    fn create_sender(&self) -> Arc<dyn CustomSender> {
        Arc::new(TestSender {
            id: self.id,
            network: self.network.clone(),
        })
    }

    fn poll_recv(
        &mut self,
        cx: &mut std::task::Context,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [noq_udp::RecvMeta],
        recv_infos: &mut [RecvInfo],
    ) -> Poll<io::Result<usize>> {
        assert_eq!(bufs.len(), metas.len(), "non matching bufs & metas");
        assert_eq!(
            bufs.len(),
            recv_infos.len(),
            "non matching bufs & recv_infos"
        );
        let n = bufs.len();
        if n == 0 {
            return Poll::Ready(Ok(0));
        }
        let mut guard = self.network.inner.lock().expect("poisoned");
        let Some((_, r)) = guard.channels.get_mut(&self.id) else {
            info!("me: {} not found in channels", self.id.fmt_short());
            return Poll::Ready(Ok(0));
        };
        let mut packets = Vec::new();
        match r.poll_recv_many(cx, &mut packets, n) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(0) => return Poll::Ready(Err(io::Error::other("channel closed"))),
            Poll::Ready(n) => n,
        };
        let mut count = 0;
        for (i, packet) in packets.into_iter().enumerate() {
            let meta = &mut metas[i];
            let buf = &mut bufs[i];
            let recv_info = &mut recv_infos[i];
            if buf.len() < packet.data.len() {
                break;
            }
            let from = try_parse_custom_addr(&packet.from).expect("valid custom addr");
            info!(
                "recv {} -> {}: copying {} bytes",
                from.fmt_short(),
                self.id.fmt_short(),
                packet.data.len()
            );
            buf[..packet.data.len()].copy_from_slice(&packet.data);
            *recv_info = RecvInfo::new(packet.from, Some(to_custom_addr(self.id)));
            meta.len = packet.data.len();
            meta.stride = packet.data.len();
            count += 1;
        }
        if count > 0 {
            info!("recv {}: filled {count} slots", self.id.fmt_short());
            Poll::Ready(Ok(count))
        } else {
            Poll::Pending
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };

    use iroh_relay::RelayMap;
    use n0_error::{Result, StdResultExt};
    use n0_tracing_test::traced_test;

    use super::*;
    use crate::{
        Endpoint, EndpointAddr, RelayMode, SecretKey, TransportAddr,
        endpoint::{Builder, Connection, presets, transports::AddrKind},
        protocol::{AcceptError, ProtocolHandler, Router},
        socket::biased_rtt_path_selector::{BiasedRttPathSelector, TransportBias},
        test_utils::run_relay_server,
    };

    const ECHO_ALPN: &[u8] = b"test/echo";

    #[derive(Debug, Clone)]
    struct Echo;

    impl ProtocolHandler for Echo {
        async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
            let (mut send, mut recv) = connection.accept_bi().await?;
            tokio::io::copy(&mut recv, &mut send).await?;
            send.finish()?;
            connection.closed().await;
            Ok(())
        }
    }

    /// Configuration for endpoint builder.
    #[derive(Clone, Default)]
    struct EndpointConfig {
        custom_bias: Option<TransportBias>,
        keep_ip: bool,
        relay_map: Option<RelayMap>,
    }

    impl EndpointConfig {
        fn with_custom_bias(mut self, bias: TransportBias) -> Self {
            self.custom_bias = Some(bias);
            self
        }

        fn with_ip(mut self) -> Self {
            self.keep_ip = true;
            self
        }

        fn with_relay(mut self, relay_map: RelayMap) -> Self {
            self.relay_map = Some(relay_map);
            self
        }
    }

    /// Creates a basic endpoint builder with the given secret key and custom transport.
    fn endpoint_builder(
        secret_key: SecretKey,
        transport: Arc<TestTransport>,
        config: EndpointConfig,
    ) -> Builder {
        let relay_mode = match config.relay_map {
            Some(map) => RelayMode::Custom(map),
            None => RelayMode::Disabled,
        };
        let mut builder = Endpoint::builder(presets::N0)
            .secret_key(secret_key)
            .relay_mode(relay_mode)
            .ca_tls_config(crate::tls::CaTlsConfig::insecure_skip_verify())
            .add_custom_transport(transport);
        if let Some(bias) = config.custom_bias {
            builder = builder.path_selector(Arc::new(
                BiasedRttPathSelector::default()
                    .with_bias(AddrKind::Custom(TEST_TRANSPORT_ID), bias),
            ));
        }
        if !config.keep_ip {
            builder = builder.clear_ip_transports();
        }
        builder
    }

    /// Creates an address with both IP (from endpoint) and custom transport addresses.
    fn mixed_addr(ep: &Endpoint, endpoint_id: EndpointId) -> EndpointAddr {
        let ep_addr = ep.addr();
        let custom_addr = to_custom_addr(endpoint_id);
        EndpointAddr::from_parts(
            endpoint_id,
            ep_addr
                .addrs
                .iter()
                .cloned()
                .chain(std::iter::once(TransportAddr::Custom(custom_addr))),
        )
    }

    /// Creates an address with only the custom transport address.
    fn custom_only_addr(endpoint_id: EndpointId) -> EndpointAddr {
        EndpointAddr::from_parts(
            endpoint_id,
            std::iter::once(TransportAddr::Custom(to_custom_addr(endpoint_id))),
        )
    }

    /// Returns true if the selected path is the custom transport.
    fn is_custom_selected(conn: &crate::endpoint::Connection) -> bool {
        let paths = conn.paths();
        paths.iter().find(|p| p.is_selected()).is_some_and(
            |p| matches!(p.remote_addr(), TransportAddr::Custom(a) if a.id() == TEST_TRANSPORT_ID),
        )
    }

    /// Returns true if either
    /// - we have both IP and custom paths, and the selected path is IP.
    /// - we only have one path
    fn is_ip_selected_from_ip_and_custom(conn: &crate::endpoint::Connection) -> bool {
        let paths = conn.paths();
        let has_ip = paths.iter().any(|p| p.remote_addr().is_ip());
        let has_custom = paths.iter().any(|p| p.remote_addr().is_custom());
        if !has_ip || !has_custom {
            return true;
        }
        paths
            .iter()
            .any(|p| p.is_selected() && p.remote_addr().is_ip())
    }

    /// Returns true if the selected path is a relay transport.
    fn is_relay_selected(conn: &crate::endpoint::Connection) -> bool {
        let paths = conn.paths();
        paths
            .iter()
            .find(|p| p.is_selected())
            .is_some_and(|p| p.is_relay())
    }

    /// Verifies echo works over the connection.
    async fn verify_echo(conn: &crate::endpoint::Connection, msg: &[u8]) -> Result<()> {
        let (mut send, mut recv) = conn.open_bi().await.anyerr()?;
        send.write_all(msg).await.anyerr()?;
        send.finish().anyerr()?;
        let response = recv.read_to_end(100).await.anyerr()?;
        assert_eq!(response, msg);
        Ok(())
    }

    /// Test custom transport only - no IP, no relay, dial by custom address.
    #[tokio::test]
    #[traced_test]
    async fn test_custom_transport_only() -> Result<()> {
        let network = TestNetwork::new();
        let s1 = SecretKey::generate();
        let s2 = SecretKey::generate();

        let t1 = network.create_transport(s1.public())?;
        let t2 = network.create_transport(s2.public())?;

        let ep1 = endpoint_builder(s1, t1, EndpointConfig::default())
            .bind()
            .await?;
        let ep2 = endpoint_builder(s2.clone(), t2, EndpointConfig::default())
            .bind()
            .await?;
        let router = Router::builder(ep2).accept(ECHO_ALPN, Echo).spawn();

        let conn = ep1
            .connect(custom_only_addr(s2.public()), ECHO_ALPN)
            .await?;

        // Verify exactly one path exists and it's the custom transport
        let paths = conn.paths();
        assert_eq!(paths.len(), 1, "Expected exactly one path");
        assert!(
            is_custom_selected(&conn),
            "Custom transport should be selected"
        );

        verify_echo(&conn, b"custom only").await?;
        conn.close(0u32.into(), b"done");
        router.shutdown().await.anyerr()?;
        Ok(())
    }

    /// Test that custom transports can surface a local address per incoming packet.
    #[tokio::test]
    #[traced_test]
    async fn test_custom_transport_local_addr() -> Result<()> {
        use crate::endpoint::LocalTransportAddr;

        let network = TestNetwork::new();
        let s1 = SecretKey::generate();
        let s2 = SecretKey::generate();

        let t1 = network.create_transport(s1.public())?;
        let t2 = network.create_transport(s2.public())?;

        let ep1 = endpoint_builder(s1, t1, EndpointConfig::default())
            .bind()
            .await?;
        let ep2 = endpoint_builder(s2.clone(), t2, EndpointConfig::default())
            .alpns(vec![ECHO_ALPN.to_vec()])
            .bind()
            .await?;

        let connect = tokio::spawn({
            let ep1 = ep1.clone();
            let dst = custom_only_addr(s2.public());
            async move { ep1.connect(dst, ECHO_ALPN).await }
        });

        let incoming = ep2.accept().await.expect("incoming");
        assert_eq!(
            incoming.local_addr(),
            LocalTransportAddr::Custom(Some(to_custom_addr(s2.public()))),
        );
        let _conn = incoming.accept().anyerr()?.await.anyerr()?;

        connect.await.anyerr()??;
        Ok(())
    }

    /// Test that custom transport is selected over IP when given an RTT advantage.
    #[tokio::test]
    #[traced_test]
    async fn test_custom_transport_wins_over_ip() -> Result<()> {
        let network = TestNetwork::new();
        let s1 = SecretKey::generate();
        let s2 = SecretKey::generate();

        let t1 = network.create_transport(s1.public())?;
        let t2 = network.create_transport(s2.public())?;

        // Strong RTT advantage for custom transport
        let custom_bias = TransportBias::primary().with_rtt_advantage(Duration::from_secs(10));
        let config = EndpointConfig::default()
            .with_ip()
            .with_custom_bias(custom_bias);

        let ep1 = endpoint_builder(s1, t1, config.clone()).bind().await?;
        let ep2 = endpoint_builder(s2.clone(), t2, config).bind().await?;
        let router = Router::builder(ep2.clone()).accept(ECHO_ALPN, Echo).spawn();

        let conn = ep1
            .connect(mixed_addr(&ep2, s2.public()), ECHO_ALPN)
            .await?;

        // Wait for paths to settle
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert!(
            is_custom_selected(&conn),
            "Custom transport should be selected with RTT advantage"
        );

        verify_echo(&conn, b"custom wins").await?;
        conn.close(0u32.into(), b"done");
        router.shutdown().await.anyerr()?;
        Ok(())
    }

    /// Test that IP is selected over custom transport when custom has an RTT disadvantage.
    #[tokio::test]
    #[traced_test]
    async fn test_ip_wins_over_custom() -> Result<()> {
        let network = TestNetwork::new();
        let s1 = SecretKey::generate();
        let s2 = SecretKey::generate();

        let t1 = network.create_transport(s1.public())?;
        let t2 = network.create_transport(s2.public())?;

        // Strong RTT disadvantage for custom transport
        let custom_bias = TransportBias::primary().with_rtt_disadvantage(Duration::from_secs(10));
        let config = EndpointConfig::default()
            .with_ip()
            .with_custom_bias(custom_bias);

        let ep1 = endpoint_builder(s1, t1, config.clone()).bind().await?;
        let ep2 = endpoint_builder(s2.clone(), t2, config).bind().await?;
        let router = Router::builder(ep2.clone()).accept(ECHO_ALPN, Echo).spawn();

        let conn = ep1
            .connect(mixed_addr(&ep2, s2.public()), ECHO_ALPN)
            .await?;

        // Wait for paths to settle
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert!(
            is_ip_selected_from_ip_and_custom(&conn),
            "IP transport should be selected when custom has RTT disadvantage"
        );

        verify_echo(&conn, b"ip wins").await?;
        conn.close(0u32.into(), b"done");
        router.shutdown().await.anyerr()?;
        Ok(())
    }

    /// Test that custom transport (primary) is selected over relay (backup).
    ///
    /// This test first connects using only the relay address, then reconnects with
    /// both relay and custom addresses to verify the custom transport (primary) wins
    /// over the relay (backup).
    #[tokio::test]
    #[traced_test]
    async fn test_custom_transport_wins_over_relay() -> Result<()> {
        let (relay_map, _relay_url, _guard) = run_relay_server().await?;
        let network = TestNetwork::new();
        let s1 = SecretKey::generate();
        let s2 = SecretKey::generate();

        let t1 = network.create_transport(s1.public())?;
        let t2 = network.create_transport(s2.public())?;

        // Custom transport is primary by default, relay is backup
        let config = EndpointConfig::default().with_relay(relay_map.clone());

        let ep1 = endpoint_builder(s1, t1, config.clone()).bind().await?;
        let ep2 = endpoint_builder(s2.clone(), t2, config).bind().await?;

        // Wait for relay connection to be established
        ep1.online().await;
        ep2.online().await;

        let router = Router::builder(ep2.clone()).accept(ECHO_ALPN, Echo).spawn();

        // Get all addresses including relay and custom
        let ep2_addr = ep2.addr();
        let custom_addr = to_custom_addr(s2.public());

        // Debug: print ep2 address to see what's available
        eprintln!("ep2 address: {:?}", ep2_addr);

        // Create address with both relay and custom
        let all_addrs = EndpointAddr::from_parts(
            s2.public(),
            ep2_addr
                .addrs
                .iter()
                .cloned()
                .chain(std::iter::once(TransportAddr::Custom(custom_addr))),
        );
        eprintln!("Connecting with all addresses: {:?}", all_addrs);

        // First, connect with relay-only to verify relay works
        let relay_addrs: Vec<_> = ep2_addr
            .addrs
            .iter()
            .filter(|a| matches!(a, TransportAddr::Relay(_)))
            .cloned()
            .collect();
        eprintln!("Relay addresses in ep2_addr: {:?}", relay_addrs);

        // If there are no relay addresses, skip the relay-first test
        if relay_addrs.is_empty() {
            eprintln!(
                "WARNING: No relay addresses found in ep2_addr, skipping relay-first connection test"
            );
        } else {
            // Connect with relay-only address first to verify relay works
            let relay_only_addr = EndpointAddr::from_parts(s2.public(), relay_addrs.into_iter());
            eprintln!("Connecting with relay-only address: {:?}", relay_only_addr);

            let conn = ep1.connect(relay_only_addr, ECHO_ALPN).await?;

            // Wait for relay path to be established
            tokio::time::sleep(Duration::from_millis(200)).await;

            // Debug: print paths after relay-only connect
            let paths = conn.paths();
            eprintln!("Paths after relay-only connect:");
            for path in paths.iter() {
                eprintln!(
                    "  {} selected={} rtt={:?}",
                    path.remote_addr(),
                    path.is_selected(),
                    path.rtt()
                );
            }

            // Verify relay is currently selected
            assert!(
                is_relay_selected(&conn),
                "Relay should be selected after connecting with relay-only address"
            );

            verify_echo(&conn, b"relay test").await?;
            conn.close(0u32.into(), b"done with relay test");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Now connect with all addresses (relay + custom)
        let conn = ep1.connect(all_addrs, ECHO_ALPN).await?;

        // Wait for paths to settle
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Debug: print all paths
        let paths = conn.paths();
        eprintln!("Paths after connecting with all addresses:");
        for path in paths.iter() {
            eprintln!(
                "  {} selected={} rtt={:?}",
                path.remote_addr(),
                path.is_selected(),
                path.rtt()
            );
        }

        // Custom (primary) should win over relay (backup)
        assert!(
            is_custom_selected(&conn),
            "Custom transport (primary) should be selected over relay (backup)"
        );

        verify_echo(&conn, b"custom wins over relay").await?;
        conn.close(0u32.into(), b"done");
        router.shutdown().await.anyerr()?;
        Ok(())
    }

    /// Regression test for the cmux dead-direct-path kill loop: when the
    /// *selected* direct path goes dark while a healthy relay path is open on
    /// the same connection, iroh must promptly demote it without closing QUIC.
    ///
    /// Field condition being modeled (see
    /// out/iroh-fork-program/B1-mechanism-note.md in cmuxterm-hq): both a
    /// direct (primary-tier) and a relay (backup-tier) path exist; the direct
    /// path is selected (`PathStatus::Available`, relay `Backup`); the direct
    /// path then black-holes. Because noq pins ALL SpaceKind::Data frames
    /// (streams, retransmits, ACKs) to the validated+Available path, and iroh
    /// without iroh's health detector application data stalls until the
    /// per-path idle timeout (`PATH_MAX_IDLE_TIMEOUT` = 15s) abandons the dead
    /// path — even though the relay could carry the data the whole time.
    /// cmux's session layer kills the connection ~2.2s into that black hole
    /// (sendQueueOverflow / control watchdog), producing the ~2s metronome
    /// kill loop in the field.
    ///
    /// The contract is survival plus relay failover within a generous 6s CI
    /// margin (the detector normally reacts in ~1-2s), followed by sustained
    /// application traffic on the same connection.
    #[tokio::test]
    #[traced_test]
    async fn test_dead_selected_direct_path_demotes_to_relay() -> Result<()> {
        /// The normal ~1-2s demotion gets ample CI headroom while remaining
        /// far below the old ~15s path-idle recovery.
        const RECOVERY_DEADLINE: Duration = Duration::from_secs(6);
        /// Keep probing well past the pre-fix ~15s path-idle recovery so a
        /// regression is diagnosed as "slow recovery at ~15s" rather than
        /// "permanently wedged".
        const PROBE_BUDGET: Duration = Duration::from_secs(45);

        let (relay_map, _relay_url, _guard) = run_relay_server().await?;
        let network = TestNetwork::new();
        let s1 = SecretKey::generate();
        let s2 = SecretKey::generate();

        let t1 = network.create_transport(s1.public())?;
        let t2 = network.create_transport(s2.public())?;

        // IP transports are cleared by default in `endpoint_builder`, so the
        // custom transport is the only primary-tier ("direct") path and the
        // relay is the only backup-tier path — the exact field topology.
        let config = EndpointConfig::default().with_relay(relay_map.clone());
        let ep1 = endpoint_builder(s1, t1, config.clone()).bind().await?;
        let ep2 = endpoint_builder(s2.clone(), t2, config).bind().await?;

        // Wait for both endpoints to have their relay connection.
        ep1.online().await;
        ep2.online().await;

        let router = Router::builder(ep2.clone()).accept(ECHO_ALPN, Echo).spawn();

        // Dial with BOTH the relay and the custom address so both paths open.
        let ep2_addr = ep2.addr();
        let all_addrs = EndpointAddr::from_parts(
            s2.public(),
            ep2_addr
                .addrs
                .iter()
                .cloned()
                .chain(std::iter::once(TransportAddr::Custom(to_custom_addr(
                    s2.public(),
                )))),
        );
        let conn = ep1.connect(all_addrs, ECHO_ALPN).await?;

        // Wait until the steady state we are testing: the direct (custom)
        // path is selected AND a relay path is open on the connection.
        let settle_deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let paths = conn.paths();
            let has_relay = paths.iter().any(|p| p.is_relay());
            if has_relay && is_custom_selected(&conn) {
                break;
            }
            assert!(
                Instant::now() < settle_deadline,
                "test setup failed: custom-selected + relay path never settled; paths: {:?}",
                paths
                    .iter()
                    .map(|p| format!("{} selected={}", p.remote_addr(), p.is_selected()))
                    .collect::<Vec<_>>()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // One long-lived echo stream; every probe is one byte round-tripped.
        let (mut send, mut recv) = conn.open_bi().await.anyerr()?;

        // Prove the stream echoes while the direct path is healthy.
        send.write_all(&[0xA5]).await.anyerr()?;
        let mut byte = [0u8; 1];
        tokio::time::timeout(Duration::from_secs(5), recv.read_exact(&mut byte))
            .await
            .std_context("echo did not work before the direct path went dark")?
            .anyerr()?;
        assert_eq!(byte, [0xA5]);

        // The selected direct path goes completely dark. The relay stays up.
        network.set_blackhole(true);
        let dark_at = Instant::now();

        // Probe: write a byte roughly every 500ms and wait for any echo.
        // Under the bug nothing comes back until noq abandons the dead path
        // (~15s). Track when data first flows again, or whether the
        // connection dies first.
        let mut first_echo_after_dark: Option<Duration> = None;
        let mut connection_error: Option<String> = None;
        while dark_at.elapsed() < PROBE_BUDGET {
            if let Err(err) = send.write_all(&[0x5A]).await {
                connection_error = Some(format!("write failed: {err:#}"));
                break;
            }
            match tokio::time::timeout(Duration::from_millis(500), recv.read_exact(&mut byte)).await
            {
                Ok(Ok(())) => {
                    first_echo_after_dark = Some(dark_at.elapsed());
                    break;
                }
                Ok(Err(err)) => {
                    connection_error = Some(format!("read failed: {err:#}"));
                    break;
                }
                Err(_) => continue, // still stalled, keep probing
            }
        }

        eprintln!(
            "dead-direct probe: first_echo_after_dark={first_echo_after_dark:?} \
             connection_error={connection_error:?} close_reason={:?} paths={:?}",
            conn.close_reason(),
            conn.paths()
                .iter()
                .map(|p| format!("{} selected={}", p.remote_addr(), p.is_selected()))
                .collect::<Vec<_>>()
        );

        assert_eq!(
            connection_error, None,
            "the connection errored while the selected direct path was dark"
        );
        assert_eq!(
            conn.close_reason(),
            None,
            "demoting the selected path must not close the QUIC connection"
        );
        let stall = first_echo_after_dark
            .expect("application traffic never recovered over the open relay path");
        assert!(
            stall < RECOVERY_DEADLINE,
            "relay recovery took {stall:?}, expected less than {RECOVERY_DEADLINE:?} \
             (the old path-idle behavior took ~15s)"
        );
        assert!(
            is_relay_selected(&conn),
            "the relay path should be selected after the dead direct path is demoted"
        );

        // The echo handler serves this one long-lived stream. Earlier one-byte
        // probes may already be queued, so read through them until the two new
        // sentinel bytes prove sustained traffic after recovery.
        send.write_all(&[0xB6, 0xC7]).await.anyerr()?;
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                recv.read_exact(&mut byte).await?;
                if byte == [0xB6] {
                    recv.read_exact(&mut byte).await?;
                    assert_eq!(byte, [0xC7]);
                    return std::result::Result::<(), noq::ReadExactError>::Ok(());
                }
                assert_eq!(byte, [0x5A]);
            }
        })
        .await
        .std_context("sustained echo did not work after relay recovery")?
        .anyerr()?;

        conn.close(0u32.into(), b"done");
        router.shutdown().await.anyerr()?;
        Ok(())
    }

    /// Regression test: keepalive PINGs and their PTO probe retransmissions
    /// must never count as stall evidence for the selected-path health
    /// detector.
    ///
    /// Field condition being modeled: an established connection sits idle (no
    /// application data pending) on a selected direct path when the radio
    /// drops for a few seconds — a WiFi roam or channel switch, well below
    /// `PATH_MAX_IDLE_TIMEOUT` (15s), which the idle timeout was deliberately
    /// sized to tolerate. The only traffic in that gap is the 5s keepalive
    /// PING (`HEARTBEAT_INTERVAL`) plus its PTO probe retransmissions. If the
    /// detector counts those raw datagrams as stall evidence, one lost
    /// keepalive and two probes reach the demotion threshold within the 1s
    /// stall floor, and the healthy direct path is demoted AND quarantined
    /// (5s doubling to 300s) with zero application data affected. Repeated
    /// transients then ratchet the quarantine and pin the user to the relay.
    #[tokio::test]
    #[traced_test]
    async fn test_selected_direct_path_idle_transient_loss_does_not_demote() -> Result<()> {
        /// Longer than one `HEARTBEAT_INTERVAL` (5s), so at least one
        /// keepalive PING is lost and PTO-probed inside the gap, while
        /// staying well below `PATH_MAX_IDLE_TIMEOUT` (15s), which must be
        /// the only mechanism allowed to abandon an idle path.
        const DARK_WINDOW: Duration = Duration::from_secs(8);

        let (relay_map, _relay_url, _guard) = run_relay_server().await?;
        let network = TestNetwork::new();
        let s1 = SecretKey::generate();
        let s2 = SecretKey::generate();

        let t1 = network.create_transport(s1.public())?;
        let t2 = network.create_transport(s2.public())?;

        // Same topology as the dead-path demotion test: the custom transport
        // is the only primary-tier ("direct") path, the relay the only
        // backup-tier path. The relay's presence is what makes a wrong
        // demotion possible at all (`has_alternative`).
        let config = EndpointConfig::default().with_relay(relay_map.clone());
        let ep1 = endpoint_builder(s1, t1, config.clone()).bind().await?;
        let ep2 = endpoint_builder(s2.clone(), t2, config).bind().await?;

        ep1.online().await;
        ep2.online().await;

        let router = Router::builder(ep2.clone()).accept(ECHO_ALPN, Echo).spawn();

        let ep2_addr = ep2.addr();
        let all_addrs = EndpointAddr::from_parts(
            s2.public(),
            ep2_addr
                .addrs
                .iter()
                .cloned()
                .chain(std::iter::once(TransportAddr::Custom(to_custom_addr(
                    s2.public(),
                )))),
        );
        let conn = ep1.connect(all_addrs, ECHO_ALPN).await?;

        // Wait for the steady state: direct (custom) selected, relay open.
        let settle_deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let paths = conn.paths();
            let has_relay = paths.iter().any(|p| p.is_relay());
            if has_relay && is_custom_selected(&conn) {
                break;
            }
            assert!(
                Instant::now() < settle_deadline,
                "test setup failed: custom-selected + relay path never settled; paths: {:?}",
                paths
                    .iter()
                    .map(|p| format!("{} selected={}", p.remote_addr(), p.is_selected()))
                    .collect::<Vec<_>>()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // One long-lived echo stream (the Echo handler serves exactly one).
        let (mut send, mut recv) = conn.open_bi().await.anyerr()?;
        let mut byte = [0u8; 1];

        // Prove the stream echoes while the direct path is healthy.
        send.write_all(&[0xA5]).await.anyerr()?;
        tokio::time::timeout(Duration::from_secs(5), recv.read_exact(&mut byte))
            .await
            .std_context("echo did not work before the transient loss")?
            .anyerr()?;
        assert_eq!(byte, [0xA5]);

        // Let the echo's trailing retransmits/ACKs drain so the connection is
        // genuinely idle: no application data pending anywhere.
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Transient radio gap: every packet on the direct transport is lost,
        // while the connection stays idle. Only keepalives and PTO probes are
        // transmitted during this window.
        network.set_blackhole(true);
        let dark_at = Instant::now();
        while dark_at.elapsed() < DARK_WINDOW {
            assert_eq!(
                conn.close_reason(),
                None,
                "the connection must survive an idle transient loss"
            );
            assert!(
                is_custom_selected(&conn),
                "idle transient loss demoted the selected direct path after {:?} \
                 (only keepalive/PTO traffic was in flight); paths: {:?}",
                dark_at.elapsed(),
                conn.paths()
                    .iter()
                    .map(|p| format!("{} selected={}", p.remote_addr(), p.is_selected()))
                    .collect::<Vec<_>>()
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        network.set_blackhole(false);

        // Give the next keepalive/PTO probe a moment to round-trip now that
        // the transient cleared.
        tokio::time::sleep(Duration::from_millis(500)).await;

        // The path was never demoted, so it must still be selected (a
        // demotion would have quarantined the direct remote for >= 5s,
        // pinning selection to the relay well past this point).
        assert!(
            is_custom_selected(&conn),
            "the direct path must still be selected after the transient cleared; paths: {:?}",
            conn.paths()
                .iter()
                .map(|p| format!("{} selected={}", p.remote_addr(), p.is_selected()))
                .collect::<Vec<_>>()
        );

        // And it must still carry application data on the same stream.
        send.write_all(&[0x42]).await.anyerr()?;
        tokio::time::timeout(Duration::from_secs(5), recv.read_exact(&mut byte))
            .await
            .std_context("echo did not work after the transient loss cleared")?
            .anyerr()?;
        assert_eq!(byte, [0x42]);
        assert!(
            is_custom_selected(&conn),
            "application traffic after the transient must still ride the direct path"
        );

        conn.close(0u32.into(), b"done");
        router.shutdown().await.anyerr()?;
        Ok(())
    }
}
