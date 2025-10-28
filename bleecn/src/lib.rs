use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use pnet::packet::icmp::time_exceeded::TimeExceededPacket;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::{MutableUdpPacket, UdpPacket};
use pnet::packet::Packet;
use pnet::transport::transport_channel;
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::{Ipv4, Ipv6};
use pnet::transport::{
    icmp_packet_iter, icmpv6_packet_iter, Ecn, IcmpTransportChannelIterator,
    Icmpv6TransportChannelIterator,
};
use serde::Serialize;
use slog::{error, info};

#[derive(Debug, Clone)]
pub enum Target {
    Ipv6(Ipv6Addr),
    Ipv4(Ipv4Addr),
}

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct Hop {
    pub index: u8,
    pub address: IpAddr,
    pub detected_bleeching: bool,
}

impl Hop {
    fn new(index: u8, addr: IpAddr, bleeching: bool) -> Self {
        Self {
            index,
            address: addr,
            detected_bleeching: bleeching,
        }
    }
    fn merge(&mut self, other: &Hop) -> bool {
        self.detected_bleeching |= other.detected_bleeching;
        self.address == other.address
    }
}

#[derive(Clone, PartialEq)]
pub struct Probe {
    pub id: u8,
    pub ttl: u8,
    pub ecn: Ecn,
}

pub enum ProbeSetError {
    ProbeExists,
    ProbeDoesNotExist,
}

impl fmt::Display for ProbeSetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProbeSetError::ProbeExists => write!(f, "Probe exists"),
            ProbeSetError::ProbeDoesNotExist => write!(f, "Probe does not exist"),
        }
    }
}

pub struct ProbeSet {
    probes: HashMap<u8, Probe>,
}

impl ProbeSet {
    pub fn new() -> Self {
        Self {
            probes: HashMap::new(),
        }
    }

    pub fn count(&self) -> usize {
        self.probes.len()
    }

    pub fn ack(&mut self, probe: &Probe) -> Result<(), ProbeSetError> {
        if self.probes.remove(&probe.id).is_some() {
            Ok(())
        } else {
            Err(ProbeSetError::ProbeDoesNotExist)
        }
    }

    pub fn insert(&mut self, probe: &Probe) -> Result<(), ProbeSetError> {
        if let Entry::Vacant(_) = self.probes.entry(probe.id) {
            self.probes.insert(probe.id, probe.clone());
            Ok(())
        } else {
            Err(ProbeSetError::ProbeExists)
        }
    }

    pub fn get(&self, id: u8) -> Option<Probe> {
        self.probes.get(&id).cloned()
    }
}

#[derive(Debug, Clone)]
enum Mode {
    Ipv6,
    Ipv4,
}

#[derive(Serialize)]
pub struct TestResult {
    pub target: IpAddr,
    #[serde(flatten)]
    pub path: Path,
    pub bleeched_hop: Option<Hop>,
}

fn ecn_to_string(ecn: Ecn) -> String {
    match ecn {
        Ecn::CE => "Congestion experienced".to_string(),
        Ecn::Ect0 => "ECT(0)".to_string(),
        Ecn::Ect1 => "ECT(1)".to_string(),
        Ecn::NotEct => "ECT disabled".to_string(),
    }
}

#[derive(Serialize)]
pub struct Path {
    path: HashMap<u8, Hop>,
}

impl Path {
    fn new() -> Self {
        Path {
            path: HashMap::new(),
        }
    }

    /// Update a hop in a path
    ///
    /// If a hop at hop_no does not exist, add it. If a hop at hop_no
    /// does exist, update it's bleaching status.
    ///
    /// Return true if either a new hop is inserted or the existing
    /// hop's address matches the new hop's address. Return false
    /// otherwise.
    fn update_hop(&mut self, hop_no: u8, hop: &Hop) -> bool {
        match self.path.get_mut(&hop_no) {
            Some(existing_hop) => {
                existing_hop.detected_bleeching |= hop.detected_bleeching;
                existing_hop.address != hop.address
            }
            None => {
                self.path.insert(hop_no, hop.clone());
                false
            }
        }
    }

    fn bleeched_hop(&self) -> Option<Hop> {
        let mut hops: Vec<&u8> = self.path.keys().collect();
        let mut prev_hop: Option<Hop> = None;
        hops.sort();
        for hop_no in hops {
            if self.path.get(hop_no).unwrap().detected_bleeching {
                if let Some(prev_hop) = prev_hop {
                    return Some(prev_hop);
                } else {
                    return Some(Hop {
                        index: 0u8,
                        address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                        detected_bleeching: true,
                    });
                }
            }
            prev_hop = Some(self.path.get(hop_no).unwrap().clone());
        }
        None
    }
}

impl fmt::Display for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let default_hop = Hop {
            index: 0,
            address: IpAddr::V4(Ipv4Addr::BROADCAST),
            detected_bleeching: false,
        };
        let mut hops: Vec<&u8> = self.path.keys().collect();
        hops.sort();
        for hop in hops {
            writeln!(
                f,
                "{}: {:?}",
                hop,
                self.path.get(hop).unwrap_or(&default_hop.clone())
            )?;
        }
        Ok(())
    }
}

enum VersionedIcmpPacket<'a> {
    Ipv4(IcmpPacket<'a>),
    #[allow(dead_code)]
    Ipv6(Icmpv6Packet<'a>),
}

enum IcmpIterable<'a> {
    Ipv4(IcmpTransportChannelIterator<'a>),
    Ipv6(Icmpv6TransportChannelIterator<'a>),
}

impl<'a> IcmpIterable<'a> {
    fn next_with_timeout(&mut self, d: Duration) -> Option<(VersionedIcmpPacket, IpAddr)> {
        match self {
            IcmpIterable::Ipv4(iterable) => {
                if let Ok(Some((pkt, addr))) = iterable.next_with_timeout(d) {
                    Some((VersionedIcmpPacket::Ipv4(pkt), addr))
                } else {
                    None
                }
            }
            IcmpIterable::Ipv6(iterable) => {
                if let Ok(Some((pkt, addr))) = iterable.next_with_timeout(d) {
                    Some((VersionedIcmpPacket::Ipv6(pkt), addr))
                } else {
                    None
                }
            }
        }
    }
}

pub fn bleecn(
    target: Target,
    probes_per_hop: u32,
    go: Option<u8>,
    hop_timeouts: u32,
    permissive: bool,
    log: &slog::Logger,
) -> Result<TestResult, Box<dyn std::error::Error>> {
    //let mut path: HashMap<u8, Hop> = HashMap::new();
    let mut path = Path::new();

    let gomode = if go.is_some() {
        info!(log, "Enabling go mode.");
        true
    } else {
        false
    };

    let (target, mode) = match target {
        Target::Ipv4(addr) => (IpAddr::V4(addr), Mode::Ipv4),
        Target::Ipv6(addr) => (IpAddr::V6(addr), Mode::Ipv6),
    };

    let protocol = match mode {
        Mode::Ipv4 => {
            info!(log, "Matching mode v4 to set protocol!");
            Layer4(Ipv4(IpNextHeaderProtocols::Udp))
        }
        Mode::Ipv6 => {
            info!(log, "Matching mode v6 to set protocol!");
            Layer4(Ipv6(IpNextHeaderProtocols::Udp))
        }
    };
    let icmp_protocol = match mode {
        Mode::Ipv4 => {
            info!(log, "Matching mode v4 to set ICMP protocol!");
            Layer4(Ipv4(IpNextHeaderProtocols::Icmp))
        }
        Mode::Ipv6 => {
            info!(log, "Matching mode v6 to set ICMP protocol!");
            Layer4(Ipv6(IpNextHeaderProtocols::Icmpv6))
        }
    };

    let (_, mut icmp_rx) = match transport_channel(4096, icmp_protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => {
            error!(
                log,
                "An error occurred when creating the icmp transport channel: {}", e
            );
            return Err(e.into());
        }
    };

    let (mut tx, _) = match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => {
            error!(
                log,
                "An error occurred when creating the transport channel: {}", e
            );
            return Err(e.into());
        }
    };

    let mut ttl: u8 = 1;
    let mut probe_count: u8 = 1;

    let mut icmp_rx_iter = match mode {
        Mode::Ipv4 => IcmpIterable::Ipv4(icmp_packet_iter(&mut icmp_rx)),
        Mode::Ipv6 => IcmpIterable::Ipv6(icmpv6_packet_iter(&mut icmp_rx)),
    };

    let mut path_divergence_detected = false;
    let mut encapsulation_error = false;

    let baseline_dest_port = 33434u16;
    let baseline_src_port = 54321u16;
/*
    if let Err(err) = tx.configure_path_mtu_discovery(false) {
        error!(
            log,
            "An error occurred while disabling path MTU discovery on the transport channel: {}",
            err
        );
        return Err(err.into());
    }
*/
    loop {
        // Probe another hop.

        let mut outstanding_probes = ProbeSet::new();

        let mut consecutive_hop_timeouts = 0u32;
        let mut hop_unreachable = false;

        let mut new_hop: Option<Hop> = None;
        for attempt_no in 0..probes_per_hop {
            let probe = Probe {
                id: probe_count,
                ttl,
                ecn: if rand::random() { Ecn::Ect1 } else { Ecn::Ect0 },
            };

            probe_count += 1;

            // htons (and the opposite direction) are automatically handled by libpnet.
            let encoded_destination_port: u16 = baseline_dest_port + probe.id as u16;
            let encoded_source_port: u16 = baseline_src_port + probe.id as u16;

            let mut probe_packet_data = [0; UdpPacket::minimum_packet_size() + 32];

            let mut maybe_packet = MutableUdpPacket::new(&mut probe_packet_data).unwrap();

            let udp = pnet::packet::udp::Udp {
                source: encoded_source_port,
                destination: encoded_destination_port,
                length: (UdpPacket::minimum_packet_size() + 32) as u16,
                checksum: 0,
                payload: [0xff as u8; 32].to_vec(),
            };

            maybe_packet.populate(&udp);

            if let Err(err) = tx.set_ecn(probe.ecn) {
                println!(
                    "Failed to set the ECN bit for the sender (Error: {:?}). Will retry later!",
                    err
                );
                continue;
            }
            if let Err(err) = tx.set_ttl(ttl) {
                println!(
                    "Failed to set the TTL for the sender (Error: {:?}). Will retry later!",
                    err
                );
                continue;
            }
            if let Err(err) = tx.send_to(maybe_packet, target) {
                println!(
                    "Failed to send the packet (Error: {:?}). Will retry later!",
                    err
                );
                continue;
            }

            if let Err(e) = outstanding_probes.insert(&probe) {
                eprintln!(
                    "Error: Could not add a probe to the outstanding probe set: {}",
                    e
                );
            }

            info!(log, "Sent out the {}th probe for TTL {}.", attempt_no, ttl);

            info!(
                log,
                "There are {} outstanding probes for this TTL.",
                outstanding_probes.count()
            );
            info!(
                log,
                "There are {} consecutive hop timeouts.", consecutive_hop_timeouts
            );

            loop {
                // (Re)read as long as there are not a maximum number of timeouts and there are outstanding probes.

                let read_result = icmp_rx_iter.next_with_timeout(Duration::from_secs(2));

                if let Some((rcvd_icmp_packet, rcvd_icmp_addr)) = read_result {
                    match rcvd_icmp_packet {
                        VersionedIcmpPacket::Ipv4(pkt) => {
                            if let Some(timeout_pkt) = TimeExceededPacket::new(pkt.packet()) {
                                if let Some(inner_pkt) = Ipv4Packet::new(timeout_pkt.payload()) {
                                    if let Some(udp_packet) = UdpPacket::new(inner_pkt.payload()) {
                                        if target != inner_pkt.get_destination() {
                                            error!(log, "Packet response with address that does not match our target.");
                                            continue;
                                        }

                                        let rcvd_probe_id: u8 = (udp_packet.get_destination()
                                            - baseline_dest_port)
                                            as u8;

                                        let rcvd_probe = outstanding_probes.get(rcvd_probe_id);
                                        if rcvd_probe.is_none() {
                                            error!(log, "Could not retrieve the outstanding probe matching id {}.", rcvd_probe_id);
                                            continue;
                                        }
                                        let rcvd_probe = rcvd_probe.unwrap();

                                        if let Err(e) = outstanding_probes.ack(&rcvd_probe) {
                                            error!(log, "Could not acknowledge the outstanding probe matching id {}: {}.", rcvd_probe_id, e);
                                            continue;
                                        }

                                        // We have a valid response; reset per-hop read timeouts.
                                        consecutive_hop_timeouts = 0;

                                        // Get the data from inside the packet that is reflected back.
                                        let actual_ecn = Ecn::from(inner_pkt.get_ecn());
                                        let actual_protocol = inner_pkt.get_next_level_protocol();
                                        let actual_ttl = inner_pkt.get_ttl();

                                        // Am I bleeched?
                                        let ecn_bleeching_detected = rcvd_probe.ecn != actual_ecn;

                                        info!(log, "Got a packet back from {:?}", rcvd_icmp_addr);
                                        info!(
                                            log,
                                            "ICMP code: {:?}; type: {:?}",
                                            pkt.get_icmp_code(),
                                            pkt.get_icmp_type()
                                        );
                                        info!(log, "Probe count: {:?}", probe_count);

                                        info!(log, "ECN:");
                                        info!(log, "{: >15} {: >15}", "Expected:", "Actual:");
                                        info!(
                                            log,
                                            "{: >15} {: >15}",
                                            ecn_to_string(rcvd_probe.ecn),
                                            ecn_to_string(actual_ecn)
                                        );
                                        info!(
                                            log,
                                            "Detected bleeching? {:?}", ecn_bleeching_detected
                                        );

                                        info!(log, "TTL:");
                                        info!(log, "{: >10} {: >10}", "Expected:", "Actual:");
                                        info!(
                                            log,
                                            "{: >10} {: >10} (should always be 1)",
                                            rcvd_probe.ttl,
                                            actual_ttl
                                        );

                                        info!(log, "Protocol:");
                                        info!(log, "{: >10} {: >10}", "Expected:", "Actual:");
                                        info!(
                                            log,
                                            "{: >10} {: >10}",
                                            IpNextHeaderProtocols::Udp.to_string(),
                                            actual_protocol.to_string()
                                        );

                                        let discovered_hop = Hop::new(
                                            rcvd_probe.ttl,
                                            rcvd_icmp_addr,
                                            ecn_bleeching_detected,
                                        );

                                        if let Some(existing_new_hop) = &mut new_hop {
                                            if !existing_new_hop.merge(&discovered_hop) {
                                                info!(
                                                    log,
                                                    "{:?} at hop number {} caused path divergence.",
                                                    new_hop,
                                                    ttl
                                                );
                                                path_divergence_detected = true;
                                            }
                                        } else {
                                            new_hop = Some(discovered_hop);
                                        }

                                        info!(
                                            log,
                                            "The hop being discovered currently looks like: {:?}",
                                            new_hop.clone().unwrap()
                                        );
                                    } else {
                                        error!(log, "Error: Timeout packet's embedded IP packet did not contain a UDP packet.");
                                        encapsulation_error = true;
                                    }
                                } else {
                                    error!(log, "Error: Timeout packet contents did not contain an IP packet.");
                                    encapsulation_error = true;
                                }
                            } else {
                                error!(log, "Error: Received packet did not parse as an ICMP Timeout packet.");
                                encapsulation_error = true;
                            }
                        }
                        VersionedIcmpPacket::Ipv6(_) => {
                            #[allow(clippy::assertions_on_constants)]
                            {
                                assert!(false, "Unimplemented.")
                            }
                        }
                    };
                } else {
                    consecutive_hop_timeouts += 1;
                    info!(log, "Had a timeout.")
                }

                // All warnings handled when detected.
                if encapsulation_error || path_divergence_detected {
                    break;
                }

                // If there are no outstanding probes, then there's no reason to do another read!
                if outstanding_probes.count() == 0 {
                    info!(
                        log,
                        "Outstanding probes are 0 -- no need to do another read!"
                    );
                    break;
                }

                // There are outstanding probes.
                assert!(outstanding_probes.count() != 0);

                // Now that it is safe to assume that there are outstanding probes, it is necessary
                // to handle three possible situations:
                // 0. Are we out of timeouts? If so, fold.
                if consecutive_hop_timeouts >= hop_timeouts {
                    info!(
                        log,
                        "Reached consecutive timeout limit ... declaring that this hop is offline."
                    );
                    break;
                }

                // 1. We still have some probes left to send. So, break out of the reading loop
                //    and send another probe.
                if attempt_no + 1 < probes_per_hop {
                    info!(
                        log,
                        "Had a timeout, but there are probes left to send. So, we send 'em."
                    );
                    break;
                }
                // 2. We have no probes left to send. Combined with earlier knowledge (i.e., that
                //    there are outstanding probes left to read and there are more timeouts available),
                //    continue the read loop and try to read another packet.
                continue;
            } // Reading probe responses loop.

            if consecutive_hop_timeouts >= hop_timeouts {
                info!(log, "Reached consecutive timeout limit ... declaring (again) that this hop is offline.");
                hop_unreachable = true;
            }

            // For some reason, we are done reading responses ...
            // ... if that reason is that there was a path divergence, then we are done.
            // ... if that reason is that there was a encapsulation error, then we are done.
            // ... if that reason is that we ran out of timeouts, then we declare that this
            //     hop is offline.
            if path_divergence_detected || encapsulation_error || hop_unreachable {
                break;
            }
        } // Sending probes to new hops loop.

        if hop_unreachable {
            if gomode {
                if ttl >= go.unwrap() {
                    info!(log, "Ending path tracing because a hop was unreachable and the number of hops is over the go parameter.");
                    break;
                } else {
                    info!(
                        log,
                        "Warning: A hop is unreachable, but go mode is enabled -- overriding."
                    )
                }
            } else {
                info!(log, "Ending path tracing because hop is unreachable.");
                break;
            }
        }

        if path_divergence_detected {
            if !permissive {
                info!(log, "Ending path tracing because divergence is detected.");
                break;
            }
            info!(
                log,
                "Warning: Path divergence detected but permissive mode is enabled -- overriding."
            );
            path_divergence_detected = false;
        }

        if encapsulation_error {
            info!(
                log,
                "Ending path tracing because of an encapsulation error."
            );
            break;
        }

        // If we are in go mode, we could get here and have an unreachable hop. Because *some* probe
        // packet could have come back, we need to explicitly opt out of this path insertion!
        if !hop_unreachable {
            // We know that new_hop can be added to the path.
            if let Some(new_hop) = new_hop {
                path.update_hop(ttl, &new_hop);
                if new_hop.address == target {
                    info!(log, "Target reached!");
                    break;
                }
            } else {
                error!(
                    log,
                    "Error: The {}th hop was alive but no hop information was collected.", ttl
                );
            }
        }

        if probe_count == u8::MAX {
            info!(log, "Max probes reached ... quitting.");
            break;
        }
        if ttl == u8::MAX {
            info!(log, "Max TTL reached ... quitting.");
            break;
        }

        ttl += 1;

        info!(log, "Moving to the {}th hop\n", ttl);
    }
    let bleeched_hop = path.bleeched_hop();
    Ok(TestResult {
        target,
        path,
        bleeched_hop,
    })
}
