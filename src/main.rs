extern crate pnet;

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

use clap::Parser;
use pnet::packet::icmp::time_exceeded::TimeExceededPacket;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::ip::IpNextHeaderProtocols::{self, Udp};
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
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Debug, Clone)]
enum Target {
    Ipv6(Ipv6Addr),
    Ipv4(Ipv4Addr),
    Name(String),
}

#[derive(Serialize, Debug, Clone, PartialEq)]
struct Hop {
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

#[derive(Clone)]
struct EcnWrapper {
    pub ecn: Ecn,
}

impl Serialize for EcnWrapper {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let actual_value = self.ecn as u8;
        serializer.serialize_u8(actual_value)
    }
}

impl<'de> Deserialize<'de> for EcnWrapper {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = u8::deserialize(deserializer)?;
        let ecn = Ecn::from(raw);
        Ok(EcnWrapper { ecn })
    }
}

#[derive(Debug, Clone)]
enum Mode {
    Ipv6,
    Ipv4,
}

#[derive(Serialize)]
struct TestResult {
    #[serde(flatten)]
    pub path: Path,
    pub bleeched_hop: Option<Hop>,
}

fn parse_target(arg: &str) -> Result<Target, String> {
    match arg.parse() {
        Ok(addr) => match addr {
            IpAddr::V4(addr) => Ok(Target::Ipv4(addr)),
            IpAddr::V6(addr) => Ok(Target::Ipv6(addr)),
        },
        Err(_) => Ok(Target::Name(arg.to_string())),
    }
}

fn ecn_to_string(ecn: Ecn) -> String {
    match ecn {
        Ecn::CE => "Congestion experienced".to_string(),
        Ecn::Ect0 => "ECT(0)".to_string(),
        Ecn::Ect1 => "ECT(1)".to_string(),
        Ecn::NotEct => "ECT disabled".to_string(),
    }
}

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Where to send IP packets.
    #[arg(short, value_parser = parse_target)]
    target: Target,

    #[arg(short, long, action = clap::ArgAction::Count)]
    debug: u8,

    /// Print the discovered path.
    #[arg(short, long, default_value_t = false)]
    path: bool,

    /// Maximum number of consecutive timeouts before considering a hop unreachable.
    #[arg(long, default_value_t = 3)]
    hop_timeouts: u32,

    /// Number of probes sent per hop to determine bleaching status.
    #[arg(long, default_value_t = 3)]
    probe_count: u32,
}

#[derive(Serialize)]
struct Path {
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
            write!(
                f,
                "{}: {:?}\n",
                hop,
                self.path.get(&hop).unwrap_or(&default_hop.clone())
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

fn main() {
    let args = Args::parse();

    //let mut path: HashMap<u8, Hop> = HashMap::new();
    let mut path = Path::new();

    let (target, mode) = match args.target.clone() {
        Target::Name(name) => {
            let hostname_with_dummy_port = name.clone() + ":80";

            let server_ips = hostname_with_dummy_port.to_socket_addrs();

            if let Err(resolution_error) = server_ips {
                println!("Error resolving target: {:?}", resolution_error);
                return;
            }

            let mut sv: Vec<SocketAddr> = vec![];
            server_ips.unwrap().for_each(|f| sv.push(f));

            let resolution_result_count = sv.len();
            let server_ip = sv[0];
            if resolution_result_count > 1 {
                println!(
                    "Warning: There were multiple IP addresses resolved from {:?}; using {:?}",
                    name.clone(),
                    server_ip.ip()
                );
            }
            match server_ip.ip() {
                IpAddr::V4(addr) => (IpAddr::V4(addr), Mode::Ipv4),
                IpAddr::V6(addr) => (IpAddr::V6(addr), Mode::Ipv6),
            }
        }
        Target::Ipv4(addr) => (IpAddr::V4(addr), Mode::Ipv4),
        Target::Ipv6(addr) => (IpAddr::V6(addr), Mode::Ipv6),
    };

    let protocol = match mode {
        Mode::Ipv4 => {
            if args.debug > 1 {
                println!("Matching mode v4 to set protocol!");
            }
            Layer4(Ipv4(IpNextHeaderProtocols::Udp))
        }
        Mode::Ipv6 => {
            if args.debug > 1 {
                println!("Matching mode v6 to set protocol!");
            }
            Layer4(Ipv6(IpNextHeaderProtocols::Udp))
        }
    };
    let icmp_protocol = match mode {
        Mode::Ipv4 => {
            if args.debug > 1 {
                println!("Matching mode v4 to set ICMP protocol!");
            }
            Layer4(Ipv4(IpNextHeaderProtocols::Icmp))
        }
        Mode::Ipv6 => {
            if args.debug > 1 {
                println!("Matching mode v6 to set ICMP protocol!");
            }
            Layer4(Ipv6(IpNextHeaderProtocols::Icmpv6))
        }
    };

    let (_, mut icmp_rx) = match transport_channel(4096, icmp_protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => {
            println!(
                "An error occurred when creating the icmp transport channel: {}",
                e
            );
            return;
        }
    };

    let (mut tx, _) = match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => {
            println!(
                "An error occurred when creating the transport channel: {}",
                e
            );
            return;
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

    loop {
        // Probe another hop.

        let mut hop_outstanding_probes = 0u32;
        let mut consecutive_hop_timeouts = 0u32;
        let mut hop_unreachable = false;

        let mut new_hop: Option<Hop> = None;
        // Send out args.probe_count packets per TTL.
        for attempt_no in 0..args.probe_count {
            let probed_ecn = if rand::random() { Ecn::Ect1 } else { Ecn::Ect0 };

            let encoded_destination_port: u16 = ((ttl as u16) << 8) | probed_ecn as u16;

            let mut probe_packet_data = [0; UdpPacket::minimum_packet_size()];

            let mut maybe_packet = MutableUdpPacket::new(&mut probe_packet_data).unwrap();

            let udp = pnet::packet::udp::Udp {
                source: 54321,
                destination: encoded_destination_port,
                length: UdpPacket::minimum_packet_size() as u16,
                checksum: 0,
                payload: [].to_vec(),
            };
            maybe_packet.populate(&udp);

            if let Err(err) = tx.set_ecn(probed_ecn) {
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

            hop_outstanding_probes += 1;

            println!("Sent out the {}th probe for TTL {}.", attempt_no, ttl);

            if args.debug > 1 {
                println!(
                    "There are {} outstanding probes for this TTL.",
                    hop_outstanding_probes
                );
                println!(
                    "There are {} consecutive hop timeouts.",
                    consecutive_hop_timeouts
                );
            }

            loop {
                // (Re)read as long as there are not a maximum number of timeouts and there are outstanding probes.

                let read_result = icmp_rx_iter.next_with_timeout(Duration::from_secs(2));

                if let Some((rcvd_icmp_packet, rcvd_icmp_addr)) = read_result {
                    match rcvd_icmp_packet {
                        VersionedIcmpPacket::Ipv4(pkt) => {
                            if let Some(timeout_pkt) = TimeExceededPacket::new(pkt.packet()) {
                                if let Some(inner_pkt) = Ipv4Packet::new(timeout_pkt.payload()) {
                                    if let Some(udp_packet) = UdpPacket::new(inner_pkt.payload()) {
                                        // Get the data from inside the packet that is reflected back.
                                        let expected_ttl: u8 =
                                            (udp_packet.get_destination() >> 8) as u8;
                                        let expected_ecn_raw: u8 =
                                            (udp_packet.get_destination() & 0xff) as u8;
                                        let expected_ecn: Ecn = Ecn::from(expected_ecn_raw);

                                        // Get the data about the packet that is reflected back.
                                        let actual_ecn = Ecn::from(inner_pkt.get_ecn());
                                        let actual_protocol = inner_pkt.get_next_level_protocol();
                                        let actual_ttl = inner_pkt.get_ttl();

                                        // Am I bleeched?
                                        let ecn_bleeching_detected = expected_ecn != actual_ecn;

                                        // It's possible that we received a non-test packet back. Let's reject it.
                                        if actual_protocol != Udp {
                                            if args.debug > 1 {
                                                println!("Discarding a non test packet.")
                                            }
                                            continue;
                                        }

                                        consecutive_hop_timeouts = 0;
                                        hop_outstanding_probes -= 1;

                                        if args.debug > 1 {
                                            println!("Got a packet back from {:?}", rcvd_icmp_addr);
                                        }
                                        if args.debug > 1 {
                                            println!("ICMP code: {:?}", pkt.get_icmp_code());
                                            println!("ICMP type: {:?}", pkt.get_icmp_type());
                                        }

                                        if args.debug > 1 {
                                            println!("Probe count: {:?}", probe_count);

                                            println!("ECN:");
                                            println!("{: >15} {: >15}", "Expected:", "Actual:");
                                            println!(
                                                "{: >15} {: >15}",
                                                ecn_to_string(expected_ecn),
                                                ecn_to_string(actual_ecn)
                                            );
                                            println!(
                                                "Detected bleeching? {:?}",
                                                ecn_bleeching_detected
                                            );

                                            println!("TTL:");
                                            println!("{: >10} {: >10}", "Expected:", "Actual:");
                                            println!(
                                                "{: >10} {: >10} (should always be 1)",
                                                expected_ttl, actual_ttl
                                            );

                                            println!("Protocol:");
                                            println!("{: >10} {: >10}", "Expected:", "Actual:");
                                            println!(
                                                "{: >10} {: >10}",
                                                IpNextHeaderProtocols::Udp.to_string(),
                                                actual_protocol.to_string()
                                            );
                                        }

                                        let discovered_hop = Hop::new(
                                            expected_ttl,
                                            rcvd_icmp_addr,
                                            ecn_bleeching_detected,
                                        );

                                        if let Some(existing_new_hop) = &mut new_hop {
                                            if !existing_new_hop.merge(&discovered_hop) {
                                                if args.debug > 1 {
                                                    println!(
                                                    "{:?} at hop number {} caused path divergence.",
                                                    new_hop, ttl
                                                );
                                                }
                                                path_divergence_detected = true;
                                            }
                                        } else {
                                            new_hop = Some(discovered_hop);
                                        }

                                        if args.debug > 1 {
                                            println!(
                                            "The hop being discovered currently looks like: {:?}",
                                            new_hop.clone().unwrap()
                                        );
                                        }
                                    } else {
                                        eprintln!("Error: Timeout packet's embedded IP packet did not contain a UDP packet.");
                                        encapsulation_error = true;
                                    }
                                } else {
                                    eprintln!("Error: Timeout packet contents did not contain an IP packet.");
                                    encapsulation_error = true;
                                }
                            } else {
                                eprintln!("Error: Received packet did not parse as an ICMP Timeout packet.");
                                encapsulation_error = true;
                            }
                        }
                        VersionedIcmpPacket::Ipv6(_) => {
                            assert!(false, "Unimplemented.")
                        }
                    };
                } else {
                    consecutive_hop_timeouts += 1;
                    if args.debug > 1 {
                        println!("Had a timeout.")
                    }
                }

                if encapsulation_error {
                    break;
                }

                // Information from the packet that was just read indicated that the traced
                // path exhibited divergence.
                if path_divergence_detected {
                    break;
                }

                // If there are no outstanding probes, then there's no reason to do another read!
                if hop_outstanding_probes == 0 {
                    if args.debug > 1 {
                        println!("Outstanding probes are 0 -- no need to do another read!")
                    }
                    break;
                }

                // There are outstanding probes.
                assert!(hop_outstanding_probes != 0);

                // Now that it is safe to assume that there are outstanding probes, it is necessary
                // to handle three possible situations:
                // 0. Are we out of timeouts? If so, fold.
                if consecutive_hop_timeouts >= args.hop_timeouts {
                    if args.debug > 0 {
                        println!(
                        "Reached consecutive timeout limit ... declaring that this hop is offline."
                    );
                    }
                    break;
                }

                // 1. We still have some probes left to send. So, break out of the reading loop
                //    and send another probe.
                if attempt_no + 1 < args.probe_count {
                    if args.debug > 0 {
                        println!(
                            "Had a timeout, but there are probes left to send. So, we send 'em."
                        );
                    }
                    break;
                }
                // 2. We have no probes left to send. Combined with earlier knowledge (i.e., that
                //    there are outstanding probes left to read and there are more timeouts available),
                //    continue the read loop and try to read another packet.
                continue;
            } // Reading probe responses loop.

            // For some reasone, we are done reading responses ...

            // ... if that reason is that we ran out of timeouts, then we declare that this
            //     hop is offline.
            if consecutive_hop_timeouts >= args.hop_timeouts {
                if args.debug > 0 {
                    println!("Reached consecutive timeout limit ... declaring (again) that this hop is offline.");
                }
                hop_unreachable = true;
                break;
            }

            // ... if that reason is that there was a path divergence, then we are done.
            if path_divergence_detected {
                break;
            }

            // ... if that reason is that there was a encapsulation error, then we are done.
            if encapsulation_error {
                break;
            }
        } // Sending probes to new hops loop.

        if hop_unreachable || path_divergence_detected || encapsulation_error {
            println!("Ending path tracing because hop is unreachable, divergence detected or an encapsulation error.");
            break;
        }

        // We know that new_hop can be added to the path.
        if let Some(new_hop) = new_hop {
            path.update_hop(ttl, &new_hop);
        } else {
            eprintln!(
                "Error: The {}th hop was alive but no hop information was collected.",
                ttl
            );
        }

        if probe_count == u8::MAX {
            println!("Max probes reached ... quitting.");
            break;
        }
        if ttl == u8::MAX {
            println!("Max TTL reached ... quitting.");
            break;
        }

        ttl += 1;
        probe_count += 1;

        if args.debug > 1 {
            println!("Moving to the {}th hop\n", ttl);
        }
    }

    let bleeched_hop = path.bleeched_hop();

    if args.debug > 1 || args.path {
        println!("path: {}", path);
    }
    if let Some(bleeched_hop) = bleeched_hop.clone() {
        println!("bleeching hop: {:?}", bleeched_hop);
    } else {
        println!("No ECN bleeching detected.");
    }

    let result = TestResult { path, bleeched_hop };

    let json_test_result = serde_json::to_string(&result).unwrap();
    println!("result: {}", json_test_result)
}
