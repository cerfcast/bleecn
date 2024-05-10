extern crate pnet;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::thread;
use std::time::Duration;

use clap::{CommandFactory, Parser};
use pnet::packet::icmp::time_exceeded::TimeExceededPacket;
use pnet::packet::icmp::{Icmp, IcmpPacket};
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::{ethernet, FromPacket, MutablePacket, Packet, PacketData};
use pnet::transport::TransportChannelType::{Layer3, Layer4};
use pnet::transport::TransportProtocol::{Ipv4, Ipv6};
use pnet::transport::{
    icmp_packet_iter, icmpv6_packet_iter, Ecn, IcmpTransportChannelIterator,
    Icmpv6TransportChannelIterator,
};
use pnet::transport::{ipv4_packet_iter, transport_channel};
use pnet::util::MacAddr;

#[derive(Debug, Clone)]
enum Target {
    Ipv6(Ipv6Addr),
    Ipv4(Ipv4Addr),
    Name(String),
}

#[derive(Debug, Clone)]
enum Mode {
    Ipv6,
    Ipv4,
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

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Where to send IP packets.
    #[arg(short, value_parser = parse_target)]
    target: Target,
}

struct EmptyPacket {
    buffer: [u8; 400],
}

impl Packet for EmptyPacket {
    fn packet(&self) -> &[u8] {
        &self.buffer
    }

    fn payload(&self) -> &[u8] {
        &self.buffer
    }
}

enum VersionedIcmpPacket<'a> {
    Ipv4(IcmpPacket<'a>),
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
            if sv.len() > 1 {
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
        Mode::Ipv4 => Layer4(Ipv4(IpNextHeaderProtocols::Test1)),
        Mode::Ipv6 => {
            println!("Mode v6!");
            Layer4(Ipv6(IpNextHeaderProtocols::Test1))
        }
    };
    let icmp_protocol = match mode {
        Mode::Ipv4 => Layer4(Ipv4(IpNextHeaderProtocols::Icmp)),
        Mode::Ipv6 => {
            println!("Mode v6!");
            Layer4(Ipv6((IpNextHeaderProtocols::Icmpv6)))
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

    let mut ttl = 1;

    let mut icmp_rx_iter = match mode {
        Mode::Ipv4 => IcmpIterable::Ipv4(icmp_packet_iter(&mut icmp_rx)),
        Mode::Ipv6 => IcmpIterable::Ipv6(icmpv6_packet_iter(&mut icmp_rx)),
    };

    loop {
        let buffer = [0xff as u8; 400];
        let maybe_packet = EmptyPacket { buffer };

        tx.set_ecn(Ecn::Ect0);
        tx.set_ttl(ttl);

        tx.send_to(maybe_packet, target);

        if let Some((rcvd_icmp_packet, rcvd_icmp_addr)) =
            icmp_rx_iter.next_with_timeout(Duration::from_secs(2))
        {
            println!("Got a packet back from {:?}", rcvd_icmp_addr);
            match rcvd_icmp_packet {
                VersionedIcmpPacket::Ipv4(pkt) => {
                    println!("ICMP code: {:?}", pkt.get_icmp_code());
                    println!("ICMP type: {:?}", pkt.get_icmp_type());
                    if let Some(timeout_pkt) = TimeExceededPacket::new(pkt.packet()) {
                        println!("timeout pkt: {:?}", timeout_pkt.get_icmp_type());
                        if let Some(inner_pkt) = Ipv4Packet::new(timeout_pkt.payload()) {
                            println!(
                                "Received Protocol: {:?}",
                                inner_pkt.get_next_level_protocol()
                            );
                            println!("Received ECN: {:?}", inner_pkt.get_ecn());
                        } else {
                            println!("Trouble!")
                        }
                    }
                }
                VersionedIcmpPacket::Ipv6(pkt) => {}
            };
        } else {
            println!("Timeout waiting for ICMP packet back!");
        }
        println!("Sleeping ...");
        thread::sleep(Duration::from_secs(1));
        println!("... waking");
        ttl += 1;
    }
}
