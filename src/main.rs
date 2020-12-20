mod ffxiv;
mod parser;
use parser::Parser;
use pcap::Capture;
use pcap::Device;
use pnet::datalink::{self};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpFlags;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use std::collections::HashMap;
use std::env;
use std::process;

const DEVICE: &str = "tap0";
const PATH: &str = "127.0.0.1:10801";
const XIV_MAGIC: [u8; 4] = [0x52, 0x52, 0xa0, 0x41];
const ENCODING_PLAIN: [u8; 2] = [0x01, 0x00];

fn main() {
    let devices = Device::list().unwrap();
    let args: Vec<String> = env::args().collect();
    let mut path = PATH;
    let mut interface = DEVICE;

    if args.len() > 1 {
        if args[1] == "-h" {
            println!("usage: {} [interface] [sock-path]", args[0]);
            println!("\nexamples:\n\t{} eth0", args[0]);
            println!("\t{} eth0 /tmp/ffxiv_packets", args[0]);
            println!("usage: {} -l\n", args[0]);
            println!("\tlists availabli interfaces");
            return;
        }
        if args[1] == "-l" {
            let interfaces = datalink::interfaces();

            let iter = if cfg!(windows) {
                interfaces
                    .into_iter()
                    .find(|e| !e.is_loopback() && !e.ips.is_empty())
            } else {
                interfaces
                    .into_iter()
                    .find(|e| e.is_up() && !e.is_loopback() && !e.ips.is_empty())
            };

            for iface in iter {
                println!("found device: {} {}", iface.name, iface.ips[0].ip())
            }
            return;
        }
        interface = &args[1];
    }

    if args.len() > 2 {
        path = &args[2];
    }

    println!("looking for {}", interface);
    let mut device: Option<Device> = None;
    for dev in devices {
        if dev.name.eq(interface) {
            println!("found {}", dev.name);
            device = Some(dev);
            break;
        }
    }
    if let None = device {
        println!("could not find device {}", interface);
        return;
    }

    let cap = Capture::from_device(device.unwrap()).unwrap();
    let cap = if cfg!(windows) {
        cap.buffer_size(1024 * 4 * 1024).snaplen(4096).timeout(0)
    } else {
        cap.buffer_size(1024 * 4 * 1024).snaplen(4096).timeout(250)
    };
    let mut cap = cap.open().unwrap();
    cap.filter("src net 124.150.157 and (tcp)")
        .expect("failed to set filter");

    let mut next_seq: u32 = 0;
    let ctx = zmq::Context::new();
    let socket = ctx.socket(zmq::PUB).unwrap();
    let endpoint = format!("tcp://{}", path);
    socket.bind(&endpoint).expect("failed to bind zmq pub");
    println!("xiv packet socket created at {}", path);
    let mut parser = Parser::new(&socket);
    let mut port: u16 = 0;
    let mut future_packets = HashMap::new();
    let mut drop = 0;
    let mut skip = 0;

    loop {
        match cap.stats() {
            Ok(stats) => {
                if stats.dropped > drop {
                    port = 0;
                    println!("packet drop detected, restarting");
                }
                drop = stats.dropped;
            }
            Err(e) => {
                eprintln!("{}. exiting", e);
                process::exit(1);
            }
        }
        let packet = cap.next();
        if let Err(e) = packet {
            eprintln!("{}. exiting", e);
            process::exit(1);
        }
        let packet = packet.unwrap();
        if parser.ended {
            println!("ended, restarting");
            port = 0;
        }
        if port == 0 && skip == -1 {
            println!("cold start! collecting packets to search for game packets...");
            future_packets.clear();
            parser = Parser::new(&socket);
            skip = 5;
            next_seq = 0;
        }

        let eth = EthernetPacket::new(packet.data).unwrap();
        let v4p: Ipv4Packet;
        let mut tcp: Option<TcpPacket> = None;
        if let EtherTypes::Ipv4 = eth.get_ethertype() {
            v4p = Ipv4Packet::new(eth.payload()).unwrap();
            if let IpNextHeaderProtocols::Tcp = v4p.get_next_level_protocol() {
                tcp = TcpPacket::new(v4p.payload());
            }
        } else if let Some(_v4p) = Ipv4Packet::new(packet.data) {
            v4p = _v4p;
            // no eth packet, possibly ip-level routed
            if let IpNextHeaderProtocols::Tcp = v4p.get_next_level_protocol() {
                tcp = TcpPacket::new(v4p.payload());
            } else {
                eprintln!("not IP!")
            }
        }
        if let Some(tcp) = tcp {
            if port > 0 && parser.last_heartbeat.elapsed().as_secs() > 30 {
                println!("lost heartbeat, resetting");
                port = 0;
            }
            if port > 0 && tcp.get_destination() != port {
                continue;
            }
            // println!(
            //     "{}:{} => {}:{}",
            //     v4p.get_source(),
            //     tcp.get_source(),
            //     v4p.get_destination(),
            //     tcp.get_destination()
            // );

            while future_packets.contains_key(&next_seq) {
                let payload = future_packets.remove(&next_seq).unwrap();
                println!("found cached packet {}", next_seq);
                parser.parse_packet(&payload);
                next_seq += payload.len() as u32;
                next_seq = next_seq & 0xffffffff;
            }

            let payload = tcp.payload().to_vec();
            if port > 0 && (tcp.get_flags() & TcpFlags::FIN) > 0 {
                println!("FIN found, restarting");
                port = 0;
                continue;
            }
            // println!("payload len: {}", payload.len());
            // println!("seq: {}", tcp.get_sequence());
            if port == 0 {
                if skip > 0 {
                    skip -= 1;
                    continue;
                }
                // only use larger packet to bypass heartbeat channel
                if payload.len() >= 104
                    && XIV_MAGIC == payload[0..4]
                    && payload[32..33] != ENCODING_PLAIN
                {
                    println!("got game packet! using port {}", tcp.get_destination());
                    port = tcp.get_destination();
                    next_seq = tcp.get_sequence();
                    skip = -1;
                } else {
                    continue;
                }
            }

            if next_seq > 0 && tcp.get_sequence() > next_seq {
                println!(
                    "expecting seq {}, got {}, caching...",
                    next_seq,
                    tcp.get_sequence()
                );
                future_packets.insert(tcp.get_sequence(), payload);
                if future_packets.len() > 10 {
                    println!("too many packets cached, restarting..");
                    let mut min_seq = 0xffffffff;
                    for &sseq in future_packets.keys() {
                        if let Some(packet) = future_packets.get(&sseq) {
                            if packet.len() >= 4 && XIV_MAGIC != packet[0..4] {
                                continue;
                            }
                            if sseq < min_seq {
                                min_seq = sseq;
                            }
                        }
                    }
                    if min_seq < 0xffffffff {
                        println!("continuing from {}", min_seq);
                        let payload = future_packets.remove(&min_seq).unwrap();
                        next_seq = min_seq + payload.len() as u32;
                        next_seq = next_seq & 0xffffffff;
                        parser = Parser::new(&socket);
                        parser.parse_packet(&payload);
                        continue;
                    }
                    future_packets.clear();
                    port = 0;
                    continue;
                }
            } else {
                if next_seq != tcp.get_sequence() {
                    println!(
                        "sequence mismatch (past packets?) discard... {} {}",
                        next_seq,
                        tcp.get_sequence()
                    );
                    continue;
                }
                // println!("expecting seq {}, got {}", next_seq, tcp.get_sequence());
                parser.parse_packet(&payload);
                // process_packet(&mut buffer, &payload);
                next_seq += payload.len() as u32;
            }
            next_seq = next_seq & 0xffffffff;
        } else {
            println!("non tcp!")
        }
    }
}
