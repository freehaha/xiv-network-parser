mod ffxiv;
mod parser;
use parser::Parser;
use pcap::Capture;
use pcap::Device;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;

const DEVICE: &str = "tap0";
const PATH: &str = "/tmp/ffxiv_packets";
const ENDPOINT: &str = "ipc:///tmp/ffxiv_packets";
const XIV_MAGIC: [u8; 4] = [0x52, 0x52, 0xa0, 0x41];

fn main() {
    let devices = Device::list().unwrap();
    let args: Vec<String> = env::args().collect();
    let mut interface = DEVICE;
    if args.len() > 1 {
        interface = &args[1];
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
        println!("could not find device {}", DEVICE);
        return;
    }

    let cap = Capture::from_device(device.unwrap()).unwrap();
    let cap = cap.buffer_size(4096 * 100).snaplen(4096).timeout(250);
    let mut cap = cap.open().unwrap();
    cap.filter("src net 124.150.157 and (tcp)")
        .expect("failed to set filter");

    let mut next_seq: u32 = 0;
    let ctx = zmq::Context::new();
    let socket = ctx.socket(zmq::PUB).unwrap();
    socket.bind(ENDPOINT).expect("failed to bind zmq pub");
    fs::set_permissions(PATH, fs::Permissions::from_mode(0o777))
        .expect("failed to set ipc permissions");
    let mut parser = Parser::new(&socket);
    let mut port: u16 = 0;
    let mut future_packets = HashMap::new();
    let mut drop = 0;
    let mut skip = 0;

    loop {
        let stats = cap.stats().unwrap();
        if stats.dropped > drop {
            port = 0;
            println!("packet drop detected, restarting");
        }
        drop = stats.dropped;
        let packet = cap.next().unwrap();
        if parser.ended {
            println!("ended, restarting");
            port = 0;
        }
        if port == 0 && skip == -1 {
            println!("cold start! collecting packets to search for game packets...");
            parser = Parser::new(&socket);
            skip = 5;
            next_seq = 0;
        }
        let eth = EthernetPacket::new(packet.data).unwrap();
        if let EtherTypes::Ipv4 = eth.get_ethertype() {
            let v4p = Ipv4Packet::new(eth.payload()).unwrap();
            if let IpNextHeaderProtocols::Tcp = v4p.get_next_level_protocol() {
                let tcp = TcpPacket::new(v4p.payload()).unwrap();
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
                let payload = tcp.payload().to_vec();
                // println!("payload len: {}", payload.len());
                // println!("seq: {}", tcp.get_sequence());
                if port == 0 {
                    if skip > 0 {
                        skip = skip - 1;
                        continue;
                    }
                    if payload.len() > 4 && XIV_MAGIC == payload[0..4] {
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
                            if XIV_MAGIC != future_packets.get(&sseq).unwrap()[0..4] {
                                continue;
                            }
                            if sseq < min_seq {
                                min_seq = sseq;
                            }
                        }
                        if min_seq < 0xffffffff {
                            println!("continuing from {}", min_seq);
                            let payload = future_packets.get(&min_seq).unwrap();
                            next_seq = min_seq + packet.len() as u32;
                            parser = Parser::new(&socket);
                            parser.parse_packet(payload);
                            continue;
                        }
                        future_packets.clear();
                        port = 0;
                        continue;
                    }
                } else {
                    // println!("expecting seq {}, got {}", next_seq, tcp.get_sequence());
                    parser.parse_packet(&payload);
                    // process_packet(&mut buffer, &payload);
                    next_seq += payload.len() as u32;
                    while future_packets.contains_key(&next_seq) {
                        let payload = future_packets.remove(&next_seq).unwrap();
                        println!("found future packet {}", next_seq);
                        parser.parse_packet(&payload);
                        next_seq += payload.len() as u32;
                    }
                }
                next_seq = next_seq & 0xffffffff;
            }
        }
    }
}
