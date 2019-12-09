use crate::ffxiv::{XivPacket, XivPacketType};
use byteorder::{LittleEndian, ReadBytesExt};
use inflate::inflate_bytes_zlib;
use std::io::{Cursor, Read, Seek, SeekFrom};

pub struct Parser<'a> {
    pub ended: bool,
    sn: u8,
    socket: &'a zmq::Socket,
    is_debug: bool,
    buffer: Vec<u8>,
}

fn to_hash(bytes: &Vec<u8>) -> String {
    let mut s = String::new();
    for b in bytes {
        let st = format!("{:02x}", b);
        s.push_str(&st);
    }
    return s;
}

impl<'a> Parser<'a> {
    pub fn parse_packet(&mut self, payload: &Vec<u8>) {
        self.buffer.extend_from_slice(payload);
        let mut len = self.buffer.len();
        // println!("processing packet len={}", len);
        while len >= 40 {
            let mut rdr = Cursor::new(self.buffer.as_slice());
            rdr.seek(SeekFrom::Start(16)).unwrap();
            let timestamp: u64 = rdr.read_u64::<LittleEndian>().unwrap();
            let subpacket_size: usize = rdr.read_u16::<LittleEndian>().unwrap() as usize;
            rdr.seek(SeekFrom::Start(30)).unwrap();
            let _subpacket_count: u16 = rdr.read_u16::<LittleEndian>().unwrap();
            let encoding: u16 = rdr.read_u16::<LittleEndian>().unwrap();
            if self.is_debug {
                println!(
                    "t: {}, size: {}, count: {}, encoding: {}",
                    timestamp, subpacket_size, _subpacket_count, encoding
                );
            }
            if len >= subpacket_size {
                let mut packet = vec![0; subpacket_size];
                rdr.set_position(0);
                rdr.read_exact(&mut packet)
                    .expect("failed to read from buffer");

                if subpacket_size > 40 {
                    let mut subpackets = vec![0; subpacket_size - 40];
                    rdr.seek(SeekFrom::Start(40)).unwrap();
                    rdr.read_exact(&mut subpackets)
                        .expect("failed to read subpacket payload");

                    if encoding == 257 || encoding == 256 {
                        self.process_subpackets(timestamp, &subpackets);
                    } else {
                        self.process_subpackets_raw(timestamp, &subpackets);
                    }
                }

                self.buffer.drain(0..subpacket_size);
                len = self.buffer.len();
                if self.is_debug {
                    println!("leftover: {}", len);
                }
            } else {
                if self.is_debug {
                    println!("not enough buffer: {} for {}", len, subpacket_size);
                }
                break;
            }
        }
    }

    pub fn process_subpackets(&mut self, t: u64, game_packets: &Vec<u8>) {
        if let Ok(bytes) = inflate_bytes_zlib(game_packets) {
            self.process_subpackets_raw(t, &bytes);
        }
    }

    pub fn process_subpackets_raw(&mut self, t: u64, game_packets: &Vec<u8>) {
        if self.is_debug {
            println!("subpackets len: {}", game_packets.len());
        }
        let mut bytes = game_packets.clone();
        let mut len = bytes.len();
        while len > 4 {
            let mut rdr = Cursor::new(bytes);
            let psize = rdr.read_u16::<LittleEndian>().unwrap() as usize;
            bytes = rdr.into_inner();
            if self.is_debug {
                println!("{}", to_hash(&bytes));
            }
            if bytes.len() < psize {
                println!(
                    "error! subpacket size({}) larger than payload({})",
                    psize,
                    bytes.len()
                );
                break;
            }
            let packet: Vec<u8> = bytes.drain(0..psize).collect();
            let p = XivPacket {
                timestamp: t,
                packet_type: XivPacketType::from_packet(&packet),
                packet: packet,
            };
            if let XivPacketType::Ignore = p.packet_type {
                len = bytes.len();
                continue;
            }
            let mut msg = vec![b'p', b' ', self.sn];
            msg.extend_from_slice(&p.to_bytes());
            self.socket.send(msg, 0).unwrap();
            self.ended = match p.packet_type {
                XivPacketType::Logout => true,
                XivPacketType::Lobby => true,
                _ => false,
            };
            // println!("hex: {}", to_hash(&packet));
            len = bytes.len();
        }
    }
    pub fn new(socket: &'a zmq::Socket) -> Parser {
        return Parser {
            socket,
            sn: 0,
            ended: false,
            is_debug: false,
            buffer: Vec::new(),
        };
    }
}
