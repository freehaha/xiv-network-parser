use crate::ffxiv::{XivPacket, XivPacketType};
use byteorder::{LittleEndian, ReadBytesExt};
use inflate::inflate_bytes_zlib;
use std::convert::TryInto;
use std::io::{BufReader, BufWriter, Cursor, Read, Seek, SeekFrom, Write};
use std::time::Instant;
use subprocess::{Popen, PopenConfig, Redirection};

pub struct Parser<'a> {
    pub ended: bool,
    sn: u8,
    socket: &'a zmq::Socket,
    is_debug: bool,
    buffer: Vec<u8>,
    pub last_heartbeat: Instant,
    pub oodle_helper: Option<Popen>,
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
        while len >= 40 {
            let mut rdr = Cursor::new(self.buffer.as_slice());
            rdr.seek(SeekFrom::Start(16)).unwrap();
            let timestamp: u64 = rdr.read_u64::<LittleEndian>().unwrap();
            let subpacket_size: usize = rdr.read_u16::<LittleEndian>().unwrap() as usize;
            rdr.seek(SeekFrom::Start(30)).unwrap();
            let _subpacket_count: u16 = rdr.read_u16::<LittleEndian>().unwrap();
            let encoding: u8 = rdr.read_u8().unwrap();
            let compression: u8 = rdr.read_u8().unwrap();
            rdr.seek(SeekFrom::Start(36)).unwrap();
            let decoded_body_length: u32 = rdr.read_u32::<LittleEndian>().unwrap();
            if self.is_debug {
                println!(
                    "t: {}, size: {}, count: {}, encoding: {} {}",
                    timestamp, subpacket_size, _subpacket_count, encoding, compression
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

                    if compression == 1 {
                        self.process_subpackets(timestamp, &subpackets);
                    } else if compression == 2 {
                        self.process_subpackets_oodle(timestamp, &subpackets, decoded_body_length);
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
            if let XivPacketType::Heartbeat = p.packet_type {
                len = bytes.len();
                self.last_heartbeat = Instant::now();
                continue;
            }
            if let XivPacketType::Ignore = p.packet_type {
                len = bytes.len();
                continue;
            }
            if let XivPacketType::Lobby = p.packet_type {
                len = bytes.len();
                self.ended = true;
                continue;
            }

            self.last_heartbeat = Instant::now();
            let mut msg = vec![b'p', b' ', self.sn];
            msg.extend_from_slice(&p.to_bytes());
            self.socket.send(msg, 0).unwrap();
            self.sn = self.sn + 1;
            if self.sn >= 128 {
                self.sn = self.sn - 128;
            }
            // println!("hex: {}", to_hash(&packet));
            len = bytes.len();
        }
    }

    fn start_oodle_helper(&mut self) {
        self.oodle_helper = Some(
            Popen::create(
                &["./oodle_helper"],
                PopenConfig {
                    stdout: Redirection::Pipe,
                    stdin: Redirection::Pipe,
                    ..Default::default()
                },
            )
            .unwrap(),
        );
    }

    pub fn process_subpackets_oodle(&mut self, t: u64, game_packets: &Vec<u8>, dec_len: u32) {
        if self.is_debug {
            println!(
                "oodle packets len: {} dec_len: {}",
                game_packets.len(),
                dec_len
            );
        }
        if self.oodle_helper.is_none() {
            println!("starting oodle_helper...");
            self.oodle_helper = Some(
                Popen::create(
                    &["./oodle_helper"],
                    PopenConfig {
                        stdin: subprocess::Redirection::Pipe,
                        stdout: subprocess::Redirection::Pipe,
                        ..Default::default()
                    },
                )
                .unwrap(),
            );
            return;
        }

        let mut bytes = game_packets.clone();
        let len: u32 = bytes.len().try_into().unwrap();

        let mut input: Vec<u8> = Vec::new();
        input.append(&mut len.to_le_bytes().to_vec());
        input.append(&mut dec_len.to_le_bytes().to_vec());
        input.append(&mut bytes);

        {
            let mut writer =
                BufWriter::new(self.oodle_helper.as_mut().unwrap().stdin.as_ref().unwrap());
            writer.write(&input).expect("oodle write error");
            writer.flush().expect("oodle flush");
        }

        {
            let mut reader =
                BufReader::new(self.oodle_helper.as_mut().unwrap().stdout.as_ref().unwrap());
            let psize: u32 = reader.read_u32::<LittleEndian>().unwrap();
            let mut out = vec![0; psize.try_into().unwrap()];
            reader.read_exact(out.as_mut_slice()).expect("oodle read");
            self.process_subpackets_raw(t, &out);
        }
    }

    pub fn new(socket: &'a zmq::Socket) -> Parser {
        let mut p = Parser {
            socket,
            sn: 0,
            ended: false,
            is_debug: false,
            buffer: Vec::new(),
            oodle_helper: None,
            last_heartbeat: Instant::now(), // last heartbeat in -90s from now
        };
        p.start_oodle_helper();
        return p;
    }
}
