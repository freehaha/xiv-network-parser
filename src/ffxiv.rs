pub struct XivPacket {
    pub packet_type: XivPacketType,
    pub timestamp: u64,
    pub packet: Vec<u8>,
}

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Seek, SeekFrom};

pub enum XivPacketType {
    Unknown,
    Lobby,
    Ignore,
}

impl XivPacketType {
    pub fn from_packet(packet: &Vec<u8>) -> XivPacketType {
        let mut rdr = Cursor::new(packet);
        rdr.seek(SeekFrom::Start(12)).unwrap();
        let flag = rdr.read_u8().unwrap();
        if flag != 3 {
            return XivPacketType::Ignore;
        }
        rdr.seek(SeekFrom::Start(16)).unwrap();
        let flag = rdr.read_u16::<LittleEndian>().unwrap();
        if flag != 0x14 {
            return XivPacketType::Lobby;
        }
        rdr.seek(SeekFrom::Start(18)).unwrap();
        return XivPacketType::Unknown;
    }
}

impl XivPacket {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.write_u64::<LittleEndian>(self.timestamp).unwrap();
        out.extend_from_slice(&self.packet);
        return out;
    }
}
