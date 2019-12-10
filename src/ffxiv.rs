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
    LeaveZone = 0x0274,
    Action = 0x01c6,
    Action8 = 0x2c03,
    Action16 = 0x02be,
    Action24 = 0x0076,
    Tick = 0x00bc,
    Status = 0x025e,
    Casting = 0x033e,
    Dialog = 0x03ad,
    StatusEffect = 0x023c,
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
        let ptype = rdr.read_u32::<LittleEndian>().unwrap();
        return match ptype {
            0x0274 => XivPacketType::LeaveZone,
            0x01c6 => XivPacketType::Action,
            0x02c3 => XivPacketType::Action8,
            0x02be => XivPacketType::Action16,
            0x0076 => XivPacketType::Action24,
            0x00bc => XivPacketType::Tick,
            0x025e => XivPacketType::Status,
            0x033e => XivPacketType::Casting,
            0x03ad => XivPacketType::Dialog,
            0x023c => XivPacketType::StatusEffect,
            _ => XivPacketType::Unknown,
        };
    }
}

impl XivPacket {
    // pub fn into_inner(self) -> Vec<u8> {
    //     return self.packet;
    // }
    //
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.write_u64::<LittleEndian>(self.timestamp).unwrap();
        out.extend_from_slice(&self.packet);
        return out;
    }
}
