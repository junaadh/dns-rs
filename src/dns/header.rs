use crate::{buffer::PacketBuffer, error::DnsError};

use super::ResCode;

#[derive(Debug, Clone, Default)]
pub struct DnsHeader {
    pub id: u16,

    pub recursion_desired: bool,
    pub truncated_message: bool,
    pub authorative_answer: bool,
    pub opcode: u8,
    pub response: bool,

    pub rescode: ResCode,
    pub checking_disabled: bool,
    pub authed_data: bool,
    pub z: bool,
    pub recursion_available: bool,

    pub questions: u16,
    pub answers: u16,
    pub authorative_entries: u16,
    pub resource_entries: u16,
}

impl DnsHeader {
    pub fn read(&mut self, buffer: &mut PacketBuffer) -> Result<(), DnsError> {
        self.id = buffer.read_u16()?;

        let flags = buffer.read_u16()?;
        let a = (flags >> 8) as u8;
        let b = (flags & 0xff) as u8;
        self.recursion_desired = (a & (1 << 0)) > 0;
        self.truncated_message = (a & (1 << 1)) > 0;
        self.authorative_answer = (a & (1 << 2)) > 0;
        self.opcode = (a >> 3) & 0x0f;
        self.response = (a & (1 << 7)) > 0;

        self.rescode = (b & 0x0f).into();
        self.checking_disabled = (b & (1 << 4)) > 0;
        self.authed_data = (b & (1 << 5)) > 0;
        self.z = (b & (1 << 6)) > 0;
        self.recursion_available = (b & (1 << 7)) > 0;

        self.questions = buffer.read_u16()?;
        self.answers = buffer.read_u16()?;
        self.authorative_entries = buffer.read_u16()?;
        self.resource_entries = buffer.read_u16()?;

        Ok(())
    }

    pub fn write(&mut self, buffer: &mut PacketBuffer) -> Result<(), DnsError> {
        buffer.write_u16(self.id)?;

        buffer.write(
            (self.recursion_desired as u8)
                | ((self.truncated_message as u8) << 1)
                | (self.opcode << 3)
                | ((self.response as u8) << 7),
        )?;

        buffer.write(
            (self.rescode as u8)
                | ((self.checking_disabled as u8) << 4)
                | ((self.authed_data as u8) << 5)
                | ((self.z as u8) << 6)
                | ((self.recursion_available as u8) << 7),
        )?;

        buffer.write_u16(self.questions)?;
        buffer.write_u16(self.answers)?;
        buffer.write_u16(self.authorative_entries)?;
        buffer.write_u16(self.resource_entries)
    }
}
