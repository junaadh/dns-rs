use crate::{buffer::PacketBuffer, error::DnsError};

use super::QueryType;

#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType,
}

impl DnsQuestion {
    pub fn new(name: String, qtype: QueryType) -> Self {
        Self { name, qtype }
    }

    pub fn read(&mut self, buffer: &mut PacketBuffer) -> Result<(), DnsError> {
        buffer.read_qname(&mut self.name)?;
        self.qtype = buffer.read_u16()?.into();
        buffer.read_u16()?;

        Ok(())
    }

    pub fn write(&self, buffer: &mut PacketBuffer) -> Result<(), DnsError> {
        buffer.write_qname(&self.name)?;

        let type_num = self.qtype.into();
        buffer.write_u16(type_num)?;
        buffer.write_u16(1)
    }
}
