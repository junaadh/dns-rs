use crate::{buffer::PacketBuffer, error::DnsError};

use self::{header::DnsHeader, question::DnsQuestion, record::DnsRecord};

pub mod header;
pub mod question;
pub mod record;
pub mod response;

#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub enum ResCode {
    #[default]
    NOERROR,
    FORMERR,
    SERVFAIL,
    NXDOMAIN,
    NOTIMP,
    REFUSED,
}

impl From<u8> for ResCode {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::FORMERR,
            2 => Self::SERVFAIL,
            3 => Self::NXDOMAIN,
            4 => Self::NOTIMP,
            5 => Self::REFUSED,
            _ => Self::NOERROR,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum QueryType {
    Unknown(u16),
    A,
    NS,
    CNAME,
    MX,
    AAAA,
}

impl From<QueryType> for u16 {
    fn from(value: QueryType) -> Self {
        match value {
            QueryType::Unknown(x) => x,
            QueryType::A => 1,
            QueryType::NS => 2,
            QueryType::CNAME => 5,
            QueryType::MX => 15,
            QueryType::AAAA => 28,
        }
    }
}

impl From<u16> for QueryType {
    fn from(value: u16) -> Self {
        match value {
            1 => Self::A,
            2 => Self::NS,
            5 => Self::CNAME,
            15 => Self::MX,
            28 => Self::AAAA,
            _ => Self::Unknown(value),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn from_buffer(buffer: &mut PacketBuffer) -> Result<Self, DnsError> {
        let mut res = Self::default();
        res.header.read(buffer)?;

        for _ in 0..res.header.questions {
            let mut question = DnsQuestion::new(String::new(), QueryType::Unknown(0));
            question.read(buffer)?;
            res.questions.push(question);
        }

        for _ in 0..res.header.answers {
            let rec = DnsRecord::read(buffer)?;
            res.answers.push(rec);
        }

        for _ in 0..res.header.authorative_entries {
            let rec = DnsRecord::read(buffer)?;
            res.authorities.push(rec);
        }

        for _ in 0..res.header.resource_entries {
            let rec = DnsRecord::read(buffer)?;
            res.authorities.push(rec);
        }

        Ok(res)
    }

    pub fn write(&mut self, buffer: &mut PacketBuffer) -> Result<(), DnsError> {
        self.header.questions = self.questions.len() as u16;
        self.header.answers = self.answers.len() as u16;
        self.header.authorative_entries = self.authorities.len() as u16;
        self.header.resource_entries = self.resources.len() as u16;

        self.header.write(buffer)?;

        for question in &self.questions {
            question.write(buffer)?;
        }
        for rec in &self.answers {
            rec.write(buffer)?;
        }
        for rec in &self.authorities {
            rec.write(buffer)?;
        }
        for rec in &self.resources {
            rec.write(buffer)?;
        }

        Ok(())
    }
}
