use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{buffer::PacketBuffer, error::DnsError};

use super::QueryType;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum DnsRecord {
    Unknown {
        domain: String,
        qtype: u16,
        data_len: u16,
        ttl: u32,
    },
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    },
    NS {
        domain: String,
        host: String,
        ttl: u32,
    },
    CNAME {
        domain: String,
        host: String,
        ttl: u32,
    },
    MX {
        domain: String,
        priority: u16,
        host: String,
        ttl: u32,
    },
    AAAA {
        domain: String,
        addr: Ipv6Addr,
        ttl: u32,
    },
}

impl DnsRecord {
    pub fn read(buffer: &mut PacketBuffer) -> Result<Self, DnsError> {
        let mut domain = String::new();
        buffer.read_qname(&mut domain)?;

        let qtype_num = buffer.read_u16()?;
        let qtype = QueryType::from(qtype_num);
        buffer.read_u16()?;
        let ttl = buffer.read_u32()?;
        let data_len = buffer.read_u16()?;

        match qtype {
            QueryType::A => {
                let raw_address = buffer.read_u32()?;
                let addr = Ipv4Addr::new(
                    ((raw_address >> 24) & 0xFF) as u8,
                    ((raw_address >> 16) & 0xFF) as u8,
                    ((raw_address >> 8) & 0xFF) as u8,
                    (raw_address & 0xFF) as u8,
                );
                Ok(DnsRecord::A { domain, addr, ttl })
            }
            QueryType::AAAA => {
                let raw_addr1 = buffer.read_u32()?;
                let raw_addr2 = buffer.read_u32()?;
                let raw_addr3 = buffer.read_u32()?;
                let raw_addr4 = buffer.read_u32()?;
                let addr = Ipv6Addr::new(
                    ((raw_addr1 >> 16) & 0xFFFF) as u16,
                    (raw_addr1 & 0xFFFF) as u16,
                    ((raw_addr2 >> 16) & 0xFFFF) as u16,
                    (raw_addr2 & 0xFFFF) as u16,
                    ((raw_addr3 >> 16) & 0xFFFF) as u16,
                    (raw_addr3 & 0xFFFF) as u16,
                    ((raw_addr4 >> 16) & 0xFFFF) as u16,
                    (raw_addr4 & 0xFFFF) as u16,
                );

                Ok(DnsRecord::AAAA { domain, addr, ttl })
            }
            QueryType::NS => {
                let mut ns = String::new();
                buffer.read_qname(&mut ns)?;

                Ok(DnsRecord::NS {
                    domain,
                    host: ns,
                    ttl,
                })
            }
            QueryType::CNAME => {
                let mut cname = String::new();
                buffer.read_qname(&mut cname)?;

                Ok(DnsRecord::CNAME {
                    domain,
                    host: cname,
                    ttl,
                })
            }
            QueryType::MX => {
                let priority = buffer.read_u16()?;
                let mut mx = String::new();
                buffer.read_qname(&mut mx)?;

                Ok(DnsRecord::MX {
                    domain,
                    priority,
                    host: mx,
                    ttl,
                })
            }
            QueryType::Unknown(_) => {
                buffer.step(data_len as usize)?;

                Ok(DnsRecord::Unknown {
                    domain,
                    qtype: qtype_num,
                    data_len,
                    ttl,
                })
            }
        }
    }

    pub fn write(&self, buffer: &mut PacketBuffer) -> Result<usize, DnsError> {
        let start_pos = buffer.pos();

        match self {
            Self::A { domain, addr, ttl } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::A.into())?;
                buffer.write_u16(1)?;
                buffer.write_u32(*ttl)?;
                buffer.write_u16(4)?;

                let octets = addr.octets();
                for &oct in octets.iter() {
                    buffer.write(oct)?;
                }
            }
            Self::NS { domain, host, ttl } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::NS.into())?;
                buffer.write_u16(1)?;
                buffer.write_u32(*ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            Self::CNAME { domain, host, ttl } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::CNAME.into())?;
                buffer.write_u16(1)?;
                buffer.write_u32(*ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            Self::MX {
                domain,
                priority,
                host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::MX.into())?;
                buffer.write_u16(1)?;
                buffer.write_u32(*ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_u16(*priority)?;
                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            Self::AAAA { domain, addr, ttl } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::AAAA.into())?;
                buffer.write_u16(1)?;
                buffer.write_u32(*ttl)?;
                buffer.write_u16(16)?;

                for &octet in &addr.segments() {
                    buffer.write_u16(octet)?;
                }
            }
            &Self::Unknown { .. } => {
                println!("Skipping...: {:?}", self);
            }
        }

        Ok(buffer.pos() - start_pos)
    }
}
