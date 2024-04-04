use crate::{err, error::DnsError};

#[derive(Debug)]
pub struct PacketBuffer {
    pub buf: [u8; 512],
    pos: usize,
}

impl Default for PacketBuffer {
    fn default() -> Self {
        Self {
            buf: [0; 512],
            pos: 0,
        }
    }
}

impl PacketBuffer {
    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn step(&mut self, offset: usize) -> Result<(), DnsError> {
        self.pos += offset;
        Ok(())
    }

    pub fn seek(&mut self, offset: usize) -> Result<(), DnsError> {
        self.pos = offset;
        Ok(())
    }

    pub fn read(&mut self) -> Result<u8, DnsError> {
        if self.pos >= 512 {
            return Err(err!(OutOfBounds));
        }

        let res = self.buf[self.pos];
        self.pos += 1;
        Ok(res)
    }

    pub fn get(&self, offset: usize) -> Result<u8, DnsError> {
        if offset >= 512 {
            return Err(err!(OutOfBounds));
        }

        Ok(self.buf[offset])
    }

    pub fn set(&mut self, offset: usize, val: u8) -> Result<(), DnsError> {
        self.buf[offset] = val;

        Ok(())
    }

    pub fn set_u16(&mut self, offset: usize, val: u16) -> Result<(), DnsError> {
        self.set(offset, (val >> 8) as u8)?;
        self.set(offset + 1, (val & 0xff) as u8)
    }

    pub fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8], DnsError> {
        if start + len >= 512 {
            return Err(err!(OutOfBounds));
        }

        Ok(&self.buf[start..start + len])
    }

    pub fn read_u16(&mut self) -> Result<u16, DnsError> {
        let res = ((self.read()? as u16) << 8) | self.read()? as u16;
        Ok(res)
    }

    pub fn read_u32(&mut self) -> Result<u32, DnsError> {
        let res = ((self.read()? as u32) << 24)
            | ((self.read()? as u32) << 16)
            | ((self.read()? as u32) << 8)
            | self.read()? as u32;
        Ok(res)
    }

    pub fn write(&mut self, val: u8) -> Result<(), DnsError> {
        if self.pos >= 512 {
            return Err(err!(OutOfBounds));
        }

        self.buf[self.pos] = val;
        self.pos += 1;
        Ok(())
    }

    pub fn write_u16(&mut self, val: u16) -> Result<(), DnsError> {
        self.write((val >> 8) as u8)?;
        self.write((val & 0xff) as u8)
    }

    pub fn write_u32(&mut self, val: u32) -> Result<(), DnsError> {
        self.write(((val >> 24) & 0xff) as u8)?;
        self.write(((val >> 16) & 0xff) as u8)?;
        self.write(((val >> 8) & 0xff) as u8)?;
        self.write((val & 0xff) as u8)
    }

    pub fn read_qname(&mut self, outstr: &mut String) -> Result<(), DnsError> {
        let mut pos = self.pos();

        let mut jumped = false;
        let max = 5;
        let mut jumps = 0;

        let mut delim = "";
        loop {
            if jumps > max {
                return Err(err!(JumpsExceed));
            }

            let len = self.get(pos)?;

            if (len & 0xc0) == 0xc0 {
                if !jumped {
                    self.seek(pos + 2)?;
                }

                let byte2 = self.get(pos + 1)? as u16;
                let offset = ((len as u16 ^ 0xc0) << 8) | byte2;
                pos = offset as usize;

                jumped = true;
                jumps += 1;
                continue;
            } else {
                pos += 1;
                if len == 0 {
                    break;
                }
                outstr.push_str(delim);
                let str = self.get_range(pos, len as usize)?;
                outstr.push_str(&String::from_utf8_lossy(str).to_lowercase());
                delim = ".";
                pos += len as usize;
            }
        }

        if !jumped {
            self.seek(pos)?;
        }

        Ok(())
    }

    pub fn write_qname(&mut self, qname: &str) -> Result<(), DnsError> {
        for label in qname.split('.') {
            let len = label.len();
            if len > 0x3f {
                return Err(err!(LabelLengthExceed));
            }

            self.write(len as u8)?;
            for b in label.as_bytes() {
                self.write(*b)?;
            }
        }
        self.write(0)
    }
}
