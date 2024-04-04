use std::net::UdpSocket;

use buffer::PacketBuffer;
use dns::DnsPacket;
use error::DnsError;

use crate::dns::{question::DnsQuestion, QueryType, ResCode};

pub mod buffer;
pub mod dns;
pub mod error;

fn main() -> Result<(), DnsError> {
    let sock = UdpSocket::bind(("0.0.0.0", 2069))
        .map_err(|err| eprintln!("{err}"))
        .unwrap();

    loop {
        match handle_query(&sock) {
            Ok(_) => {}
            Err(e) => eprintln!("An error occured: {}", e),
        }
    }
}

fn lookup(qname: &str, qtype: QueryType) -> Result<DnsPacket, DnsError> {
    let server = ("8.8.8.8", 53);
    let socket = UdpSocket::bind(("0.0.0.0", 43210))
        .map_err(|err| eprintln!("{}", err))
        .unwrap();

    let mut res_packet = DnsPacket::default();

    res_packet.header.id = 6969;
    res_packet.header.questions = 1;
    res_packet.header.recursion_desired = true;
    res_packet
        .questions
        .push(DnsQuestion::new(qname.to_string(), qtype));

    let mut req_buffer = PacketBuffer::default();
    res_packet.write(&mut req_buffer)?;

    socket
        .send_to(&req_buffer.buf[0..req_buffer.pos()], server)
        .map_err(|err| eprintln!("{err}"))
        .unwrap();

    let mut res_buffer = PacketBuffer::default();
    socket
        .recv_from(&mut res_buffer.buf)
        .map_err(|err| eprintln!("{err}"))
        .unwrap();

    DnsPacket::from_buffer(&mut res_buffer)
}

fn handle_query(socket: &UdpSocket) -> Result<(), DnsError> {
    let mut req_buffer = PacketBuffer::default();

    let (_len, src) = socket
        .recv_from(&mut req_buffer.buf)
        .map_err(|err| eprintln!("{err}"))
        .unwrap();

    let mut request = DnsPacket::from_buffer(&mut req_buffer)?;

    let mut packet = DnsPacket::default();
    packet.header.id = request.header.id;
    packet.header.recursion_desired = true;
    packet.header.recursion_available = true;
    packet.header.response = true;

    if let Some(question) = request.questions.pop() {
        println!("Received query: {:?}", question);

        match lookup(&question.name, question.qtype) {
            Ok(res) => {
                packet.questions.push(question);
                packet.header.rescode = res.header.rescode;

                for rec in res.answers {
                    println!("Answer: {:?}", rec);
                    packet.answers.push(rec);
                }
                for rec in res.authorities {
                    println!("Authority: {:?}", rec);
                    packet.authorities.push(rec);
                }
                for rec in res.resources {
                    println!("Resource: {:?}", rec);
                    packet.resources.push(rec);
                }
            }
            Err(_) => packet.header.rescode = ResCode::SERVFAIL,
        }
    } else {
        packet.header.rescode = ResCode::FORMERR;
    }

    let mut res_buffer = PacketBuffer::default();
    packet.write(&mut res_buffer)?;

    let len = res_buffer.pos();
    let data = res_buffer.get_range(0, len)?;

    socket
        .send_to(data, src)
        .map_err(|err| eprintln!("{err}"))
        .unwrap();

    Ok(())
}
