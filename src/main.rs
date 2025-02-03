#![allow(dead_code)]
use anyhow::Context;
use etherparse::Ipv4HeaderSlice;
use etherparse::TcpHeaderSlice;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use tun;

const BUF_LEN: usize = 84;
const TUN_NAME: &'static str = "utun69";
const PROTO_INDEX: usize = 9;
const FLAGS_INDEX_V6: usize = 33;
const FLAGS_INDEX_V4: usize = 6;

// standard constants
const IPV4_HEADER_LEN: usize = 20;
const ICMP_HEADER_LEN: usize = 8;
const ICMP_PAYLOAD_LEN: usize = 56;
const TCP_HEADER_LEN: usize = 20; // common header
const TCP_PAYLOAD_LEN: usize = 24; // can vary

mod tcp;

#[derive(PartialEq)]
enum Proto {
    TCP,
    ICMP,
    Other,
}

type Port = u16;

#[derive(Hash, Debug, Clone, Copy, PartialEq, Eq)]
struct Quad {
    src: (Ipv4Addr, Port),
    dest: (Ipv4Addr, Port),
}

fn main() -> anyhow::Result<()> {
    let mut config = tun::Configuration::default();
    let config = config.tun_name(TUN_NAME); /* add tun name */
    let nic = tun::create(&config).context("failed to create tun")?;
    let mut buf = [0u8; BUF_LEN];

    loop {
        let nbytes = nic.recv(&mut buf[..]).context("failed to receive")?;

        // Check if we have enough bytes for the TCP header
        if nbytes < TCP_HEADER_LEN {
            println!("Not enough data for the TCP header.");
            continue;
        }

        println!("Received {nbytes} bytes");

        let proto: Proto = match buf[PROTO_INDEX] {
            6 => Proto::TCP,
            1 => Proto::ICMP,
            _ => Proto::Other,
        };

        let ipv4_header = Ipv4HeaderSlice::from_slice(&buf[..IPV4_HEADER_LEN])
            .context("unable to parse ipv4 header")?;
        let mut connections: HashMap<Quad, tcp::State> = Default::default();

        match proto {
            Proto::TCP => {
                // let tcp_flags = buf[FLAGS_INDEX_V6];
                // let sync = (tcp_flags & 0x02) != 0;
                // let ack = (tcp_flags & 0x10) != 0;
                // let fin = (tcp_flags & 0x01) != 0;
                // println!("FLAGS: \nSync: {}, Ack: {}, Fin: {}", sync, ack, fin);
                let tcp_header = TcpHeaderSlice::from_slice(&buf[IPV4_HEADER_LEN..])
                    .context("failed to parse tcp_header")?;
                let tcp_payload_offset = IPV4_HEADER_LEN + TCP_HEADER_LEN;
                println!(
                    "{} -> {} of tcp to port {}",
                    ipv4_header.source_addr(),
                    ipv4_header.destination_addr(),
                    tcp_header.destination_port()
                );
                connections
                    .entry(Quad {
                        src: (ipv4_header.source_addr(), tcp_header.source_port()),
                        dest: (
                            ipv4_header.destination_addr(),
                            tcp_header.destination_port(),
                        ),
                    })
                    .or_default()
                    .on_packet(ipv4_header, tcp_header, &buf[tcp_payload_offset..]);
            }
            Proto::ICMP => {
                // Manual
                let total_len: u16 = (buf[2] as u16) << 8 | buf[3] as u16;
                let ihl = (buf[0] & 0x0F) as usize;
                let header_len = ihl * 4;
                let flags = buf[FLAGS_INDEX_V4];
                let _reserved = (flags & 0b100) != 0;
                let df = (flags & 0b010) != 0;
                let mf = (flags & 0b001) != 0;
                let payload_len = total_len - header_len as u16;
                let src_addr: u32 = (buf[12] as u32) << 24
                    | (buf[13] as u32) << 16
                    | (buf[14] as u32) << 8
                    | buf[15] as u32;
                let dest_addr: u32 = (buf[16] as u32) << 24
                    | (buf[17] as u32) << 16
                    | (buf[18] as u32) << 8
                    | buf[19] as u32;
                let _seq: u16 = (buf[26] as u16) << 8 | buf[27] as u16;

                // Using crate
                assert!(
                    nbytes > IPV4_HEADER_LEN,
                    "Note enough bytes for IPV4 header parsing"
                );
                assert_eq!(total_len, ipv4_header.total_len(), "total length mismatch");
                assert_eq!(
                    header_len,
                    (ipv4_header.ihl() * 4) as usize,
                    "header length mismatch"
                );
                assert_eq!(mf, ipv4_header.more_fragments(), "more fragments mismatch");
                assert_eq!(df, ipv4_header.dont_fragment(), "don't fragment mismatch");
                assert_eq!(
                    payload_len,
                    ipv4_header.payload_len().unwrap(),
                    "payload length mismatch"
                );
                assert_eq!(
                    src_addr,
                    ipv4_header.source_addr().into(),
                    "source addipv4_header. mismatch"
                );
                assert_eq!(
                    dest_addr,
                    ipv4_header.destination_addr().into(),
                    "source addipv4_header. mismatch"
                );
            }
            _ => {
                println!("Other packet received.");
            }
        }
    }
}

// Bit Position	    7	    6	    5	    4	    3	    2	    1	    0
// Flag Name	    CWR	    ECE	    URG	    ACK	    PSH	    RST	    SYN	    FIN
// Binary	        1	    0	    0	    0	    0	    0	    0	    0
// Hex Mask	        0x80	0x40	0x20	0x10	0x08	0x04	0x02	0x01
// NOTE: Hex Mask is calculated as: ACK position is 4 -> 2^4 = 16 -> hex -> 0x10
// Lets say we get a packet byte (@FLAGS_INDEX) as 0b00010010 (binary representation)
// We need to do bit mask using "&" validation and check if its true or not.
// Lets check for ACK flag: 0x10 -> 0b00010000 -> 0b00010000 & 0b00010000 -> 0b00010000
// Which is true and hence ACK flag is set.
