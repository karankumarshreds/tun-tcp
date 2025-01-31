#![allow(unused)]
use anyhow::Context;
use base64;
use byteorder::{BigEndian, ByteOrder};
use tun;

const BUF_LEN: usize = 4096;
const TUN_NAME: &'static str = "utun69";
const TCP_HEADER_SIZE: usize = 20;
const PROTO_INDEX: usize = 9;
const FLAGS_INDEX: usize = 33;

#[derive(PartialEq)]
enum Proto {
    TCP,
    ICMP,
    Other,
}

fn main() -> anyhow::Result<()> {
    let mut config = tun::Configuration::default();
    let config = config.tun_name(TUN_NAME); /* add tun name */
    let nic = tun::create(&config).context("failed to create tun")?;
    let mut buf = [0u8; BUF_LEN];

    loop {
        let nbytes = nic.recv(&mut buf[..]).context("failed to receive")?;

        // Check if we have enough bytes for the TCP header
        if nbytes < TCP_HEADER_SIZE {
            println!("Not enough data for the TCP header.");
            continue;
        }

        let proto: Proto = match buf[PROTO_INDEX] {
            6 => Proto::TCP,
            1 => Proto::ICMP,
            _ => Proto::Other,
        };

        match proto {
            Proto::TCP => {
                continue; // for now
                println!("TCP packet recieved.");
                let tcp_flags = buf[FLAGS_INDEX];
                let sync = (tcp_flags & 0x02) != 0;
                let ack = (tcp_flags & 0x10) != 0;
                let fin = (tcp_flags & 0x01) != 0;

                println!("FLAGS: \nSync: {}, Ack: {}, Fin: {}", sync, ack, fin);
            }
            Proto::ICMP => {
                println!("Ping packet received.");
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
