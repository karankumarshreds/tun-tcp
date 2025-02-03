use anyhow::Context;
use tun;
use etherparse::Ipv4HeaderSlice;
// use etherparse::Ipv4ExtensionsSlice;

const BUF_LEN: usize = 4096;
const TUN_NAME: &'static str = "utun69";
const TCP_HEADER_SIZE: usize = 20;
const PROTO_INDEX: usize = 9;
const FLAGS_INDEX_V6: usize = 33;
const FLAGS_INDEX_V4: usize = 6;

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

        println!("Received {nbytes} bytes");

        let proto: Proto = match buf[PROTO_INDEX] {
            6 => Proto::TCP,
            1 => Proto::ICMP,
            _ => Proto::Other,
        };

        match proto {
            Proto::TCP => {
                println!("TCP packet recieved.");
                let tcp_flags = buf[FLAGS_INDEX_V6];
                let sync = (tcp_flags & 0x02) != 0;
                let ack = (tcp_flags & 0x10) != 0;
                let fin = (tcp_flags & 0x01) != 0;

                println!("FLAGS: \nSync: {}, Ack: {}, Fin: {}", sync, ack, fin);
                continue; // for now
            }
            Proto::ICMP => {
                println!("Ping packet received.");

                // Manual
                let total_len: u16 = (buf[2] as u16) << 8 | buf[3] as u16;
                let ihl = (buf[0] & 0x0F) as usize;
                let header_len = ihl * 4;
                let flags = buf[FLAGS_INDEX_V4];
                let reserved = (flags & 0b100) != 0;
                let df = (flags & 0b010) != 0;
                let mf = (flags & 0b001) != 0;
                let payload_len = total_len  - header_len as u16;
                let src_addr: u32 = (buf[12] as u32) << 24 | (buf[13] as u32) << 16 | (buf[14] as u32) << 8 | buf[15] as u32;
                let dest_addr: u32 = (buf[16] as u32) << 24 | (buf[17] as u32) << 16 | (buf[18] as u32) << 8 | buf[19] as u32;
                let seq: u16 = (buf[26] as u16) << 8 | buf[27] as u16;

                println!("Total length: {total_len}");
                println!("Header length: {header_len}");
                println!("Reserved: {reserved}");
                println!("Don't fragment: {df}");
                println!("More fragments: {mf}");
                println!("Source address: {src_addr}");
                println!("Destination address: {dest_addr}");
                println!("Payload length: {payload_len}");
                println!("Sequence: {seq}");

                // Using crate
                let res = Ipv4HeaderSlice::from_slice(&buf[..nbytes]).context("unable to parse ipv4 header")?;
                assert_eq!(total_len, res.total_len(), "total length mismatch");
                assert_eq!(header_len, (res.ihl() * 4) as usize, "header length mismatch");
                assert_eq!(mf, res.more_fragments(), "more fragments mismatch");
                assert_eq!(df, res.dont_fragment(), "don't fragment mismatch");
                assert_eq!(payload_len, res.payload_len().unwrap(), "payload length mismatch");
                assert_eq!(src_addr, res.source_addr().into(), "source address mismatch");
                assert_eq!(dest_addr, res.destination_addr().into(), "source address mismatch");
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
