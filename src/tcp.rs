use etherparse::Ipv4HeaderSlice;
use etherparse::TcpHeaderSlice;
use etherparse::TcpHeader;
use etherparse::Ipv4Header;
use std::io::Write;
use std::io;

pub enum State {
    Closed,
    Listen,
    // SynRcvd,
    // Estab,
}

pub struct Connection {
    state: State,
}


impl Default for Connection {
    fn default() -> Self {
        Self {
            state: State::Listen /* for now */
        }
    }
}

struct SendSequenceSpace {
    /// send unacknowledged (the last sequence which has been sent but not acknowledged)
    una: usize,
    /// send next (next sequence number to be send)
    nxt: usize,
    /// window size ()
    wnd: usize,
}
   

impl State {
    pub fn on_packet(
        &mut self,
        nic: &mut tun::Device,
        ipv4_header: Ipv4HeaderSlice,
        tcp_header: TcpHeaderSlice,
        _data: &[u8],
    ) -> io::Result<usize> {
        match self {
            State::Closed => {
                return Ok(0)
            },
            State::Listen => {
                if !tcp_header.syn() {
                    println!("Only expected syn packet");
                    return Ok(0)
                }
                // Now we send back the TCPHeader with a SYNC, ACK flag
                // let mut syn_ack = TcpHeader::new(
                //     tcp_header.destination_port(),
                //     tcp_header.source_port(),
                //     2, // for syn+ack
                //     tcp_header.window_size(),
                // );
                let mut syn_ack = TcpHeader{
                    destination_port: tcp_header.destination_port(),
                    source_port: tcp_header.source_port(),
                    sequence_number: 2, // for syn+ack
                    window_size: tcp_header.window_size(),
                    ..Default::default()
                };
                syn_ack.syn = true;
                syn_ack.ack = true;
                assert_eq!(syn_ack.header_len(), 20, "Header len is not 20");

                // let additional_payload_len = 0; // because we are only sending syn/ack packet
                // let ipv4_header_len = 20;
                // let payload_len = syn_ack.header_len() + ipv4_header_len + additional_payload_len;
                // assert_eq!(payload_len, 40, "Payload len is not 40");

                let ipv4h = Ipv4Header::new(
                    // payload_len as u16,
                    syn_ack.header_len_u16(),
                    64,
                    etherparse::IpNumber::TCP,
                    ipv4_header.destination_addr().octets(),
                    ipv4_header.source_addr().octets(),
                ).expect("Ipv4Header should create");
                println!("Sending syn-ack packet");

                let mut payload_buf = [0u8; 1500]; // figure out a way to make this calculated
                let mut buf = &mut payload_buf[..]; // this creates a slice which points to the main buf

                ipv4h.write(&mut buf).expect("Unable to write to buf by ipv4"); // moves the start pointer after writing
                syn_ack.write(&mut buf).expect("Unable to write to buf by syn_ack"); // moves the start pointer after writing
                let offset = buf.len() - payload_buf.len(); // whatever part didn't get written OR how much is unwritten
                return nic.write(&payload_buf[..offset])
            },
            _ => todo!()
        }
        // println!(
        //     "{}:{} -> {}:{}, data_len: {}",
        //     ipv4_header.source_addr(),
        //     tcp_header.source_port(),
        //     ipv4_header.destination_addr(),
        //     tcp_header.destination_port(),
        //     payload.len()
        // );
    }
}
