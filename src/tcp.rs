use etherparse::Ipv4Header;
use etherparse::Ipv4HeaderSlice;
use etherparse::TcpHeader;
use etherparse::TcpHeaderSlice;
use std::io;
use std::io::Write;

pub enum State {
    Closed,
    Listen,
    // SynRcvd,
    // Estab,
}

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: ReceiveSequenceSpace,
}

impl Default for Connection {
    fn default() -> Self {
        Self {
            state: State::Listen, /* for now */
            send: Default::default(),
            recv: Default::default(),
        }
    }
}

#[derive(Default)]
struct SendSequenceSpace {
    /// send unacknowledged (the last sequence which has been sent but not acknowledged)
    una: usize,
    /// send next (next sequence number to be send)
    nxt: usize,
    /// window size (number of bytes which can be received at max)
    wnd: usize,
    /// Send urgent pointer
    up: bool,
    /// segment sequence number used for last window update
    wl1: usize,
    /// segment acknowledgment number used for last window update
    wl2: usize,
    /// initial send sequence number
    iss: usize,
}

#[derive(Default)]
struct ReceiveSequenceSpace {
    /// receive next
    nxt: usize,
    /// receive window
    wnd: usize,
    /// receive urgent pointer
    up: bool,
    /// initial receive sequence number
    irs: usize,
}

impl Connection {
    pub fn on_packet(
        &mut self,
        nic: &mut tun::Device,
        ipv4_header: Ipv4HeaderSlice,
        tcp_header: TcpHeaderSlice,
        _data: &[u8],
    ) -> io::Result<usize> {
        match self.state {
            State::Closed => Ok(0),
            State::Listen => {
                if !tcp_header.syn() {
                    println!("Only expected syn packet");
                    return Ok(0);
                }

                // Now we send back the TCPHeader with a SYNC, ACK flag
                let send_sequence_number = 0; /* because we start sending (as server), we can choose to pick any start off number */
                let mut syn_ack = TcpHeader::new(
                    tcp_header.destination_port(),
                    tcp_header.source_port(),
                    send_sequence_number,
                    10, // picking random value for now
                );

                // Keep track of senders sequence
                self.recv.irs = tcp_header.sequence_number() as usize; /* initial receive sequence number */
                self.recv.nxt = (tcp_header.sequence_number() + 1) as usize; /* next byte we are expecting from client */
                self.recv.wnd = tcp_header.window_size() as usize;
                self.recv.up = false; // not sure why, figure out

                // Decide on stuff we need to send (SendSequenceSpace)
                self.send.una = send_sequence_number as usize; /* the last sequence which has been sent but not acknowledged
                                   which automatically becomes the initial send sequence number which is what we send them */
                self.send.nxt = self;
                self.send.wnd = tcp_header.window_size() as usize;

                // We need to acknowledge the incoming syn
                // The sequence_number from the incoming tcp header means the sequence number of
                // the SYN. Next we are expecting is the next byte, which we specify as the acknowledgment number
                syn_ack.acknowledgment_number = self.recv.nxt as u32;
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
                )
                .expect("Ipv4Header should create");
                println!("Sending syn-ack packet");

                let mut payload_buf = [0u8; 1500]; // figure out a way to make this calculated
                let mut buf = &mut payload_buf[..]; // this creates a slice which points to the main buf

                ipv4h
                    .write(&mut buf)
                    .expect("Unable to write to buf by ipv4"); // moves the start pointer after writing
                syn_ack
                    .write(&mut buf)
                    .expect("Unable to write to buf by syn_ack"); // moves the start pointer after writing
                let offset = buf.len() - payload_buf.len(); // whatever part didn't get written OR how much is unwritten
                nic.write(&payload_buf[..offset])
            }
            _ => todo!(),
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
