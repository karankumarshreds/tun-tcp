use etherparse::Ipv4HeaderSlice;
use etherparse::TcpHeaderSlice;
use etherparse::TcpHeader;
use etherparse::Ipv4Header;

pub enum State {
    Closed,
    Listen,
    SynRcvd,
    Estab,
}

impl Default for State {
    fn default() -> Self {
        State::Listen // for now listen to all connections 
    }
}

impl State {
    pub fn on_packet(
        &mut self,
        ipv4_header: Ipv4HeaderSlice,
        tcp_header: TcpHeaderSlice,
        payload: &[u8],
    ) {
        match self {
            State::Closed => {
                return;
            },
            State::Listen => {
                if !tcp_header.syn() {
                    println!("Only expected syn packet");
                    return;
                }
                // Now we send back the TCPHeader with a SYNC, ACK flag
                let mut syn_ack = TcpHeader::new(
                    tcp_header.destination_port(),
                    tcp_header.source_port(),
                    2, // for syn ack
                    tcp_header.window_size(),
                );
                syn_ack.syn = true;
                syn_ack.ack = true;
                assert_eq!(syn_ack.header_len(), 20, "Header len is not 20");

                let additional_payload_len = 0; // because we are only sending syn/ack packet
                let ipv4_header_len = 20;
                let payload_len = syn_ack.header_len() + ipv4_header_len + additional_payload_len;
                assert_eq!(payload_len, 40, "Payload len is not 40");

                let mut ipv4h = Ipv4Header::new(
                    payload_len as u16,
                    64,
                    etherparse::IpNumber::TCP,
                    ipv4_header.destination_addr().octets(),
                    ipv4_header.source_addr().octets(),
                );
                println!("Sending syn-ack packet");

            },
            _ => todo!()
        }
        println!(
            "{}:{} -> {}:{}, data_len: {}",
            ipv4_header.source_addr(),
            tcp_header.source_port(),
            ipv4_header.destination_addr(),
            tcp_header.destination_port(),
            payload.len()
        );
    }
}
