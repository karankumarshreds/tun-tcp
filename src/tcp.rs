use etherparse::Ipv4HeaderSlice;
use etherparse::TcpHeaderSlice;

pub struct State {}

impl Default for State {
    fn default() -> Self {
        State {}
    }
}

impl State {
    pub fn on_packet(
        &mut self,
        ipv4_header: Ipv4HeaderSlice,
        tcp_header: TcpHeaderSlice,
        payload: &[u8],
    ) {
        todo!()
    }
}
