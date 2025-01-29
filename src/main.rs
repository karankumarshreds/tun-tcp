use std::io::Read;
use anyhow::Context;
use tun;

const BUF_LEN: usize = 1054;
const TUN_NAME: &'static str = "utun69"; 

fn main() -> anyhow::Result<()> {
    let mut config = tun::Configuration::default();
    let config = config.tun_name(TUN_NAME);
    let nic = tun::create(&config).context("failed to create tun")?;
    let mut buf = [0u8; BUF_LEN];

    let nbytes = nic.recv(&mut buf[..]).context("failed to read")?;
    println!("read {:?} bytes: {:#?}", nbytes, &buf[..nbytes]);
    Ok(())
}
