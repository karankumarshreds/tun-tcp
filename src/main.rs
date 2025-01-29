use std::io::Read;
use anyhow::Context;
use tun;

const BUF_LEN: usize = 1054;

fn main() -> anyhow::Result<()> {
    let config = tun::Configuration::default();
    let mut nic = tun::create(&config).context("failed to create tun")?;
    let mut buf = [0u8; BUF_LEN];

    let nbytes = nic.read(&mut buf[..]).context("failed to read")?;
    println!("read {:?} bytes: {:#?}", nbytes, &buf[..nbytes]);
    Ok(())
}
