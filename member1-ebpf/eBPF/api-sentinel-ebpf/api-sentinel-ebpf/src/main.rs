use anyhow::Context as _;
use aya::{
    maps::RingBuf,
    programs::{Xdp, XdpMode},
};
use api_sentinel_ebpf_common::FlowEvent;
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit.
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };

    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };

    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // Load the eBPF program.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/api-sentinel-ebpf"
    )))?;

    // Initialize eBPF logger.
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(
                    logger,
                    tokio::io::Interest::READABLE,
                )?;

            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    let Opt { iface } = opt;

    // Load the XDP program.
    let program: &mut Xdp = ebpf
        .program_mut("api_sentinel_ebpf")
        .context("failed to find XDP program")?
        .try_into()?;

    program.load()?;

    // Attach XDP program to the network interface.
    program
        .attach(&iface, XdpMode::Skb)
        .context("failed to attach the XDP program in Skb mode")?;

    println!("XDP program attached to {iface}");
    println!("Waiting for IPv4 TCP/UDP traffic...");
    println!("Press Ctrl-C to stop.");

    // Get the EVENTS RingBuf created by the eBPF program.
    let mut events = RingBuf::try_from(
        ebpf.take_map("EVENTS")
            .context("failed to get EVENTS map")?,
    )?;

    // Handle Ctrl-C and RingBuf events at the same time.
    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                println!("Exiting...");
                break;
            }

            _ = tokio::time::sleep(
                std::time::Duration::from_millis(100)
            ) => {
                while let Some(item) = events.next() {
                    if item.len() < core::mem::size_of::<FlowEvent>() {
                        continue;
                    }

                    let event = unsafe {
                        &*(item.as_ptr() as *const FlowEvent)
                    };

                    let src_ip =
                        std::net::Ipv4Addr::from(event.src_ip.to_be());

                    let dst_ip =
                        std::net::Ipv4Addr::from(event.dst_ip.to_be());

                    let protocol = match event.protocol {
                        6 => "TCP",
                        17 => "UDP",
                        _ => "OTHER",
                    };

                    println!(
                        "[{}] {}:{} -> {}:{} | protocol={} | packet_len={}",
                        event.timestamp,
                        src_ip,
                        event.src_port,
                        dst_ip,
                        event.dst_port,
                        protocol,
                        event.packet_len
                    );
                }
            }
        }
    }

    Ok(())
}
