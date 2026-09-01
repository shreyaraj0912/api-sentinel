use anyhow::Context as _;
use api_sentinel_ebpf_common::FlowEvent;
use aya::{
    maps::RingBuf,
    programs::{Xdp, XdpMode},
};
use clap::Parser;
use log::{debug, warn};
use serde::Serialize;
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[derive(Debug, Serialize)]
struct TelemetryEvent {
    event_id: String,

    timestamp: u64,

    src_ip: String,
    dst_ip: String,

    src_port: u16,
    dst_port: u16,

    protocol: String,

    packet_len: u32,

    method: Option<String>,
    path: Option<String>,

    user_id: Option<String>,
    role: Option<String>,
    object_id: Option<String>,
}

fn ip_to_string(ip: u32) -> String {
    let bytes = ip.to_ne_bytes();
    std::net::Ipv4Addr::from(bytes).to_string()
}

fn flow_to_json(event: &FlowEvent, event_id: u64) -> anyhow::Result<String> {
    let protocol = match event.protocol {
        6 => "TCP",
        17 => "UDP",
        _ => "OTHER",
    }
    .to_string();

    let telemetry = TelemetryEvent {
        event_id: format!("evt-{event_id:06}"),

        timestamp: event.timestamp,

        src_ip: ip_to_string(event.src_ip),
        dst_ip: ip_to_string(event.dst_ip),

        src_port: event.src_port,
        dst_port: event.dst_port,

        protocol,

        packet_len: event.packet_len,

        // HTTP metadata is reserved for future parsing.
        method: None,
        path: None,

        // Detection enrichment fields.
        user_id: None,
        role: None,
        object_id: None,
    };

    Ok(serde_json::to_string(&telemetry)?)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };

    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };

    if ret != 0 {
        debug!("failed to increase memlock limit");
    }

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/api-sentinel-ebpf"
    )))?;

    match aya_log::EbpfLogger::init(&mut ebpf) {
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;

            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();

                    guard.get_inner_mut().flush();

                    guard.clear_ready();
                }
            });
        }

        Err(e) => {
            warn!("failed to initialize eBPF logger: {e}");
        }
    }

    let Opt { iface } = opt;

    let program: &mut Xdp = ebpf
        .program_mut("api_sentinel_ebpf")
        .context("failed to find XDP program")?
        .try_into()?;

    program.load()?;

    program
        .attach(&iface, XdpMode::Skb)
        .context("failed to attach XDP program")?;

    println!("======================================");
    println!("API-SENTINEL eBPF TELEMETRY COLLECTOR");
    println!("======================================");
    println!("XDP program attached to: {iface}");
    println!("Monitoring IPv4 TCP/UDP traffic...");
    println!("JSON telemetry output enabled.");
    println!("Press Ctrl-C to stop.");
    println!("--------------------------------------");

    let mut events = RingBuf::try_from(
        ebpf.take_map("EVENTS")
            .context("failed to get EVENTS map")?,
    )?;

    let mut event_counter: u64 = 0;

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                println!();
                println!("Stopping API-Sentinel...");
                break;
            }

            _ = tokio::time::sleep(
                std::time::Duration::from_millis(50)
            ) => {
                while let Some(item) = events.next() {
                    if item.len()
                        < core::mem::size_of::<FlowEvent>()
                    {
                        continue;
                    }

                    let event = unsafe {
                        &*(
                            item.as_ptr()
                                as *const FlowEvent
                        )
                    };

                    event_counter += 1;

                    match flow_to_json(
                        event,
                        event_counter,
                    ) {
                        Ok(json) => {
                            println!("{json}");
                        }

                        Err(e) => {
                            warn!(
                                "failed to serialize event: {e}"
                            );
                        }
                    }
                }
            }
        }
    }

    println!("API-Sentinel stopped.");

    Ok(())
}
