#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::RingBuf,
    programs::XdpContext,
};

use api_sentinel_ebpf_common::FlowEvent;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

const ETH_P_IP: u16 = 0x0800;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

#[xdp]
pub fn api_sentinel_ebpf(ctx: XdpContext) -> u32 {
    match try_api_sentinel_ebpf(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, u32> {
    let start = ctx.data();
    let end = ctx.data_end();

    let len = core::mem::size_of::<T>();

    let ptr = start + offset;

    if ptr + len > end {
        return Err(xdp_action::XDP_ABORTED);
    }

    Ok(ptr as *const T)
}

fn try_api_sentinel_ebpf(ctx: XdpContext) -> Result<u32, u32> {
    let data_start = ctx.data();
    let data_end = ctx.data_end();

    let packet_len = (data_end - data_start) as u32;

    // Ethernet header = 14 bytes
    if packet_len < 14 {
        return Ok(xdp_action::XDP_PASS);
    }

    // EtherType is at Ethernet offset 12
    let eth_proto_ptr = unsafe { ptr_at::<u16>(&ctx, 12)? };

    let eth_proto = unsafe { u16::from_be(*eth_proto_ptr) };

    // We currently process IPv4 only.
    if eth_proto != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }

    // IPv4 header begins at offset 14.
    let ip_ptr = unsafe { ptr_at::<u8>(&ctx, 14)? };

    let version_ihl = unsafe { *ip_ptr };

    let version = version_ihl >> 4;
    let ihl = (version_ihl & 0x0f) as usize;

    if version != 4 {
        return Ok(xdp_action::XDP_PASS);
    }

    // IPv4 header length = IHL * 4
    let ip_header_len = ihl * 4;

    if ip_header_len < 20 {
        return Ok(xdp_action::XDP_PASS);
    }

    if packet_len < (14 + ip_header_len) as u32 {
        return Ok(xdp_action::XDP_PASS);
    }

    // IPv4 protocol field
    let protocol_ptr = unsafe {
        ptr_at::<u8>(&ctx, 14 + 9)?
    };

    let protocol = unsafe { *protocol_ptr };

    // Source IPv4 address
    let src_ip_ptr = unsafe {
        ptr_at::<u32>(&ctx, 14 + 12)?
    };

    // Destination IPv4 address
    let dst_ip_ptr = unsafe {
        ptr_at::<u32>(&ctx, 14 + 16)?
    };

    let src_ip = unsafe { *src_ip_ptr };
    let dst_ip = unsafe { *dst_ip_ptr };

    // TCP/UDP header starts after IPv4 header.
    let transport_offset = 14 + ip_header_len;

    let mut src_port: u16 = 0;
    let mut dst_port: u16 = 0;

    if protocol == IPPROTO_TCP || protocol == IPPROTO_UDP {
        let src_port_ptr = unsafe {
            ptr_at::<u16>(&ctx, transport_offset)?
        };

        let dst_port_ptr = unsafe {
            ptr_at::<u16>(&ctx, transport_offset + 2)?
        };

        src_port = unsafe { u16::from_be(*src_port_ptr) };
        dst_port = unsafe { u16::from_be(*dst_port_ptr) };
    } else {
        // Ignore other protocols for now.
        return Ok(xdp_action::XDP_PASS);
    }

    // Reserve an event in the RingBuf.
    if let Some(mut entry) = EVENTS.reserve::<FlowEvent>(0) {
        entry.write(FlowEvent {
            timestamp: 0,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            _pad: 0,
            packet_len,
        });

        entry.submit(0);
    }

    // Always allow the packet to continue.
    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
