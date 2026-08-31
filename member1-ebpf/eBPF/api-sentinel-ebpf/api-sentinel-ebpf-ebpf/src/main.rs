#![no_std]
#![no_main]

use api_sentinel_ebpf_common::FlowEvent;
use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
    macros::{map, xdp},
    maps::RingBuf,
    programs::XdpContext,
};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0);

#[xdp]
pub fn api_sentinel_ebpf(ctx: XdpContext) -> u32 {
    match try_api_sentinel_ebpf(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_api_sentinel_ebpf(ctx: XdpContext) -> Result<u32, ()> {
    /*
     * Ethernet Header
     *
     * Destination MAC = 6 bytes
     * Source MAC      = 6 bytes
     * EtherType       = 2 bytes
     *
     * Total = 14 bytes
     */

    let eth_proto = unsafe { read_u16(&ctx, 12)? };

    // Ethernet type must be IPv4
    if u16::from_be(eth_proto) != 0x0800 {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip_offset = 14usize;

    /*
     * IPv4 Header
     */

    let version_ihl = unsafe { read_u8(&ctx, ip_offset)? };

    let version = version_ihl >> 4;

    // Only IPv4
    if version != 4 {
        return Ok(xdp_action::XDP_PASS);
    }

    // Internet Header Length
    let ihl = ((version_ihl & 0x0f) * 4) as usize;

    // Minimum IPv4 header size
    if ihl < 20 {
        return Ok(xdp_action::XDP_PASS);
    }

    // Protocol field
    let protocol = unsafe { read_u8(&ctx, ip_offset + 9)? };

    // TCP = 6
    // UDP = 17
    if protocol != 6 && protocol != 17 {
        return Ok(xdp_action::XDP_PASS);
    }

    /*
     * Source IP
     */

    let src_ip = unsafe { read_u32(&ctx, ip_offset + 12)? };

    /*
     * Destination IP
     */

    let dst_ip = unsafe { read_u32(&ctx, ip_offset + 16)? };

    /*
     * Transport Header
     */

    let transport_offset = ip_offset + ihl;

    let src_port_raw = unsafe { read_u16(&ctx, transport_offset)? };

    let dst_port_raw = unsafe { read_u16(&ctx, transport_offset + 2)? };

    /*
     * Packet Length
     */

    let packet_len = (ctx.data_end() - ctx.data()) as u32;

    /*
     * Create Flow Event
     */

    let event = FlowEvent {
        timestamp: unsafe { bpf_ktime_get_ns() },

        src_ip,
        dst_ip,

        src_port: u16::from_be(src_port_raw),
        dst_port: u16::from_be(dst_port_raw),

        protocol,

        _pad: [0; 3],

        packet_len,
    };

    /*
     * Send Event to Userspace
     */

    if let Some(mut entry) = EVENTS.reserve::<FlowEvent>(0) {
        entry.write(event);
        entry.submit(0);
    }

    Ok(xdp_action::XDP_PASS)
}

/*
 * Safe Packet Reading Helpers
 */

unsafe fn read_u8(ctx: &XdpContext, offset: usize) -> Result<u8, ()> {
    let start = ctx.data();
    let end = ctx.data_end();

    let ptr = (start + offset) as *const u8;

    if (ptr as usize + core::mem::size_of::<u8>()) > end as usize {
        return Err(());
    }

    Ok(unsafe { ptr.read_unaligned() })
}

unsafe fn read_u16(ctx: &XdpContext, offset: usize) -> Result<u16, ()> {
    let start = ctx.data();
    let end = ctx.data_end();

    let ptr = (start + offset) as *const u16;

    if (ptr as usize + core::mem::size_of::<u16>()) > end as usize {
        return Err(());
    }

    Ok(unsafe { ptr.read_unaligned() })
}

unsafe fn read_u32(ctx: &XdpContext, offset: usize) -> Result<u32, ()> {
    let start = ctx.data();
    let end = ctx.data_end();

    let ptr = (start + offset) as *const u32;

    if (ptr as usize + core::mem::size_of::<u32>()) > end as usize {
        return Err(());
    }

    Ok(unsafe { ptr.read_unaligned() })
}

/*
 * Required Panic Handler
 */

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
