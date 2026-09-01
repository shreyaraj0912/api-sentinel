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
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_api_sentinel_ebpf(ctx: XdpContext) -> Result<u32, ()> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    /*
     * Ethernet header
     *
     * Destination MAC : 6 bytes
     * Source MAC      : 6 bytes
     * EtherType       : 2 bytes
     *
     * Total: 14 bytes
     */

    if data + 14 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let eth_proto_ptr = (data + 12) as *const u16;

    let eth_proto = unsafe { u16::from_be(eth_proto_ptr.read_unaligned()) };

    /*
     * IPv4 only
     */

    if eth_proto != 0x0800 {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip_offset = 14usize;

    /*
     * Minimum IPv4 header validation
     */

    if data + ip_offset + 20 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let version_ihl_ptr = (data + ip_offset) as *const u8;

    let version_ihl = unsafe { version_ihl_ptr.read_unaligned() };

    let version = version_ihl >> 4;

    if version != 4 {
        return Ok(xdp_action::XDP_PASS);
    }

    let ihl = ((version_ihl & 0x0f) * 4) as usize;

    if ihl < 20 {
        return Ok(xdp_action::XDP_PASS);
    }

    /*
     * Validate complete IPv4 header
     */

    if data + ip_offset + ihl > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    /*
     * Protocol
     */

    let protocol_ptr = (data + ip_offset + 9) as *const u8;

    let protocol = unsafe { protocol_ptr.read_unaligned() };

    /*
     * TCP = 6
     * UDP = 17
     */

    if protocol != 6 && protocol != 17 {
        return Ok(xdp_action::XDP_PASS);
    }

    /*
     * Source IP
     */

    let src_ip_ptr = (data + ip_offset + 12) as *const u32;

    let src_ip = unsafe { src_ip_ptr.read_unaligned() };

    /*
     * Destination IP
     */

    let dst_ip_ptr = (data + ip_offset + 16) as *const u32;

    let dst_ip = unsafe { dst_ip_ptr.read_unaligned() };

    /*
     * Transport header
     */

    let transport_offset = ip_offset + ihl;

    /*
     * Need source + destination ports
     */

    if data + transport_offset + 4 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let src_port_ptr = (data + transport_offset) as *const u16;

    let dst_port_ptr = (data + transport_offset + 2) as *const u16;

    let src_port_raw = unsafe { src_port_ptr.read_unaligned() };

    let dst_port_raw = unsafe { dst_port_ptr.read_unaligned() };

    /*
     * Packet length
     */

    let packet_len = (data_end - data) as u32;

    /*
     * Create telemetry event
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
     * Send event to userspace
     */

    if let Some(mut entry) = EVENTS.reserve::<FlowEvent>(0) {
        entry.write(event);
        entry.submit(0);
    }

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
