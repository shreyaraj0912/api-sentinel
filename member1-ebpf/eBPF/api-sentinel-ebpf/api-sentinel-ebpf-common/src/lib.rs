#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FlowEvent {
    pub timestamp: u64,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub _pad: u8,
    pub packet_len: u32,
}
