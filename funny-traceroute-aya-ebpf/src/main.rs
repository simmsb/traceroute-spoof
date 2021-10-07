#![no_std]
#![no_main]

use byteorder::{ByteOrder, NetworkEndian as NE};
use core::{ptr::slice_from_raw_parts, slice};

use aya_bpf::{
    bindings::xdp_action,
    helpers::bpf_xdp_adjust_head,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
    BpfContext,
};

use funny_traceroute_aya_common::{MyAddr, ResponseKey};

const ETHER: usize = 14;
const IPV6: usize = 40;
const ICMPV6: usize = 8;

#[map(name = "DEST_ADDRS")]
static mut DEST_ADDRS: HashMap<MyAddr, u8> = HashMap::with_max_entries(255, 0);

#[map(name = "REPLIES")]
static mut REPLIES: HashMap<ResponseKey, MyAddr> = HashMap::with_max_entries(1024, 0);

#[xdp(name = "funny_traceroute_aya")]
pub fn funny_traceroute_aya(ctx: XdpContext) -> u32 {
    match try_funny_traceroute_aya(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[must_use]
#[inline(always)]
fn ensure_at_least(ctx: &XdpContext, len: usize) -> Result<(), u32> {
    let len = len as isize;

    if len < 0 {
        return Err(xdp_action::XDP_PASS);
    }

    let pos = (ctx.data() as isize) + len;

    if pos < 0 {
        return Err(xdp_action::XDP_PASS);
    }

    if pos < (ctx.data() as isize) {
        return Err(xdp_action::XDP_PASS);
    }

    if pos > (ctx.data_end() as isize) {
        return Err(xdp_action::XDP_PASS);
    }

    Ok(())
}

#[repr(C, align(2))]
struct A<T>(T);

fn bounded_slice_csum(s: &[u8], bound: usize) -> u32 {
    let mut sum = 0u32;
    let mut i = 0;

    for _ in 0..bound {
        let v = match s.get(i..i + 2) {
            Some(s) => NE::read_u16(s),
            None => break,
        };

        sum += v as u32;
        i += 2;
    }

    if let Some(v) = s.get(i) {
        sum += (*v as u32) << 8;
    }

    sum
}

unsafe fn csum_of<T>(x: T) -> u32 {
    let y = A(x);
    let slc = &*slice_from_raw_parts(&y as *const _ as *const u8, core::mem::size_of::<T>());

    bounded_slice_csum(slc, core::mem::size_of::<T>())
}

#[inline(always)]
fn body_csum(ctx: &XdpContext, start: usize) -> u32 {
    let mut pos = ctx.data() + start;
    let mut sum = 0u32;

    for _ in 0..740 {
        if (pos + 2) > ctx.data_end() {
            break;
        }

        let slc = unsafe { &*slice::from_raw_parts(pos as *const u8, 2) };
        sum += NE::read_u16(slc) as u32;
        pos += 2;
    }

    if (pos + 1) <= ctx.data_end() {
        sum += (unsafe { *(pos as *const u8) } as u32) << 8;
    }

    sum
}

#[inline(always)]
fn csum_fold(mut sum: u32) -> u16 {
    for _ in 0..4 {
        if sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
    }

    !(sum as u16)
}

#[inline(always)]
fn try_funny_traceroute_aya(ctx: XdpContext) -> Result<u32, u32> {
    if (ctx.data_end() - ctx.data()) < (ETHER + IPV6) {
        return Err(xdp_action::XDP_PASS);
    }

    let pkt_buf = unsafe {
        core::slice::from_raw_parts(ctx.data() as *const u8, ctx.data_end() - ctx.data())
    };

    let eth = jnet::ether::Frame::parse(pkt_buf).map_err(|_| xdp_action::XDP_PASS)?;

    if eth.get_type() != jnet::ether::Type::Ipv6 {
        return Ok(xdp_action::XDP_PASS);
    }

    ensure_at_least(&ctx, ETHER + IPV6)?;

    let ipv6 = jnet::ipv6::Packet::parse(eth.payload()).map_err(|_| xdp_action::XDP_PASS)?;

    let ipv6_nx: u8 = ipv6.get_next_header().into();

    let reply_table_idx = unsafe {
        *DEST_ADDRS
            .get(&MyAddr(ipv6.get_destination().0))
            .ok_or(xdp_action::XDP_PASS)?
    };

    let payload_len = ipv6.get_length() as usize;

    if payload_len < 8 || payload_len > 1500 {
        return Err(xdp_action::XDP_PASS);
    }

    if (ctx.data_end() - ctx.data()) < (ETHER + IPV6 + payload_len) {
        return Err(xdp_action::XDP_PASS);
    }

    let response_key = ResponseKey {
        idx: reply_table_idx,
        ttl: ipv6.get_hop_limit(),
    };

    let (ipv6_out_src, has_reached_end) = match unsafe { REPLIES.get(&response_key) } {
        Some(v) => (jnet::ipv6::Addr(v.0), false),
        None => (ipv6.get_destination(), true),
    };

    let eth_out_dst = eth.get_source();
    let eth_out_src = eth.get_destination();

    let ipv6_out_dst = ipv6.get_source();

    let icmp_content: u32 = if ipv6_nx == 58 {
        ensure_at_least(&ctx, ETHER + IPV6 + ICMPV6)?;

        let pkt = pkt_buf
            .get(ETHER + IPV6..ETHER + IPV6 + ICMPV6)
            .ok_or(xdp_action::XDP_PASS)?;
        NE::read_u32(pkt.get(4..8).ok_or(xdp_action::XDP_PASS)?)
    } else {
        0
    };

    let (icmp_type, icmp_code) = if has_reached_end {
        match ipv6_nx {
            17 => (1, 4),
            58 => (129, 0),
            _ => (3, 0),
        }
    } else {
        (3, 0)
    };

    let mut sum = 0u32;
    sum += unsafe { csum_of(ipv6_out_src.0) };
    sum += unsafe { csum_of(ipv6_out_dst.0) };
    let l = (ICMPV6 as u16 + IPV6 as u16 + payload_len as u16) as u32;
    sum += l as u32;

    sum += 58u32;

    sum += ((icmp_type as u16) << 8 | icmp_code as u16) as u32;
    sum += unsafe { csum_of(icmp_content.to_be_bytes()) };
    sum += body_csum(&ctx, ETHER);

    let sum = csum_fold(sum);

    if unsafe { bpf_xdp_adjust_head(ctx.as_ptr() as *mut _, -(IPV6 as i32 + ICMPV6 as i32)) } < 0 {
        return Err(xdp_action::XDP_ABORTED);
    }

    ensure_at_least(&ctx, ETHER + IPV6 + ICMPV6 + 1)?;

    let pkt_buf_out = unsafe {
        core::slice::from_raw_parts_mut(ctx.data() as *mut u8, ctx.data_end() - ctx.data())
    };

    let mut out_eth = jnet::ether::Frame::new(pkt_buf_out).ok_or(xdp_action::XDP_ABORTED)?;
    out_eth.set_source(eth_out_src);
    out_eth.set_destination(eth_out_dst);
    out_eth.set_type(jnet::ether::Type::Ipv6);

    let mut out_ipv6 =
        jnet::ipv6::Packet::new(out_eth.payload_mut()).ok_or(xdp_action::XDP_ABORTED)?;
    out_ipv6
        .set_next_header(jnet::ipv6::NextHeader::Ipv6Icmp)
        .ok_or(xdp_action::XDP_ABORTED)?;
    unsafe {
        out_ipv6.set_length(ICMPV6 as u16 + IPV6 as u16 + payload_len as u16);
    }
    out_ipv6.set_source(ipv6_out_src);
    out_ipv6.set_destination(ipv6_out_dst);

    let icmp_pkt = &mut out_eth.free()[(ETHER + IPV6)..];

    *icmp_pkt.get_mut(0).ok_or(xdp_action::XDP_ABORTED)? = icmp_type;
    *icmp_pkt.get_mut(1).ok_or(xdp_action::XDP_ABORTED)? = icmp_code;

    icmp_pkt
        .get_mut(2..4)
        .ok_or(xdp_action::XDP_ABORTED)?
        .copy_from_slice(&sum.to_be_bytes()[..]);

    icmp_pkt
        .get_mut(4..8)
        .ok_or(xdp_action::XDP_ABORTED)?
        .copy_from_slice(&icmp_content.to_be_bytes()[..]);

    Ok(xdp_action::XDP_TX)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unreachable!()
}
