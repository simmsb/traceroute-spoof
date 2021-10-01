#![no_std]
#![no_main]

use core::marker::PhantomData;

use aya_bpf::{
    bindings::{bpf_map_def, xdp_action, BPF_F_CURRENT_CPU},
    cty::c_void,
    helpers::bpf_perf_event_output,
    macros::{map, xdp},
    maps::PerfMap,
    programs::XdpContext,
    BpfContext,
};

const ETHER: usize = 14;
const IPV6: usize = 40;
const UDP: usize = 8;

#[map(name = "TRACE_PACKETS")]
static mut TRACE_PACKETS: PerfMap<()> = PerfMap::with_max_entries(1024, 0);

#[xdp(name = "funny_traceroute_aya")]
pub fn funny_traceroute_aya(ctx: XdpContext) -> u32 {
    match try_funny_traceroute_aya(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn ensure_at_least(ctx: &XdpContext, len: usize) -> Result<(), u32> {
    if (ctx.data() + len) >= ctx.data_end() {
        return Err(xdp_action::XDP_PASS);
    }

    Ok(())
}

#[inline(always)]
fn emit_packet(ctx: &XdpContext) {
    #[repr(transparent)]
    struct PlsNoNasalDemons {
        def: bpf_map_def,
        _t: PhantomData<()>,
    }

    let map = unsafe {
        &mut core::mem::transmute::<_, &mut PlsNoNasalDemons>(&mut TRACE_PACKETS).def as *mut _
            as *mut c_void
    };

    let index = BPF_F_CURRENT_CPU as u64;
    let len = (ctx.data_end() - ctx.data()) as u64;
    let flags = (len << 32) | index;
    let v = ();

    unsafe {
        bpf_perf_event_output(ctx.as_ptr(), map, flags, &v as *const _ as *mut c_void, 0);
    }
}

#[inline(always)]
fn try_funny_traceroute_aya(ctx: XdpContext) -> Result<u32, u32> {
    emit_packet(&ctx);

    // let pkt_buf = unsafe {
    //     core::slice::from_raw_parts(ctx.data() as *const u8, ctx.data_end() - ctx.data())
    // };

    // let eth = jnet::ether::Frame::parse(pkt_buf).map_err(|_| xdp_action::XDP_PASS)?;

    // if eth.get_type() != jnet::ether::Type::Ipv6 {
    //     return Ok(xdp_action::XDP_PASS);
    // }

    // ensure_at_least(&ctx, ETHER + IPV6)?;

    // let ipv6 = jnet::ipv6::Packet::parse(eth.payload()).map_err(|_| xdp_action::XDP_PASS)?;

    // if ipv6.get_next_header() != jnet::ipv4::Protocol::Udp {
    //     return Ok(xdp_action::XDP_PASS);
    // }

    // ensure_at_least(&ctx, ETHER + IPV6 + UDP)?;

    // let _udp = jnet::udp::Packet::parse(ipv6.payload()).map_err(|_| xdp_action::XDP_PASS)?;

    // emit_packet(&ctx);

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unreachable!()
}
