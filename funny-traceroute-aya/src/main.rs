use aya::maps::Array;
use aya::programs::{Xdp, XdpFlags};
use aya::{Bpf, Pod};
// use aya_log::BpfLogger;
// use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};
use std::convert::{TryFrom, TryInto};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(short, long)]
    path: String,
    #[structopt(short, long)]
    iface: String,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct MyAddr([u8; 16]);

unsafe impl Pod for MyAddr {}

static FUNNY_IPS: &[[u8; 16]] = &[
    [32, 1, 4, 112, 31, 9, 2, 7, 0, 0, 0, 0, 0, 0, 0, 5],
    [32, 1, 4, 112, 31, 9, 2, 7, 0, 0, 0, 0, 0, 0, 0, 6],
    [32, 1, 4, 112, 31, 9, 2, 7, 0, 0, 0, 0, 0, 0, 0, 7],
    [32, 1, 4, 112, 31, 9, 2, 7, 0, 0, 0, 0, 0, 0, 0, 8],
    [32, 1, 4, 112, 31, 9, 2, 7, 0, 0, 0, 0, 0, 0, 0, 9],
    [32, 1, 4, 112, 31, 9, 2, 7, 0, 0, 0, 0, 0, 0, 0, 10],
    [32, 1, 4, 112, 31, 9, 2, 7, 0, 0, 0, 0, 0, 0, 0, 11],
    [32, 1, 4, 112, 31, 9, 2, 7, 0, 0, 0, 0, 0, 0, 0, 12],
    [32, 1, 4, 112, 31, 9, 2, 7, 0, 0, 0, 0, 0, 0, 0, 13],
    [32, 1, 4, 112, 31, 9, 2, 7, 0, 0, 0, 0, 0, 0, 0, 14],
    [32, 1, 4, 112, 31, 9, 2, 7, 0, 0, 0, 0, 0, 0, 0, 15],
    [32, 1, 4, 112, 31, 9, 2, 7, 0, 0, 0, 0, 0, 0, 0, 16],
    [32, 1, 4, 112, 31, 9, 2, 7, 0, 0, 0, 0, 0, 0, 0, 17],
    [32, 1, 4, 112, 31, 9, 2, 7, 0, 0, 0, 0, 0, 0, 0, 18],
    [32, 1, 4, 112, 31, 9, 2, 7, 0, 0, 0, 0, 0, 0, 0, 19],
    [32, 1, 4, 112, 31, 9, 2, 7, 0, 0, 0, 0, 0, 0, 0, 20],
    [32, 1, 4, 112, 31, 9, 2, 7, 0, 0, 0, 0, 0, 0, 0, 21],
    [32, 1, 4, 112, 31, 9, 2, 7, 0, 0, 0, 0, 0, 0, 0, 22],
    [32, 1, 4, 112, 31, 9, 2, 7, 0, 0, 0, 0, 0, 0, 0, 23],
];

#[tokio::main]
pub async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::from_args();
    let mut bpf = Bpf::load_file(&opt.path)?;

    // BpfLogger::init(
    //     &mut bpf,
    //     TermLogger::new(
    //         LevelFilter::Trace,
    //         ConfigBuilder::new()
    //             .set_target_level(LevelFilter::Error)
    //             .set_location_level(LevelFilter::Error)
    //             .build(),
    //         TerminalMode::Mixed,
    //         ColorChoice::Auto,
    //     ),
    // )
    // .unwrap();

    let mut array: Array<_, MyAddr> = Array::try_from(bpf.map_mut("REPLIES")?)?;

    for (i, ip) in FUNNY_IPS.iter().enumerate() {
        array.set(i as u32, MyAddr(*ip), 0)?;
    }

    let program: &mut Xdp = bpf.program_mut("funny_traceroute_aya")?.try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::SKB_MODE)?;
    // program.attach(&opt.iface, XdpFlags::SKB_MODE | XdpFlags::REPLACE | XdpFlags::UPDATE_IF_NOEXIST)?;

    println!("Waiting for Ctrl-C...");
    tokio::signal::ctrl_c().await?;
    println!("Exiting...");

    Ok(())
}
