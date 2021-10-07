use aya::{
    maps::{HashMap, Map},
    programs::{Xdp, XdpFlags},
    Bpf,
};
use funny_traceroute_aya_common::{MyAddr, ResponseKey};
use serde::Deserialize;
use std::{
    convert::{TryFrom, TryInto},
    net::Ipv6Addr,
    ops::DerefMut,
    path::PathBuf,
};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "traceroute spoofer",
    about = "Replies to traceroutes with different source IPs depending on the TTL on arrival.",
    author,
)]
struct Opt {
    #[structopt(short, long)]
    path: String,

    #[structopt(short, long)]
    iface: String,

    #[structopt(short, long, parse(from_os_str))]
    cfg: PathBuf,
}

#[derive(Debug, Deserialize)]
struct ConfigEntry {
    dst: Ipv6Addr,
    replies: Vec<Ipv6Addr>,
}

fn insert_replies<Td: DerefMut<Target = Map>, Tr: DerefMut<Target = Map>>(
    dest_addrs: &mut HashMap<Td, MyAddr, u8>,
    replies: &mut HashMap<Tr, ResponseKey, MyAddr>,
    entries: &[ConfigEntry],
) {
    for (idx, entry) in entries.iter().enumerate() {
        dest_addrs
            .insert(MyAddr(entry.dst.octets()), idx.try_into().unwrap(), 0)
            .unwrap();

        for (ttl, reply) in entry.replies.iter().enumerate() {
            replies
                .insert(
                    ResponseKey {
                        idx: idx.try_into().unwrap(),
                        ttl: ttl.try_into().unwrap(),
                    },
                    MyAddr(reply.octets()),
                    0,
                )
                .unwrap();
        }
    }
}

#[tokio::main]
pub async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::from_args();

    let cfg = std::fs::File::open(&opt.cfg)?;
    let cfg: Vec<ConfigEntry> = serde_yaml::from_reader(cfg)?;

    println!("{:#?}", cfg);

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

    let mut dest_addrs: HashMap<_, MyAddr, u8> = HashMap::try_from(bpf.map_mut("DEST_ADDRS")?)?;
    let mut replies: HashMap<_, ResponseKey, MyAddr> = HashMap::try_from(bpf.map_mut("REPLIES")?)?;

    insert_replies(&mut dest_addrs, &mut replies, &cfg);

    let program: &mut Xdp = bpf.program_mut("funny_traceroute_aya")?.try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::SKB_MODE)?;
    // program.attach(&opt.iface, XdpFlags::SKB_MODE | XdpFlags::REPLACE | XdpFlags::UPDATE_IF_NOEXIST)?;

    println!("Waiting for Ctrl-C...");
    tokio::signal::ctrl_c().await?;
    println!("Exiting...");

    Ok(())
}
