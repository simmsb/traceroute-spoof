use aya::programs::{Xdp, XdpFlags};
use aya::util::online_cpus;
use aya::Bpf;
use bytes::BytesMut;
use std::{
    convert::{TryFrom, TryInto},
    sync::atomic::{AtomicBool, Ordering},
    sync::Arc,
};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(short, long)]
    path: String,
    #[structopt(short, long)]
    iface: String,
}

#[tokio::main]
pub async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::from_args();
    let mut bpf = Bpf::load_file(&opt.path)?;

    let program: &mut Xdp = bpf.program_mut("funny_traceroute_aya")?.try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::SKB_MODE)?;
    // program.attach(&opt.iface, XdpFlags::SKB_MODE | XdpFlags::REPLACE | XdpFlags::UPDATE_IF_NOEXIST)?;

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    let mut perf_array =
        aya::maps::perf::AsyncPerfEventArray::try_from(bpf.map_mut("TRACE_PACKETS")?)?;

    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;

        tokio::spawn(async move {
            // println!("starting monitor on {}", cpu_id);

            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1600))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                println!("wao");

                for i in 0..events.read {
                    let buf: &[u8] = buffers[i].as_ref();

                    println!("heya");
                }
            }
        });
    }

    println!("Waiting for Ctrl-C...");
    tokio::signal::ctrl_c().await?;
    println!("Exiting...");

    Ok(())
}
