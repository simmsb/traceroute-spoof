# Some Traceroute Spoofer

A bit of an experiment, it looks like this:

![image](https://user-images.githubusercontent.com/5330444/136429214-766d2e5d-d495-4d72-8ae6-5b9f6d6e3415.png)

### Config

The config file should look something like this:

```yaml
---

- dst: "2001:bc8:47a8:1922::2"
  replies:
    - "2001:470:1f09:207::5"
    - "2001:470:1f09:207::6"
    - "2001:470:1f09:207::7"
    - "2001:470:1f09:207::8"
    - "2001:470:1f09:207::9"
    - "2001:470:1f09:207::a"
    - "2001:470:1f09:207::b"
    - "2001:470:1f09:207::c"
    - "2001:470:1f09:207::d"
    - "2001:470:1f09:207::e"
    - "2001:470:1f09:207::f"
    - "2001:470:1f09:207::10"
    - "2001:470:1f09:207::11"
    - "2001:470:1f09:207::12"
    - "2001:470:1f09:207::13"
    - "2001:470:1f09:207::14"
    - "2001:470:1f09:207::15"
    - "2001:470:1f09:207::16"
```


### Usage

```
traceroute spoofer 0.1.0
Ben Simms <ben@bensimms.moe>
Replies to traceroutes with different source IPs depending on the TTL on arrival.

USAGE:
    funny-traceroute-aya --cfg <cfg> --iface <iface> --path <path>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -c, --cfg <cfg>
    -i, --iface <iface>
    -p, --path <path>
```

### Building

## Prerequisites

1. Install a rust stable toolchain: `rustup install stable`
1. Install a rust nightly toolchain: `rustup install nightly`
1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag

## Build Userspace

```bash
cargo build
```

## Run

```bash
sudo ./target/release/funny-traceroute-aya --path ./target/bpfel-unknown-none/release/funny-traceroute-aya --iface <interface> --cfg config.yaml
```
