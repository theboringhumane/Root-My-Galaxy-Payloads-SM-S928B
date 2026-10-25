//! Fetch a byte range from Samsung FUS, decrypt it, and write it to disk.
//!
//! A full AP archive plus its decrypted form needs roughly twice the archive
//! size in free space. This tool exists so a port can grab only the head of the
//! ZIP (local file headers, `boot.img.lz4`, the other images in order) instead
//! of both copies of a multi-gigabyte package.
//!
//! FUS v2 encrypts the whole package as one AES-128-ECB stream, so any range
//! starting on a 16-byte boundary decrypts independently; offset 0 is the only
//! offset used here, and the tail is dropped if the server returns a non-multiple
//! of 16.

use cipher::{inout::InOutBuf, BlockModeDecrypt};
use samloader_fus::FusClient;
use std::io::Read;

struct Args {
    model: String,
    region: String,
    version: String,
    bytes: u64,
    out: String,
}

fn usage() -> ! {
    eprintln!(
        "usage: fusfetch --model SM-S928B --region INS \\\n\
         \x20               --version S928BXXU6EZIF/S928BOXM6EZIF/S928BXXU6EZIF/S928BXXU6EZIF \\\n\
         \x20               [--bytes 268435456] [--out prefix.dec]"
    );
    std::process::exit(2)
}

fn parse_args() -> Args {
    let mut args = Args {
        model: String::new(),
        region: String::new(),
        version: String::new(),
        bytes: 268_435_456,
        out: "prefix.dec".to_string(),
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let value = it.next().unwrap_or_else(|| usage());
        match flag.as_str() {
            "--model" => args.model = value,
            "--region" => args.region = value,
            "--version" => args.version = value,
            "--bytes" => args.bytes = value.parse().unwrap_or_else(|_| usage()),
            "--out" => args.out = value,
            _ => usage(),
        }
    }
    if args.model.is_empty() || args.region.is_empty() || args.version.is_empty() {
        usage();
    }
    args
}

fn main() {
    let args = parse_args();
    let mut client = FusClient::new().expect("FUS client");
    client.fetch_binary_info(&args.model, &args.region, &args.version);
    println!(
        "file={} size={} version={}",
        client.info.filename, client.info.size, client.info.version
    );

    let want = args.bytes.min(client.info.size);
    client.init_download().expect("init download");
    let response = client
        .download_file(Some(0), Some(want - 1))
        .expect("range GET");
    println!("status={} requested={}", response.status(), want);

    // take() bounds the read even when the server ignores the Range header.
    let mut buf = Vec::with_capacity(want as usize);
    response.take(want).read_to_end(&mut buf).expect("read body");
    let usable = buf.len() / 16 * 16;
    buf.truncate(usable);
    println!("downloaded={} decrypting={}", buf.len(), usable);

    let mut decryptor = client.get_decryptor();
    let (blocks, _tail) = InOutBuf::from(&mut buf[..]).into_chunks();
    decryptor.decrypt_blocks_inout(blocks);

    match buf.get(..4) {
        Some(b"PK\x03\x04") => println!("plaintext starts with a ZIP local file header"),
        Some(other) => println!("warning: unexpected plaintext prefix {:02x?}", other),
        None => println!("warning: nothing decrypted"),
    }

    std::fs::write(&args.out, &buf).expect("write");
    println!("wrote {} bytes to {}", buf.len(), args.out);
}
