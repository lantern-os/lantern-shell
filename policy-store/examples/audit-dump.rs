//! `audit-dump <flash image> [--kept COUNT HEAD] [--forge-drop INDEX OUT]`
//!
//! Reads the audit log ([RFC-0024](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0024-audit-log.md)) from a `virt.flash1`
//! image without changing it: one line per record, then `chain ok`, or `CORRUPT`, which the store itself
//! would treat the same way.
//!
//! - `--kept COUNT HEAD`: also checks that the first COUNT records still chain to HEAD, a head recorded
//!   earlier. This is how a log rewritten consistently from outside is caught.
//! - `--forge-drop INDEX OUT`: writes to OUT what an attacker able to write the flash could: the same log
//!   with one record removed and the chain recomputed. `binder-matrix.sh` uses it to keep RFC-0024's known
//!   limit visible.
//!
//! Run on the host: `cargo run --example audit-dump --target x86_64-unknown-linux-gnu -- <image>`.

use std::cell::RefCell;

use lantern_abi::policy::{event, reason, AuditEntry};
use lantern_policy_store::audit::{scan, verify_prefix, AuditLog};
use lantern_policy_store::Flash;

/// The first megapage of the image: what the store maps.
const MAPPED_BYTES: usize = 0x20_0000;

struct Image(RefCell<Vec<u32>>);

impl Flash for &Image {
    fn read(&self, word: usize) -> u32 {
        self.0.borrow()[word]
    }
    fn program(&mut self, word: usize, value: u32) {
        self.0.borrow_mut()[word] &= value;
    }
}

fn load(path: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("reading {path}: {e}"))
}

fn words(bytes: &[u8]) -> Image {
    Image(RefCell::new(bytes[..MAPPED_BYTES].chunks(4).map(|w| u32::from_le_bytes(w.try_into().unwrap())).collect()))
}

fn name(event: u8) -> &'static str {
    match event {
        event::BOOT => "BOOT",
        event::GRANTING => "GRANTING",
        event::GRANT_FAILED => "GRANT_FAILED",
        event::DECLINED => "DECLINED",
        event::REVOKING => "REVOKING",
        _ => "UNKNOWN",
    }
}

fn reason_name(reason: u8) -> &'static str {
    match reason {
        reason::NONE => "-",
        reason::UNVERIFIED_PACKAGE => "UNVERIFIED_PACKAGE",
        reason::NOT_DECLARED => "NOT_DECLARED",
        reason::NOT_IN_POLICY => "NOT_IN_POLICY",
        reason::OPS_EXCEED_POLICY => "OPS_EXCEED_POLICY",
        reason::REVOKED => "REVOKED",
        reason::STORE_UNAVAILABLE => "STORE_UNAVAILABLE",
        _ => "UNKNOWN",
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = args.get(1).expect("usage: audit-dump <flash image> [--kept COUNT HEAD] [--forge-drop INDEX OUT]");
    let bytes = load(path);
    let image = words(&bytes);

    let mut entries: Vec<AuditEntry> = Vec::new();
    let scanned = scan(&&image, |sequence, entry| {
        println!(
            "record {sequence} {} {} interface={} slot={} object={} ops={:#x} key={:016x}{:016x}",
            name(entry.event),
            reason_name(entry.reason),
            entry.interface,
            entry.slot,
            entry.object,
            entry.ops,
            entry.key[0],
            entry.key[1],
        );
        entries.push(*entry);
    });
    let Ok((head, _)) = scanned else {
        println!("CORRUPT");
        std::process::exit(1);
    };
    println!("chain ok count={} head={}", head.count, hex(&head.head));

    match args.get(2).map(String::as_str) {
        Some("--kept") => {
            let count: u64 = args[3].parse().expect("COUNT");
            let kept: [u8; 16] = (0..16).map(|i| u8::from_str_radix(&args[4][i * 2..i * 2 + 2], 16).unwrap()).collect::<Vec<_>>().try_into().unwrap();
            let ok = verify_prefix(&&image, count, kept) == Ok(true);
            println!("kept head {}", if ok { "matches" } else { "MISMATCH" });
            std::process::exit(if ok { 0 } else { 3 });
        }
        Some("--forge-drop") => {
            let drop: usize = args[3].parse().expect("INDEX");
            let mut forged = bytes.clone();
            forged[0x4_0000..MAPPED_BYTES].fill(0xff);
            let blank = words(&forged);
            // Opening writes a header and a `BOOT`, as the original's first record was.
            let mut log = AuditLog::open(&blank);
            for (index, entry) in entries.iter().enumerate().skip(1) {
                if index != drop {
                    log.append(entry).expect("forging");
                }
            }
            let out: Vec<u8> = blank.0.borrow().iter().flat_map(|w| w.to_le_bytes()).collect();
            forged[..MAPPED_BYTES].copy_from_slice(&out);
            std::fs::write(&args[4], forged).expect("writing the forged image");
        }
        _ => {}
    }
}
