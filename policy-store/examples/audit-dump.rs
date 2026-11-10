//! `audit-dump <flash image> [--kept COUNT HEAD | --forge-drop INDEX OUT | --fill N OUT]`
//!
//! Reads the audit log ([RFC-0024](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0024-audit-log.md),
//! [RFC-0025](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0025-audit-log-service-operations.md)) from a `virt.flash1` image
//! without changing it: one line per surviving record, then `chain ok`, or `CORRUPT`, which the store itself
//! would treat the same way. `oldest` says how much history retention has retired.
//!
//! Then, for each grant, one `grant` line joining the role (`GRANTING`), the badge (`GRANTED` or
//! `SERVICE_GRANTED`) and every use recorded under that badge in the same boot.
//!
//! - `--kept COUNT HEAD`: also checks a head recorded earlier: `matches`, `MISMATCH`, or `RETIRED` when that
//!   history is gone and nobody can check it. A log rewritten consistently from outside is caught this way.
//! - `--forge-drop INDEX OUT`: writes to OUT what an attacker able to write the flash could: the same log
//!   with one record removed and the chain recomputed. `binder-matrix.sh` uses it to keep RFC-0024's known
//!   limit visible. Only for a log with nothing retired.
//! - `--fill N OUT`: writes to OUT the same log with N more `BOOT` records, so the matrix can reach
//!   retention without running for hours.
//!
//! Run on the host: `cargo run --example audit-dump --target x86_64-unknown-linux-gnu -- <image>`.

use std::cell::RefCell;

use lantern_abi::frame::status;
use lantern_abi::policy::{event, reason, AuditEntry};
use lantern_policy_store::audit::{scan, verify_prefix, AuditLog, Kept};
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
    fn erase_sector(&mut self, first: usize, words: usize) {
        self.0.borrow_mut()[first..first + words].fill(u32::MAX);
    }
}

fn load(path: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("reading {path}: {e}"))
}

fn words(bytes: &[u8]) -> Image {
    Image(RefCell::new(bytes[..MAPPED_BYTES].chunks(4).map(|w| u32::from_le_bytes(w.try_into().unwrap())).collect()))
}

fn save(image: &Image, original: &[u8], path: &str) {
    let mut out = original.to_vec();
    let mapped: Vec<u8> = image.0.borrow().iter().flat_map(|w| w.to_le_bytes()).collect();
    out[..MAPPED_BYTES].copy_from_slice(&mapped);
    std::fs::write(path, out).unwrap_or_else(|e| panic!("writing {path}: {e}"));
}

fn name(event: u8) -> &'static str {
    match event {
        event::BOOT => "BOOT",
        event::GRANTING => "GRANTING",
        event::GRANT_FAILED => "GRANT_FAILED",
        event::DECLINED => "DECLINED",
        event::REVOKING => "REVOKING",
        event::GRANTED => "GRANTED",
        event::SERVICE_GRANTED => "SERVICE_GRANTED",
        event::USING => "USING",
        event::USE_FAILED => "USE_FAILED",
        event::QUOTA_REACHED => "QUOTA_REACHED",
        event::RETIRED => "RETIRED",
        _ => "UNKNOWN",
    }
}

/// A decline's reason, or for `USE_FAILED`, and a `QUOTA_REACHED` that replaced one, the operation's RFC-0019
/// status.
fn reason_name(entry: &AuditEntry) -> &'static str {
    if entry.event == event::USE_FAILED || entry.event == event::QUOTA_REACHED && entry.slot == event::USE_FAILED {
        return match entry.reason as u16 {
            status::ACCESS => "ACCESS",
            status::INVALID => "INVALID",
            status::FAILED => "FAILED",
            status::BUSY => "BUSY",
            _ => "UNKNOWN",
        };
    }
    match entry.reason {
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

/// One grant this dump could follow: its role if the binder made it, and the badge's uses.
struct Grant {
    boot: usize,
    interface: u8,
    badge: u64,
    role: Option<[u64; 2]>,
    uses: Vec<String>,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = args.get(1).expect("usage: audit-dump <flash image> [--kept COUNT HEAD | --forge-drop INDEX OUT | --fill N OUT]");
    let bytes = load(path);
    let image = words(&bytes);

    let mut entries: Vec<AuditEntry> = Vec::new();
    let mut grants: Vec<Grant> = Vec::new();
    let mut boot = 0;
    // The last `GRANTING` per (interface, slot) this boot, for its `GRANTED` to name the role.
    let mut granting: Vec<(u8, u8, [u64; 2])> = Vec::new();
    let scanned = scan(&&image, |sequence, entry| {
        println!(
            "record {sequence} {} {} interface={} slot={} object={} ops={:#x} subject={:016x}{:016x}",
            name(entry.event),
            reason_name(entry),
            entry.interface,
            entry.slot,
            entry.object,
            entry.ops,
            entry.subject[0],
            entry.subject[1],
        );
        entries.push(*entry);
        match entry.event {
            event::BOOT => {
                boot += 1;
                granting.clear();
            }
            event::GRANTING => granting.push((entry.interface, entry.slot, entry.subject)),
            event::GRANTED | event::SERVICE_GRANTED => {
                let role = (entry.event == event::GRANTED)
                    .then(|| granting.iter().rev().find(|g| (g.0, g.1) == (entry.interface, entry.slot)).map(|g| g.2))
                    .flatten();
                grants.push(Grant { boot, interface: entry.interface, badge: entry.subject[0], role, uses: Vec::new() });
            }
            event::USING | event::USE_FAILED => {
                let use_ = if entry.event == event::USING {
                    format!("{:#x}", entry.ops)
                } else {
                    format!("failed:{}", reason_name(entry))
                };
                match grants.iter_mut().rev().find(|g| (g.boot, g.interface, g.badge) == (boot, entry.interface, entry.subject[0])) {
                    Some(grant) => grant.uses.push(use_),
                    None => println!("UNLINKED record {sequence}: no grant this boot for interface={} badge={}", entry.interface, entry.subject[0]),
                }
            }
            _ => {}
        }
    });
    let Ok(scanned) = scanned else {
        println!("CORRUPT");
        std::process::exit(1);
    };
    let head = scanned.head;
    println!("chain ok count={} head={}", head.count, hex(&head.head));
    println!("oldest {} previous={}", head.oldest, hex(&head.oldest_previous));
    for grant in &grants {
        let role = grant.role.map_or(String::from("service"), |r| format!("{:016x}{:016x}", r[0], r[1]));
        println!(
            "grant boot={} interface={} badge={} role={role} uses={}",
            grant.boot,
            grant.interface,
            grant.badge,
            if grant.uses.is_empty() { String::from("-") } else { grant.uses.join(",") }
        );
    }

    match args.get(2).map(String::as_str) {
        Some("--kept") => {
            let count: u64 = args[3].parse().expect("COUNT");
            let kept: [u8; 16] = (0..16).map(|i| u8::from_str_radix(&args[4][i * 2..i * 2 + 2], 16).unwrap()).collect::<Vec<_>>().try_into().unwrap();
            let verdict = verify_prefix(&&image, count, kept);
            println!(
                "kept head {}",
                match verdict {
                    Ok(Kept::Matches) => "matches",
                    Ok(Kept::Retired) => "RETIRED",
                    _ => "MISMATCH",
                }
            );
            std::process::exit(match verdict {
                Ok(Kept::Matches) => 0,
                Ok(Kept::Retired) => 4,
                _ => 3,
            });
        }
        Some("--forge-drop") => {
            assert_eq!(head.oldest, 0, "forging is only for a log with nothing retired");
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
            save(&blank, &forged, &args[4]);
        }
        Some("--fill") => {
            let n: u64 = args[3].parse().expect("N");
            // Opening appends a `BOOT` of its own, which counts as one of the N.
            let mut log = AuditLog::open(&image);
            for _ in 1..n {
                log.append(&AuditEntry { event: event::BOOT, ..AuditEntry::default() }).expect("filling");
            }
            save(&image, &bytes, &args[4]);
        }
        _ => {}
    }
}
