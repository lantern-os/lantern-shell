//! `lantern-launcher` — [RFC-0029](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0029-a-confined-launcher.md)'s launcher: it builds an
//! app's process from a signed package, through system calls alone, when a person asks at the console, and reclaims it
//! when it ends. See `lib.rs` for what it decides.
//!
//! It holds:
//!
//! - an `Untyped` for apps' memory, which it splits into one 18 MiB child per app slot;
//! - its own CNode and VSpace, to copy pages in through a scratch mapping;
//! - the runtime's ELF and the package set, read-only;
//! - the binder's endpoint, under the registration badge and under each app slot's badge, none of which it can mint;
//! - each app slot's keystore and store channel Frames, which boot mapped into the services, and nothing else of theirs;
//! - the shell's notification, under the bits it may signal, and the page it shares with the shell.
//!
//! **An app is a fresh `confined-runtime`**: the runtime's ELF copied into 2 MiB Frames, a stack, a heap, a 3-megapage
//! arena, a private copy of its package, and its slot's channel for the one interface it asks for. All of it comes from
//! the slot, and none of it from anything a service or another app uses. The binder learns which package the slot runs
//! (`REGISTER`) before the runtime's first instruction, and verifies that package itself.
//!
//! **When the app ends**, by its own report or by a fault, the launcher has the binder end its grants (`UNREGISTER`),
//! `Reset`s the slot, which destroys everything made from it (RFC-0030), clears its channels, and only then tells the
//! shell. With the `HOLD` flag (boot's `launcher-hold-test` feature), it keeps ended apps resident instead, so a test can
//! fill every slot.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use alloc::vec::Vec;

use lantern_abi::grant::{self, APP_SLOTS, INTERFACE_KEYSTORE};
use lantern_abi::launcher::{self, bit, outcome, Command, Reply};
use lantern_abi::sys::{self, cnode, frame, retype, tcb, untyped};
use lantern_abi::wire::{MapPerms, Rights};
use lantern_launcher::{copies_into, plan_megapages, Catalog, Entry, Slot, Slots, MEGA};

lantern_abi::entry!(run);

// Granted by the loader (`lantern-boot/src/system/loader.rs`).
const MEMORY: usize = 1;
const SELF_CNODE: usize = 2;
const SELF_VSPACE: usize = 3;
const NOTIFY: usize = 4;
const REGISTER: usize = 5;
const APP_BINDER: usize = 6;
const SHELL_REPLIED: usize = 10;
const SHELL_ENDED: usize = 11;
const SHELL_FAILED: usize = 15;
const KS_CHANNEL: usize = 19;
const ST_CHANNEL: usize = 23;
// Its own.
const SLOT: usize = 27;
const DONE: usize = 31;
const FAILED: usize = 35;
const FAULT: usize = 39;
const TCB: usize = 43;
/// Where each build's capabilities live until the app starts; after that only the TCB's is kept.
const B_VSPACE: usize = 50;
const B_CNODE: usize = 51;
const B_SCHED: usize = 52;
const B_TCB: usize = 53;
const B_PARK: usize = 54;
const B_ELF: usize = 55;
const B_STACK: usize = 59;
const B_HEAP: usize = 60;
const B_ARENA: usize = 61;
const B_PACKAGE: usize = 64;
const BUILD_SLOTS: core::ops::Range<usize> = B_VSPACE..B_PACKAGE + 1;

/// Its own addresses.
const HEAP_BASE: usize = 0x8620_0000;
const HEAP_LEN: usize = 0x20_0000;
const RUNTIME_VADDR: usize = 0x8a00_0000;
const COMMAND_VADDR: usize = 0x9000_0000;
const SCRATCH_VADDR: usize = 0x9200_0000;
const SMALL_SCRATCH_VADDR: usize = 0x9400_0000;

/// What `confined-runtime` expects (`lantern-runtime/confined-runtime/src/lib.rs`, `lantern-boot/src/launch.rs`).
const APP_STACK_VADDR: usize = 0x8600_0000;
const APP_HEAP_VADDR: usize = 0x8620_0000;
const APP_PACKAGE_VADDR: usize = 0x8c00_0000;
const APP_FRAME_VADDR: usize = 0x9000_0000;
const APP_ENDPOINT: usize = 1;
const APP_SUCCESS: usize = 3;
const APP_FAILURE: usize = 4;
const APP_SELF_VSPACE: usize = 6;
const APP_ARENA: usize = 7;
const APP_ARENA_MEGAPAGES: usize = 3;
const APP_PARK: usize = 12;

/// The VSpace's root, then the runtime's megapages, stack, heap, arena and package: 9 × 2 MiB.
const SLOT_BYTES: usize = 9 * MEGA;

fn run(arg0: usize) -> ! {
    // SAFETY: the loader mapped `HEAP_BASE..+HEAP_LEN` read/write into this program's own VSpace.
    unsafe { lantern_abi::rt::init_heap(HEAP_BASE, HEAP_LEN) };
    let hold = arg0 & launcher::HOLD != 0;
    let count = (arg0 & 0xff).min(launcher::SET_MAX);
    let catalog = Catalog::new((0..count).map(|i| launcher::set_entry(set_frame(i))));
    let runtime = launcher::set_entry(runtime_frame()).unwrap_or_default();

    let mut ready = true;
    for app in 0..APP_SLOTS {
        let mints = [(DONE, bit::app_done(app)), (FAILED, bit::app_failed(app)), (FAULT, bit::app_fault(app))];
        for (base, badge) in mints {
            ready &= cnode::mint(SELF_CNODE, NOTIFY, base + app, badge, Rights::WRITE).is_ok();
        }
        ready &= untyped::child(MEMORY, SLOT + app, SLOT_BYTES).is_ok();
    }
    let mut slots = Slots::default();
    loop {
        let bits = sys::wait(NOTIFY).unwrap_or(0);
        for app in 0..APP_SLOTS {
            let failed = bits & (bit::app_failed(app) | bit::app_fault(app)) != 0;
            if failed || bits & bit::app_done(app) != 0 {
                ended(&mut slots, app, failed, hold);
            }
        }
        if bits & bit::COMMAND != 0 {
            command(&catalog, runtime, &mut slots, ready);
        }
    }
}

fn set_frame(i: usize) -> &'static [u8] {
    // SAFETY: the loader mapped each of the set's Frames read-only, consecutively, at `SET_VADDR`, for this program's
    // whole life.
    unsafe { core::slice::from_raw_parts((launcher::SET_VADDR + i * launcher::SET_STRIDE) as *const u8, launcher::SET_STRIDE) }
}

fn runtime_frame() -> &'static [u8] {
    // SAFETY: as `set_frame`'s, for the runtime's ELF, in the set's format, at `RUNTIME_VADDR`.
    unsafe { core::slice::from_raw_parts(RUNTIME_VADDR as *const u8, launcher::SET_STRIDE) }
}

fn command_page() -> &'static mut [u8] {
    // SAFETY: the loader mapped the 4 KiB page shared with the shell read/write at `COMMAND_VADDR`. Only one command is
    // outstanding, and the shell doesn't touch the page until this program signals `REPLIED`.
    unsafe { core::slice::from_raw_parts_mut(COMMAND_VADDR as *mut u8, 4096) }
}

fn command(catalog: &Catalog, runtime: &[u8], slots: &mut Slots, ready: bool) {
    let page = command_page();
    let (op, name) = match launcher::decode_command(&page[launcher::COMMAND_OFFSET..][..launcher::COMMAND_LEN]) {
        Some(Command { op, name }) => (op, Vec::from(name)),
        None => (0, Vec::new()),
    };
    let reply = |outcome, app, entries: &[(&[u8], &[u8])]| {
        launcher::encode_reply(Reply { outcome, app, count: 0 }, entries, &mut command_page()[launcher::REPLY_OFFSET..]);
    };
    match op {
        launcher::OP_LIST => {
            let entries: Vec<(&[u8], &[u8])> =
                catalog.entries.iter().map(|e| (e.name.as_bytes(), e.description.as_bytes())).collect();
            reply(outcome::OK, 0, &entries);
        }
        launcher::OP_RUN => match catalog.find(&name) {
            None => reply(outcome::UNKNOWN, 0, &[]),
            Some(_) if !ready => reply(outcome::FAILED, 0, &[]),
            Some(entry) => match slots.free().and_then(|app| start(app, entry, runtime).map(|()| app)) {
                Ok(app) => {
                    slots.slots[app] = Slot::Running { package: entry.index };
                    reply(outcome::OK, app as u8, &[]);
                }
                Err(why) => reply(why, 0, &[]),
            },
        },
        _ => reply(outcome::INVALID, 0, &[]),
    }
    let _ = sys::signal(SHELL_REPLIED);
}

/// Builds `entry`'s app in slot `app`, registers it, and starts it. On any failure, nothing of it is left: the slot is
/// `Reset`, which also empties this program's build slots, since everything in them was made from it.
fn start(app: usize, entry: &Entry, runtime: &[u8]) -> Result<(), u8> {
    let built = build(app, entry, runtime);
    let registered = built.and_then(|()| match grant::register(REGISTER, app, entry.index) {
        Ok(lantern_abi::frame::status::OK) => Ok(()),
        _ => Err(outcome::UNVERIFIED),
    });
    let started = registered.and_then(|()| {
        let configured = sys::tcb_configure(B_TCB, B_CNODE, B_SCHED, B_VSPACE).is_ok()
            && cnode::move_cap(SELF_CNODE, B_TCB, TCB + app).is_ok();
        if configured {
            Ok(())
        } else {
            let _ = grant::unregister(REGISTER, app);
            Err(outcome::FAILED)
        }
    });
    if started.is_err() {
        let _ = untyped::reset(SELF_CNODE, SLOT + app);
    }
    // The app's objects outlive these capabilities: each is reachable through its own VSpace, CNode or TCB, and its
    // slot's `Reset` destroys them all.
    for slot in BUILD_SLOTS {
        let _ = cnode::delete(SELF_CNODE, slot);
    }
    started
}

fn build(app: usize, entry: &Entry, runtime: &[u8]) -> Result<(), u8> {
    let memory = SLOT + app;
    let no_memory = |_| outcome::NO_MEMORY;
    let (pc, pages) = plan_megapages(runtime).ok_or(outcome::FAILED)?;
    retype::vspace(memory, B_VSPACE).map_err(no_memory)?;

    let rw = MapPerms::READ.union(MapPerms::WRITE).union(MapPerms::USER);
    for (i, page) in pages.iter().enumerate() {
        let cap = B_ELF + i;
        retype::frame_mega(memory, cap).map_err(no_memory)?;
        fill(cap, |dest| {
            for (at, from, len) in copies_into(runtime, page.vaddr) {
                dest[at..at + len].copy_from_slice(&runtime[from..from + len]);
            }
        })?;
        let perms = MapPerms(page.perms | MapPerms::USER.bits());
        frame::map(cap, B_VSPACE, page.vaddr, perms).map_err(no_memory)?;
    }
    for (cap, vaddr) in [(B_STACK, APP_STACK_VADDR), (B_HEAP, APP_HEAP_VADDR)] {
        retype::frame_mega(memory, cap).map_err(no_memory)?;
        frame::map(cap, B_VSPACE, vaddr, rw).map_err(no_memory)?;
    }
    for i in 0..APP_ARENA_MEGAPAGES {
        retype::frame_mega(memory, B_ARENA + i).map_err(no_memory)?;
    }
    // Its own copy of its package: the set's Frames are the binder's and this program's alone.
    let package = launcher::set_entry(set_frame(entry.index)).ok_or(outcome::FAILED)?;
    retype::frame_mega(memory, B_PACKAGE).map_err(no_memory)?;
    fill(B_PACKAGE, |dest| dest[..package.len()].copy_from_slice(package))?;
    frame::map(B_PACKAGE, B_VSPACE, APP_PACKAGE_VADDR, MapPerms::READ.union(MapPerms::USER)).map_err(no_memory)?;
    // The slot's channel for the one interface it asks for, cleared when the last app in this slot ended.
    let channel = if entry.interface == INTERFACE_KEYSTORE { KS_CHANNEL + app } else { ST_CHANNEL + app };
    frame::map(channel, B_VSPACE, APP_FRAME_VADDR, rw).map_err(no_memory)?;

    retype::cnode(memory, B_CNODE).map_err(no_memory)?;
    retype::notification(memory, B_PARK).map_err(no_memory)?;
    let mut grants = alloc::vec![
        (APP_BINDER + app, APP_ENDPOINT),
        (DONE + app, APP_SUCCESS),
        (FAILED + app, APP_FAILURE),
        (B_VSPACE, APP_SELF_VSPACE),
        (B_PARK, APP_PARK),
    ];
    grants.extend((0..APP_ARENA_MEGAPAGES).map(|i| (B_ARENA + i, APP_ARENA + i)));
    for (src, dest) in grants {
        cnode::copy_cross(B_CNODE, SELF_CNODE, src, dest).map_err(|_| outcome::FAILED)?;
    }
    retype::sched_context(memory, B_SCHED).map_err(no_memory)?;
    retype::tcb(memory, B_TCB).map_err(no_memory)?;
    tcb::set_fault_notification(B_TCB, FAULT + app).map_err(|_| outcome::FAILED)?;
    let arg0 = entry.len | grant::WITH_CONSENT;
    tcb::set_entry(B_TCB, pc, APP_STACK_VADDR + MEGA, arg0).map_err(|_| outcome::FAILED)?;
    Ok(())
}

/// Maps the 2 MiB Frame at `cap` into this program's scratch address, lets `write` fill it, and unmaps it. The kernel
/// zeroed it when it was retyped (RFC-0030), so only what `write` writes isn't zero.
fn fill(cap: usize, write: impl FnOnce(&mut [u8])) -> Result<(), u8> {
    let rw = MapPerms::READ.union(MapPerms::WRITE).union(MapPerms::USER);
    frame::map(cap, SELF_VSPACE, SCRATCH_VADDR, rw).map_err(|_| outcome::NO_MEMORY)?;
    // SAFETY: the Frame is mapped read/write at `SCRATCH_VADDR` just above, here only, until the unmap below.
    write(unsafe { core::slice::from_raw_parts_mut(SCRATCH_VADDR as *mut u8, MEGA) });
    frame::unmap(cap, SELF_VSPACE).map_err(|_| outcome::FAILED)
}

/// App slot `app`'s app ended. Unless holding, its grants end, its slot is reclaimed, and its channels are cleared,
/// before the shell is told.
fn ended(slots: &mut Slots, app: usize, failed: bool, hold: bool) {
    let Slot::Running { package } = slots.slots[app] else { return };
    if hold {
        slots.slots[app] = Slot::Held { package };
    } else {
        let _ = grant::unregister(REGISTER, app);
        let _ = sys::cnode::delete(SELF_CNODE, TCB + app);
        let _ = untyped::reset(SELF_CNODE, SLOT + app);
        for channel in [KS_CHANNEL + app, ST_CHANNEL + app] {
            clear(channel);
        }
        slots.slots[app] = Slot::Free;
    }
    let _ = sys::signal(if failed { SHELL_FAILED + app } else { SHELL_ENDED + app });
}

/// Zeroes a 4 KiB channel Frame, so the next app in its slot never sees what the last one, or its service, left in it.
/// The `Reset` that ended the app removed its mapping, so this program can map it beside the service's.
fn clear(channel: usize) {
    let rw = MapPerms::READ.union(MapPerms::WRITE).union(MapPerms::USER);
    if frame::map(channel, SELF_VSPACE, SMALL_SCRATCH_VADDR, rw).is_ok() {
        // SAFETY: mapped read/write at `SMALL_SCRATCH_VADDR` just above, until the unmap below.
        unsafe { core::ptr::write_bytes(SMALL_SCRATCH_VADDR as *mut u8, 0, 4096) };
        let _ = frame::unmap(channel, SELF_VSPACE);
    }
}
