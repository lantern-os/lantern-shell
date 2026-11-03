//! `lantern-grant-control` — [RFC-0021](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0021-grant-ledger-and-revocation.md)'s
//! v0 holder of the launch binder's control capability. **It is a test script standing in for a
//! future shell, not a user interface:** no person sees or decides anything here.
//!
//! When the runtime signals, with a client exchange deliberately left open at the service, it:
//!
//! 1. Lists ledger entry 0, and checks it is the grant it expects, not yet revoked.
//! 2. Checks an empty and an out-of-range index are both reported as such.
//! 3. Sends a stranger's request to the service, which must answer `BUSY`.
//! 4. Revokes entry 0, and checks the ledger now says so.
//! 5. Revokes it again, which must also succeed.
//!
//! Then it signals back. Any failed check signals `FAILURE` instead, with the step in `detail`.
//! Step 4 returning at all shows the service served `REVOKE` during the open exchange.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

use lantern_abi::frame::status;
use lantern_abi::grant;
use lantern_abi::sys;

/// The binder's endpoint, under `CONTROL_BADGE`.
const CONTROL_CPTR: usize = 1;
/// An unbadged copy of the service's endpoint, only for step 3. It reaches nothing else: the
/// service refuses every data request from a badge it never minted.
const STRANGER_CPTR: usize = 2;
/// Shared with the runtime, whose number for it the demos' trap handlers compare against.
const FAILURE_CPTR: usize = 4;
const REQUEST_CPTR: usize = 5;
const DONE_CPTR: usize = 6;

/// `confined-runtime`'s `Stage::Control`, in a `Signal`'s `a1`.
const STAGE_CONTROL: usize = 12;

/// An index no demo fills, and one past the end of the ledger.
const EMPTY_INDEX: usize = 3;
const OUT_OF_RANGE_INDEX: usize = 99;

lantern_abi::entry!(run);

/// `arg0`: the expected entry's interface word, with its ops bits above it.
fn run(arg0: usize) -> ! {
    lantern_abi::rt::report_panics_via(FAILURE_CPTR);
    let _ = sys::wait(REQUEST_CPTR);
    match script((arg0 & 0xff) as u8, (arg0 >> 8) as u8) {
        Ok(()) => {
            let _ = sys::signal(DONE_CPTR);
        }
        Err(step) => {
            let _ = sys::signal_with(FAILURE_CPTR, STAGE_CONTROL, step);
        }
    }
    // Nothing signals this again: parks without spinning.
    loop {
        let _ = sys::wait(REQUEST_CPTR);
    }
}

fn script(interface: u8, ops: u8) -> Result<(), usize> {
    let entry = grant::list(CONTROL_CPTR, 0).map_err(|_| 1usize)?.ok_or(1usize)?;
    if entry.interface != interface || entry.slot != 0 || entry.ops != ops || entry.revoked {
        return Err(1);
    }

    for index in [EMPTY_INDEX, OUT_OF_RANGE_INDEX] {
        if !matches!(grant::list(CONTROL_CPTR, index), Ok(None)) {
            return Err(2);
        }
        if !matches!(grant::revoke(CONTROL_CPTR, index), Ok(status::INVALID)) {
            return Err(2);
        }
    }

    match sys::call_with_label(STRANGER_CPTR, 0, [0, 0, 0]) {
        Ok((_, tag)) if tag.label == status::BUSY as u32 => {}
        _ => return Err(3),
    }

    if !matches!(grant::revoke(CONTROL_CPTR, 0), Ok(status::OK)) {
        return Err(4);
    }
    if !matches!(grant::list(CONTROL_CPTR, 0), Ok(Some(entry)) if entry.revoked) {
        return Err(4);
    }

    if !matches!(grant::revoke(CONTROL_CPTR, 0), Ok(status::OK)) {
        return Err(5);
    }
    Ok(())
}
