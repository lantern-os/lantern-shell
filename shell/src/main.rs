//! `lantern-shell` — [RFC-0026](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0026-trusted-path-and-consent.md)'s shell: **the only program
//! that reaches the console**, so everything a person reads there comes from here, and everything they type comes here.
//!
//! It holds the UART's 4 KiB page and its `IrqHandler`, the launch binder's control capability (list, revoke, remembered
//! decisions), the audit log's read-only capability, and four capabilities to the binder's answer notification, one per
//! answer. It mints nothing and holds no service endpoint: it can answer the binder, which still holds every granter
//! capability, and nothing more. A compromised shell can say yes to anything within the binder's ceiling, and no further.
//!
//! **It waits on one notification**, by badge bit (`consent::bit`): a keystroke, the binder asking, or the app finishing.
//! While a request is open, the binder is waiting for the answer, so commands that call the binder are refused rather than
//! deadlocking: the console takes only an answer.
//!
//! What it shows of an app's text goes through `lantern_shell::sanitized` (see `lib.rs`).

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::fmt::Write;

use lantern_abi::consent::{self, bit, Answer};
use lantern_abi::frame::status;
use lantern_abi::grant;
use lantern_abi::policy::{self, decision};
use lantern_abi::sys::{self, irq};
use lantern_policy_store::audit::chain;
use lantern_shell::{
    event_name, interface_name, parse_answer, parse_command, reason_name, sanitized, write_prompt, Command, Key, LineEditor,
    Ops, HELP, LINE_MAX,
};

const IRQ_CPTR: usize = 1;
/// This program's notification, to wait on.
const NOTIFY_CPTR: usize = 2;
/// The same notification, badged `bit::CONSOLE`, for binding the UART's line.
const CONSOLE_BIT_CPTR: usize = 3;
/// The binder's endpoint under `CONTROL_BADGE`.
const CONTROL_CPTR: usize = 4;
/// The policy store under `READER_BADGE`.
const READER_CPTR: usize = 5;
/// The binder's answer notification, badged once each: `Answer::AllowOnce`, `AllowAlways`, `Deny`, `DenyAlways`.
const ANSWER_CPTR_BASE: usize = 6;

/// Must equal the system loader's: the UART's page, and the consent `Frame` shared with the binder.
const UART_VADDR: usize = 0x9500_0000;
const CONSENT_VADDR: usize = 0x9000_0000;

/// The binder's ledger size, `launch-binder`'s `MAX_BINDS`.
const LEDGER_SIZE: usize = 4;
/// Most remembered decisions `decisions` lists.
const DECISIONS_MAX: usize = 64;

const RBR_THR: usize = 0;
const IER: usize = 1;
const LSR: usize = 5;
const IER_RX_AVAILABLE: u8 = 1 << 0;
const LSR_DATA_READY: u8 = 1 << 0;
const LSR_THR_EMPTY: u8 = 1 << 5;

lantern_abi::entry!(run);

fn uart_read(offset: usize) -> u8 {
    // SAFETY: the loader mapped the UART's 4 KiB page read/write at UART_VADDR for this program's whole life, and no other
    // program maps it. These are its byte registers.
    unsafe { core::ptr::read_volatile((UART_VADDR + offset) as *const u8) }
}

fn uart_write(offset: usize, value: u8) {
    // SAFETY: as `uart_read`.
    unsafe { core::ptr::write_volatile((UART_VADDR + offset) as *mut u8, value) }
}

/// The console. Only this program writes to it.
struct Console;

impl Console {
    fn byte(byte: u8) {
        while uart_read(LSR) & LSR_THR_EMPTY == 0 {}
        uart_write(RBR_THR, byte);
    }
}

impl Write for Console {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for byte in s.bytes() {
            if byte == b'\n' {
                Console::byte(b'\r');
            }
            Console::byte(byte);
        }
        Ok(())
    }
}

fn names() -> (&'static [u8], &'static [u8]) {
    // SAFETY: the loader mapped the consent `Frame` at CONSENT_VADDR for this program's whole life. The binder writes the
    // names half only while answering this program's own `Call`, so it isn't changing while this reads it.
    let half = unsafe { core::slice::from_raw_parts((CONSENT_VADDR + consent::NAMES_OFFSET) as *const u8, consent::NAMES_LEN) };
    consent::decode_names(half).unwrap_or((b"", b""))
}

fn asked() -> Option<consent::Ask<'static>> {
    // SAFETY: as `names`. The binder wrote the request half before signalling, and waits for the answer, so it isn't
    // changing while this reads it.
    let half = unsafe { core::slice::from_raw_parts((CONSENT_VADDR + consent::ASK_OFFSET) as *const u8, consent::ASK_LEN) };
    consent::decode_ask(half)
}

fn run(_arg0: usize) -> ! {
    let mut out = Console;
    let bound = irq::set_notification(IRQ_CPTR, CONSOLE_BIT_CPTR).is_ok();
    uart_write(IER, IER_RX_AVAILABLE);
    let _ = write!(out, "\nLanternOS. This console is the shell's alone: no app can write to it.\nType help for commands.\n");
    if !bound {
        let _ = writeln!(out, "lantern: the console's interrupt couldn't be bound; typing won't work.");
    }
    let _ = out.write_str("> ");

    let mut editor = LineEditor::default();
    let mut asking = false;
    loop {
        let bits = sys::wait(NOTIFY_CPTR).unwrap_or(0);
        if bits & bit::ASK != 0 {
            match asked() {
                Some(ask) => {
                    let _ = write_prompt(&mut out, &ask);
                    asking = true;
                }
                None => {
                    // The binder is waiting: it must get an answer, and the only safe one is no.
                    answer(Answer::Deny);
                    let _ = out.write_str("\nlantern: a request couldn't be read, and was refused.\n> ");
                }
            }
        }
        if bits & bit::CONSOLE != 0 {
            while uart_read(LSR) & LSR_DATA_READY != 0 {
                match editor.feed(uart_read(RBR_THR)) {
                    Key::Echo(byte) => Console::byte(byte),
                    Key::Erase => {
                        let _ = out.write_str("\x08 \x08");
                    }
                    Key::Enter => {
                        let _ = out.write_str("\n");
                        let mut line = [0; LINE_MAX];
                        let len = editor.take(&mut line);
                        asking = handle_line(&mut out, &line[..len], asking);
                    }
                    Key::Ignore => {}
                }
            }
            let _ = irq::ack(IRQ_CPTR);
        }
        if bits & bit::SYSTEM_FAILED != 0 {
            let _ = write!(out, "\nlantern: a system service stopped with an error. Grants may be refused from now on.\n> ");
        }
        if bits & (bit::APP_DONE | bit::APP_FAILED) != 0 {
            let how = if bits & bit::APP_FAILED != 0 { "stopped with an error" } else { "finished" };
            let _ = write!(out, "\nlantern: the app {how}.\n{}", if asking { "allow? > " } else { "> " });
        }
    }
}

fn answer(answer: Answer) {
    let index = [Answer::AllowOnce, Answer::AllowAlways, Answer::Deny, Answer::DenyAlways].iter().position(|&a| a == answer);
    if let Some(index) = index {
        let _ = sys::signal(ANSWER_CPTR_BASE + index);
    }
}

/// One typed line. Returns whether a request is still open.
fn handle_line(out: &mut Console, line: &[u8], asking: bool) -> bool {
    if asking {
        let Some(chosen) = parse_answer(line) else {
            let _ = out.write_str("         please answer y, a, n or e > ");
            return true;
        };
        answer(chosen);
        let said = match chosen {
            Answer::AllowOnce => "allowed, this time",
            Answer::AllowAlways => "allowed, and remembered",
            Answer::Deny => "refused, this time",
            Answer::DenyAlways => "refused, and remembered",
        };
        let _ = write!(out, "lantern: {said}.\n> ");
        return false;
    }
    match parse_command(line) {
        Command::Empty => {}
        Command::Help => {
            let _ = out.write_str(HELP);
        }
        Command::Grants => grants(out),
        Command::Revoke(index) => {
            let said = match grant::revoke(CONTROL_CPTR, index) {
                Ok(status::OK) => "revoked: it ends now, and the app will be asked again next time",
                Ok(status::INVALID) => "there's no grant with that number",
                Ok(status::FAILED) => "revoked now, but its remembered \"always\" couldn't be forgotten",
                _ => "the revocation failed",
            };
            let _ = writeln!(out, "lantern: grant {index}: {said}.");
        }
        Command::Decisions => decisions(out),
        Command::Forget(index) => {
            let said = match grant::forget(CONTROL_CPTR, index) {
                Ok(status::OK) => "forgotten: you'll be asked next time",
                Ok(status::INVALID) => "there's no remembered answer with that number",
                _ => "it couldn't be forgotten",
            };
            let _ = writeln!(out, "lantern: answer {index}: {said}.");
        }
        Command::Audit(count) => audit(out, count),
        Command::Unknown => {
            let _ = out.write_str("lantern: unknown command; type help.\n");
        }
    }
    let _ = out.write_str("> ");
    false
}

fn grants(out: &mut Console) {
    let mut any = false;
    for index in 0..LEDGER_SIZE {
        match grant::list(CONTROL_CPTR, index) {
            Ok(Some(g)) => {
                any = true;
                let (app, role) = names();
                let _ = writeln!(
                    out,
                    "  {index}  \"{}\" {} role \"{}\": {}{}",
                    sanitized(app),
                    interface_name(g.interface),
                    sanitized(role),
                    Ops { interface: g.interface, bits: g.ops },
                    if g.revoked { "  (revoked)" } else { "" }
                );
            }
            Ok(None) => {}
            Err(_) => {
                let _ = out.write_str("lantern: the binder couldn't be reached.\n");
                return;
            }
        }
    }
    if !any {
        let _ = out.write_str("  no grants\n");
    }
}

fn decisions(out: &mut Console) {
    let mut any = false;
    for index in 0..DECISIONS_MAX {
        match grant::decisions(CONTROL_CPTR, index) {
            Ok(Some(d)) => {
                any = true;
                let said = if d.decision == decision::ALLOW { "always" } else { "never " };
                let (app, role) = names();
                if d.named {
                    let _ = writeln!(out, "  {index}  {said}  \"{}\" role \"{}\"", sanitized(app), sanitized(role));
                } else {
                    let _ = writeln!(out, "  {index}  {said}  (a role of an app not running now)");
                }
            }
            Ok(None) => break,
            Err(_) => {
                let _ = out.write_str("lantern: the binder couldn't be reached.\n");
                return;
            }
        }
    }
    if !any {
        let _ = out.write_str("  no remembered answers\n");
    }
}

/// Verifies the whole chain from the oldest surviving record, then shows the last `count`. The log is shown only if it
/// verifies.
fn audit(out: &mut Console, count: usize) {
    let (Ok((status::OK, total, head)), Ok((status::OK, oldest, previous))) =
        (policy::head(READER_CPTR), policy::oldest(READER_CPTR))
    else {
        let _ = out.write_str("lantern: the audit log can't be read: it's missing or corrupt.\n");
        return;
    };
    let mut chained = previous;
    for index in oldest..total {
        match policy::read(READER_CPTR, index) {
            Ok((status::OK, entry)) => chained = chain(chained, &entry, index),
            _ => {
                let _ = writeln!(out, "lantern: the audit log couldn't be read at record {index}.");
                return;
            }
        }
    }
    if chained != head {
        let _ = out.write_str("lantern: the audit log does NOT verify. It isn't shown.\n");
        return;
    }
    let _ = writeln!(out, "  {} records, verified{}", total - oldest, if oldest > 0 { "; older ones retired" } else { "" });
    for index in total.saturating_sub(count as u64).max(oldest)..total {
        if let Ok((status::OK, e)) = policy::read(READER_CPTR, index) {
            let reason = reason_name(e.event, e.reason);
            let _ = write!(out, "  #{index:<6} {:<16}", event_name(e.event));
            if e.interface != 0 {
                let _ = write!(out, " {} {}", interface_name(e.interface), Ops { interface: e.interface, bits: e.ops });
            }
            let _ = writeln!(out, "{}{}", if reason.is_empty() { "" } else { "  " }, reason);
        }
    }
}
