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
//!
//! **It asks the launcher to run apps** ([RFC-0029](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0029-a-confined-launcher.md)): `apps`
//! and `run NAME` write a command into the page it shares with the launcher and signal it, and the launcher's reply, and
//! later each app's end, arrive as more bits on the same notification. Only the shell can ask, so a person starts every
//! app. Names and descriptions come from packages, and are sanitized like everything else an app says.
//!
//! **It never claims an answer counted until the binder says so** ([RFC-0028](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0028-deadlines-and-a-capability-clock.md)):
//! a request can time out while the person types. The binder answers each request with `ASK_DONE` (it took the answer) or
//! `ASK_CANCELLED` (it timed out first), and only then does the console say what was decided.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::fmt::Write;

use lantern_abi::consent::{self, bit, Answer};
use lantern_abi::frame::status;
use lantern_abi::grant::{self, APP_SLOTS};
use lantern_abi::launcher::{self, outcome, shell_bit, OP_LIST, OP_RUN};
use lantern_abi::policy::{self, decision, AuditEntry};
use lantern_abi::provenance;
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
/// The launcher's notification, badged `launcher::bit::COMMAND`.
const LAUNCHER_CPTR: usize = 10;
/// The store's endpoint under `provenance::STORE_READER_BADGE`: sizes and provenance, never contents.
const STORE_READER_CPTR: usize = 11;
/// RFC-0034: the store's endpoint under `provenance::STORE_CONSOLE_BADGE`, for `write`, and its channel.
const STORE_CONSOLE_CPTR: usize = 12;
const STORE_CONSOLE_VADDR: usize = 0x9002_0000;
/// RFC-0035: the wallet's endpoint under `identity::READER_BADGE`: what it presented, never a key.
const WALLET_READER_CPTR: usize = 13;
/// The archiver, under its reader badge ([RFC-0038](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0038-signed-models-and-kept-audit-history.md)).
const ARCHIVE_CPTR: usize = 14;

/// Must equal the system loader's: the UART's page, and the consent `Frame` shared with the binder.
const UART_VADDR: usize = 0x9500_0000;
const CONSENT_VADDR: usize = 0x9000_0000;
/// The page shared with the launcher.
const LAUNCHER_VADDR: usize = 0x9001_0000;

/// The binder's ledger size, `launch-binder`'s `LEDGER_LEN`: `MAX_BINDS` for each app slot.
const LEDGER_SIZE: usize = 4 * APP_SLOTS;
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

fn launcher_page() -> &'static mut [u8] {
    // SAFETY: the loader mapped the 4 KiB page shared with the launcher read/write at LAUNCHER_VADDR for this program's
    // whole life. This program writes a command only when none is outstanding, and reads the reply only after the
    // launcher signals `REPLIED`, so the two never touch it at once.
    unsafe { core::slice::from_raw_parts_mut(LAUNCHER_VADDR as *mut u8, 4096) }
}

/// An app's name, as the person typed it, kept for what the console says about it later.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Name {
    bytes: [u8; launcher::NAME_MAX],
    len: usize,
}

impl Name {
    const NONE: Self = Self { bytes: [0; launcher::NAME_MAX], len: 0 };

    fn new(name: &[u8]) -> Self {
        let mut bytes = [0; launcher::NAME_MAX];
        let len = name.len().min(launcher::NAME_MAX);
        bytes[..len].copy_from_slice(&name[..len]);
        Self { bytes, len }
    }

    fn get(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// A command the launcher hasn't answered yet.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Launch {
    List,
    Run(Name),
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
    let mut state = Prompt::Idle;
    let mut launching: Option<Launch> = None;
    let mut running = [Name::NONE; APP_SLOTS];
    loop {
        let bits = sys::wait(NOTIFY_CPTR).unwrap_or(0);
        // The launcher's answer comes before a request its app may already have made.
        if bits & shell_bit::REPLIED != 0 {
            if let Some(launch) = launching.take() {
                launched(&mut out, launch, &mut running);
                let _ = out.write_str(if state == Prompt::Asking { "allow? > " } else { "> " });
            }
        }
        // The binder's verdict on the last request comes before any new one.
        if bits & bit::ASK_DONE != 0 {
            if let Prompt::Sent(chosen) = state {
                let said = match chosen {
                    Answer::AllowOnce => "allowed, this time",
                    Answer::AllowAlways => "allowed, and remembered",
                    Answer::Deny => "refused, this time",
                    Answer::DenyAlways => "refused, and remembered",
                };
                let _ = write!(out, "lantern: {said}.\n> ");
            }
            state = Prompt::Idle;
        }
        if bits & bit::ASK_CANCELLED != 0 {
            let _ = out.write_str(match state {
                Prompt::Sent(_) => "lantern: too late: the request had already timed out, and was refused.\n> ",
                _ => "\nlantern: nobody answered in time, so the request was refused.\n> ",
            });
            state = Prompt::TimedOut;
        }
        if bits & bit::ASK != 0 {
            match asked() {
                Some(ask) => {
                    let _ = write_prompt(&mut out, &ask);
                    state = Prompt::Asking;
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
                        state = handle_line(&mut out, &line[..len], state, &mut launching);
                    }
                    Key::Ignore => {}
                }
            }
            let _ = irq::ack(IRQ_CPTR);
        }
        if bits & bit::SYSTEM_FAILED != 0 {
            let _ = write!(out, "\nlantern: a system service stopped with an error. Grants may be refused from now on.\n> ");
        }
        for (app, name) in running.iter_mut().enumerate() {
            let failed = bits & shell_bit::failed(app) != 0;
            if failed || bits & shell_bit::ended(app) != 0 {
                let how = if failed { "stopped with an error" } else { "finished" };
                let asking = state == Prompt::Asking;
                let shown = sanitized(name.get());
                let _ = write!(out, "\nlantern: \"{shown}\" {how}.\n{}", if asking { "allow? > " } else { "> " });
                *name = Name::NONE;
            }
        }
        if bits & (bit::APP_DONE | bit::APP_FAILED) != 0 {
            let how = if bits & bit::APP_FAILED != 0 { "stopped with an error" } else { "finished" };
            let asking = state == Prompt::Asking;
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

/// Where the console is with consent.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Prompt {
    Idle,
    /// A request is shown, and only an answer is taken: the binder is waiting, so a command that calls it would deadlock.
    Asking,
    /// An answer was sent, and the binder hasn't said yet whether it counted.
    Sent(Answer),
    /// The last request timed out. An answer typed now is too late, and is said to be.
    TimedOut,
}

/// Says what the launcher answered.
fn launched(out: &mut Console, launch: Launch, running: &mut [Name; APP_SLOTS]) {
    let Some((reply, entries)) = launcher::decode_reply(&launcher_page()[launcher::REPLY_OFFSET..]) else {
        let _ = out.write_str("lantern: the launcher's answer couldn't be read.\n");
        return;
    };
    match launch {
        Launch::List => {
            let mut any = false;
            for (name, description) in entries {
                any = true;
                // `sanitized` shows each byte as one character, so its width is the name's length.
                let pad = 22usize.saturating_sub(name.len());
                let _ = writeln!(out, "  {}{:pad$} {}", sanitized(name), "", sanitized(description));
            }
            if !any {
                let _ = out.write_str("  no apps\n");
            }
        }
        Launch::Run(name) => {
            let shown = sanitized(name.get());
            let _ = match reply.outcome {
                outcome::OK if (reply.app as usize) < APP_SLOTS => {
                    running[reply.app as usize] = name;
                    writeln!(out, "lantern: \"{shown}\" started.")
                }
                outcome::UNKNOWN => writeln!(out, "lantern: there's no app called \"{shown}\"; type apps."),
                outcome::UNVERIFIED => writeln!(out, "lantern: \"{shown}\" didn't verify, and wasn't started."),
                outcome::NO_ROOM => writeln!(out, "lantern: no room: {APP_SLOTS} apps are running already."),
                outcome::NO_MEMORY => writeln!(out, "lantern: \"{shown}\" didn't fit in memory, and wasn't started."),
                _ => writeln!(out, "lantern: \"{shown}\" couldn't be started."),
            };
        }
    }
}

/// One typed line. Returns where the console is now.
fn handle_line(out: &mut Console, line: &[u8], state: Prompt, launching: &mut Option<Launch>) -> Prompt {
    match state {
        Prompt::Asking => {
            let Some(chosen) = parse_answer(line) else {
                let _ = out.write_str("         please answer y, a, n or e > ");
                return Prompt::Asking;
            };
            answer(chosen);
            return Prompt::Sent(chosen);
        }
        Prompt::Sent(_) => {
            let _ = out.write_str("lantern: wait: your answer is on its way.\n");
            return state;
        }
        Prompt::TimedOut if parse_answer(line).is_some() => {
            let _ = out.write_str("lantern: too late: that request timed out, and was refused.\n> ");
            return Prompt::Idle;
        }
        _ => {}
    }
    let command = parse_command(line);
    if launching.is_some() && command != Command::Empty {
        let _ = out.write_str("lantern: wait: the launcher is answering.\n");
        return state;
    }
    match command {
        Command::Empty => {}
        Command::Apps | Command::Run(_) => {
            let (op, name, launch) = match command {
                Command::Run(name) => (OP_RUN, name, Launch::Run(Name::new(name))),
                _ => (OP_LIST, &b""[..], Launch::List),
            };
            launcher::encode_command(&launcher::Command { op, name }, &mut launcher_page()[launcher::COMMAND_OFFSET..]);
            if sys::signal(LAUNCHER_CPTR).is_ok() {
                // The reply prints the prompt.
                *launching = Some(launch);
                return Prompt::Idle;
            }
            let _ = out.write_str("lantern: the launcher couldn't be reached.\n");
        }
        Command::Help => {
            let _ = out.write_str(HELP);
        }
        Command::Grants => grants(out),
        Command::Files => files(out),
        Command::Identities => identities(out),
        Command::Archive(from) => archive(out, from),
        Command::Read(file) => {
            let mut content = [0u8; 256];
            match console_read(file, &mut content) {
                Ok((status::OK, 0)) => {
                    let _ = writeln!(out, "lantern: file {file} is empty.");
                }
                Ok((status::OK, len)) => {
                    // Whatever wrote it, it's shown as text, never as control sequences: line breaks start an indented
                    // line, and anything else unprintable is a `?`.
                    let text = content[..len].strip_suffix(b"\n").unwrap_or(&content[..len]);
                    for line in text.split(|&b| b == b'\n') {
                        let _ = writeln!(out, "  {}", lantern_shell::Text(line));
                    }
                }
                Ok(_) => {
                    let _ = writeln!(out, "lantern: there's no file {file}.");
                }
                Err(()) => {
                    let _ = out.write_str("lantern: the store couldn't be reached.\n");
                }
            }
        }
        Command::Write(file, text) => {
            let said = match console_write(file, text) {
                Ok(status::OK) => "written, as you",
                Ok(status::INVALID) => "there's no such file, or the text is too long for one",
                _ => "the store couldn't write it",
            };
            let _ = writeln!(out, "lantern: file {file}: {said}.");
        }
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
    Prompt::Idle
}

/// Each file the store holds, its size, and its last writes, newest first, each named by the binder.
fn files(out: &mut Console) {
    let mut any = false;
    for index in 0.. {
        let info = match provenance::file_info(STORE_READER_CPTR, index) {
            Ok(Some(info)) => info,
            Ok(None) => break,
            Err(_) => {
                let _ = out.write_str("lantern: the store couldn't be reached.\n");
                return;
            }
        };
        if !info.exists {
            continue;
        }
        any = true;
        let state = if info.destroyed { "  (destroyed)" } else { "" };
        let _ = write!(out, "  file {index}  {} bytes{state}", info.len);
        if info.entries == 0 {
            let _ = out.write_str("  never written\n");
            continue;
        }
        for k in 0..info.entries {
            let Ok(Some(entry)) = provenance::file_entry(STORE_READER_CPTR, index, k) else { break };
            let _ = out.write_str(if k == 0 { "   written by " } else { "\n          before:        " });
            writer(out, entry.principal);
            let _ = write!(out, ", write {}, boot {}", entry.write, entry.boot);
        }
        let _ = out.write_str("\n");
    }
    if !any {
        let _ = out.write_str("  no files\n");
    }
}

/// `write`: replaces `file`'s content with `text` at the store, which records the console as its writer. A file is one of
/// the store's blocks, so `text` fits any line the editor takes.
fn console_write(file: usize, text: &[u8]) -> Result<u16, ()> {
    let file = u16::try_from(file).map_err(|_| ())?;
    let mut request = [0u8; 2 + LINE_MAX];
    let len = provenance::encode_console_write(file, text, &mut request).ok_or(())?;
    // SAFETY: the loader mapped the channel shared with the store read/write at STORE_CONSOLE_VADDR, this program's only
    // use of it, and nothing else here holds a `Channel` over it.
    let mut channel = unsafe { lantern_abi::frame::Channel::new(STORE_CONSOLE_CPTR, STORE_CONSOLE_VADDR as *mut u8) };
    channel.call(provenance::OP_CONSOLE_WRITE, &request[..len], &mut []).map(|(status, _)| status).map_err(|_| ())
}

/// `read`: file `file`'s content from the store, as the person at the console.
fn console_read(file: usize, out: &mut [u8]) -> Result<(u16, usize), ()> {
    let file = u16::try_from(file).map_err(|_| ())?;
    // SAFETY: as in `console_write`.
    let mut channel = unsafe { lantern_abi::frame::Channel::new(STORE_CONSOLE_CPTR, STORE_CONSOLE_VADDR as *mut u8) };
    channel.call(provenance::OP_CONSOLE_READ, &file.to_le_bytes(), out).map_err(|_| ())
}

/// Each identity the wallet has presented: which app, to which peer, the key's first bytes, and how many sessions.
fn identities(out: &mut Console) {
    let mut any = false;
    for index in 0..64 {
        let p = match lantern_abi::identity::identity(WALLET_READER_CPTR, index) {
            Ok(Some(p)) => p,
            Ok(None) => break,
            Err(_) => {
                let _ = out.write_str("lantern: the wallet couldn't be reached.\n");
                return;
            }
        };
        any = true;
        let _ = out.write_str("  ");
        writer(out, p.principal);
        let peer = lantern_abi::identity::context(p.context).map_or("an unknown peer", |c| c.peer);
        let s = if p.sessions == 1 { "" } else { "s" };
        let _ = writeln!(out, " to {peer}: key {:08x}.., {} session{s}", p.key, p.sessions);
    }
    if !any {
        let _ = out.write_str("  none presented yet\n");
    }
}

/// Who a principal is, as the binder knows from the packages it verified.
fn writer(out: &mut Console, principal: u64) {
    if principal == provenance::NONE {
        let _ = out.write_str("an unattributed writer");
        return;
    }
    if principal == provenance::CONSOLE {
        let _ = out.write_str("you, at the console");
        return;
    }
    match grant::principal(CONTROL_CPTR, principal) {
        Ok(Some(shown)) => {
            let (app, _) = names();
            let p = shown.to_be_bytes();
            let _ = write!(
                out,
                "\"{}\" (publisher {:02x}{:02x}{:02x}{:02x}..{:02x}{:02x})",
                sanitized(app),
                p[2],
                p[3],
                p[4],
                p[5],
                p[6],
                p[7]
            );
        }
        _ => {
            let _ = write!(out, "an app not on this disk (principal {principal:012x})");
        }
    }
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
/// RFC-0038: what a `RETIRED` or `EXPORTED` record says about history: kept in the archive, dropped from it, or lost.
fn history_detail(out: &mut Console, e: &AuditEntry) {
    let [a, b] = e.subject;
    if e.event == policy::event::RETIRED {
        let _ = match b {
            policy::KEPT_UNKNOWN => write!(out, " (#{a} and before retired; whether they were kept is unknown)"),
            b if b > a => write!(out, " (#{a} and before retired, all kept in the archive)"),
            b => write!(out, " (#{a} and before retired; #{b} to #{a} were never kept: lost)"),
        };
    } else if e.event == policy::event::EXPORTED {
        let _ = write!(out, " (kept in the archive up to #{})", a.saturating_sub(1));
        if b > 0 {
            let _ = write!(out, " (the archive dropped #{} and before to make room)", b - 1);
        }
    }
}

/// `archive`: each export the archiver holds, oldest first. `archive N`: its records from sequence number `N`, each
/// export checked whole by the archiver before any record of it is shown.
fn archive(out: &mut Console, from: Option<usize>) {
    let Some(from) = from else {
        let mut any = false;
        for i in 0.. {
            match sys::call_with_label(ARCHIVE_CPTR, lantern_abi::archive::OP_LIST, [0, i, 0]) {
                Ok(([first, end, dropped], tag)) if tag.label == status::OK as u32 => {
                    any = true;
                    let _ = write!(out, "  #{first} to #{}", end.saturating_sub(1));
                    if dropped > 0 && i == 0 {
                        let _ = write!(out, "  (#{} and before dropped to make room)", dropped - 1);
                    }
                    let _ = out.write_str("\n");
                }
                Ok(_) => break,
                Err(_) => {
                    let _ = out.write_str("lantern: the archive can't be reached.\n");
                    return;
                }
            }
        }
        if !any {
            let _ = out.write_str("  the archive holds nothing\n");
        }
        return;
    };
    for sequence in from as u64..from as u64 + lantern_shell::AUDIT_DEFAULT as u64 {
        let Ok((answer, e)) = policy::read(ARCHIVE_CPTR, sequence) else {
            let _ = out.write_str("lantern: the archive can't be reached.\n");
            return;
        };
        match answer {
            status::OK => record_line(out, sequence, &e),
            status::FAILED => {
                let _ = writeln!(out, "lantern: the archive's copy of record #{sequence} does NOT verify. It isn't shown.");
                return;
            }
            _ => {
                if sequence == from as u64 {
                    let _ = writeln!(out, "lantern: the archive doesn't hold record #{sequence}.");
                }
                return;
            }
        }
    }
}

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
            record_line(out, index, &e);
        }
    }
}

/// One audit record, as `audit` and `archive` show it.
fn record_line(out: &mut Console, index: u64, e: &AuditEntry) {
    let reason = reason_name(e.event, e.reason);
    let _ = write!(out, "  #{index:<6} {:<16}", event_name(e.event));
    if e.interface != 0 {
        let _ = write!(out, " {} {}", interface_name(e.interface), Ops { interface: e.interface, bits: e.ops });
    }
    // RFC-0034: which model ran, on how much, for how long; RFC-0038: whose model it was. And what the person wrote
    // themselves.
    if e.event == policy::event::USING && e.interface as usize == grant::INTERFACE_INFERENCE {
        let (model, tokens, prompt) = lantern_abi::inference::split_audit_subject(e.subject[1]);
        let _ = write!(out, " (model {model:08x} by publisher {:04x}, up to {tokens} tokens, {prompt}-byte prompt)", e.object);
    } else if e.event == policy::event::USING && e.interface as usize == grant::INTERFACE_IDENTITY {
        let (key, len) = lantern_abi::identity::split_audit_subject(e.subject[1]);
        let peer = lantern_abi::identity::context(e.object).map_or("an unknown peer", |c| c.peer);
        let _ = write!(out, " to {peer} as {key:08x}.. ({len} bytes)");
    } else if e.event == policy::event::USING && e.subject[0] == provenance::STORE_CONSOLE_BADGE {
        let _ = write!(out, " file {} (you, at the console)", e.object);
    }
    history_detail(out, e);
    let _ = writeln!(out, "{}{}", if reason.is_empty() { "" } else { "  " }, reason);
}
