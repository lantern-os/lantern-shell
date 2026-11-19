//! The testable half of [RFC-0026](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0026-trusted-path-and-consent.md)'s shell: everything that
//! decides what reaches the console, with no syscalls in it. `src/main.rs` is the program around it.
//!
//! **The console is a trusted path because only the shell writes to it.** So every byte of text an app supplies (its name,
//! its roles' names, its justifications) goes through [`sanitized`] first. That passes printable ASCII and nothing else,
//! and replaces quote marks too. So an app's text can't move the cursor, clear the screen, start a new line, or close its
//! own quotation and append something that looks like the shell's.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use core::fmt::{self, Write};

use lantern_abi::consent::{Answer, Ask};
use lantern_abi::grant::{INTERFACE_FILESYSTEM, INTERFACE_IDENTITY, INTERFACE_INFERENCE, INTERFACE_KEYSTORE};

/// App-supplied text, made safe to print: printable ASCII passes, and every other byte, `"` and `\` included, becomes
/// `?`.
pub struct Sanitized<'a>(pub &'a [u8]);

pub fn sanitized(text: &[u8]) -> Sanitized<'_> {
    Sanitized(text)
}

/// A file's text, for `read` ([RFC-0034](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0034-local-inference-and-a-file-assistant.md)):
/// printable ASCII as it is, quotes included, since it's shown indented and never inside quotes, and anything else as `?`,
/// so no file, whatever wrote it, can send the terminal a control sequence.
pub struct Text<'a>(pub &'a [u8]);

impl fmt::Display for Text<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for &byte in self.0 {
            f.write_char(if matches!(byte, 0x20..=0x7e) { byte as char } else { '?' })?;
        }
        Ok(())
    }
}

impl fmt::Display for Sanitized<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for &byte in self.0 {
            let safe = matches!(byte, 0x20..=0x7e) && byte != b'"' && byte != b'\\';
            f.write_char(if safe { byte as char } else { '?' })?;
        }
        Ok(())
    }
}

/// An interface's name, and its ops' names, for prompts and listings.
pub fn interface_name(interface: u8) -> &'static str {
    match interface as usize {
        INTERFACE_KEYSTORE => "keystore",
        INTERFACE_FILESYSTEM => "filesystem",
        INTERFACE_INFERENCE => "the language model",
        INTERFACE_IDENTITY => "a network identity",
        _ => "unknown",
    }
}

/// `KeyOps` or `FileOps` bits, by name. Must match `lantern_crypto::KeyOps` and `lantern_filesystem::FileOps`, which this
/// crate doesn't link.
pub struct Ops {
    pub interface: u8,
    pub bits: u8,
}

impl fmt::Display for Ops {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: &[(u8, &str)] = match self.interface as usize {
            INTERFACE_KEYSTORE => &[(1, "encrypt"), (2, "decrypt"), (4, "sign")],
            INTERFACE_FILESYSTEM => &[(1, "read"), (2, "write")],
            INTERFACE_INFERENCE => &[(lantern_abi::inference::GENERATE, "generate")],
            INTERFACE_IDENTITY => &[
                (lantern_abi::identity::CONNECT, "connect"),
                (lantern_abi::identity::SEND, "send"),
                (lantern_abi::identity::RECV, "receive"),
            ],
            _ => &[],
        };
        let mut first = true;
        for &(bit, name) in names {
            if self.bits & bit != 0 {
                if !first {
                    f.write_str(", ")?;
                }
                f.write_str(name)?;
                first = false;
            }
        }
        let known: u8 = names.iter().map(|&(bit, _)| bit).fold(0, |a, b| a | b);
        if self.bits & !known != 0 || first {
            write!(f, "{}ops {:#x}", if first { "" } else { ", " }, self.bits & !known)?;
        }
        Ok(())
    }
}

/// The consent prompt, from a request the binder wrote. Everything the app supplied is sanitized and quoted, after a label
/// the shell wrote.
pub fn write_prompt(out: &mut impl Write, ask: &Ask<'_>) -> fmt::Result {
    let p = &ask.publisher;
    write!(
        out,
        "\nlantern: \"{}\" (publisher {:02x}{:02x}{:02x}{:02x}..{:02x}{:02x}) asks for\n",
        sanitized(ask.app),
        p[0],
        p[1],
        p[2],
        p[3],
        p[30],
        p[31]
    )?;
    writeln!(
        out,
        "         {} role \"{}\": {}",
        interface_name(ask.interface),
        sanitized(ask.role),
        Ops { interface: ask.interface, bits: ask.ops }
    )?;
    writeln!(out, "         the app says: \"{}\"", sanitized(ask.justification))?;
    if ask.truncated {
        out.write_str("         (the app's text was cut short)\n")?;
    }
    out.write_str("         allow? [y]es once, [a]lways, [n]o, n[e]ver > ")
}

/// A prompt's answer, from one typed line: `y`, `a`, `n` or `e`, in either case, with spaces around it ignored.
pub fn parse_answer(line: &[u8]) -> Option<Answer> {
    match trim(line) {
        b"y" | b"Y" => Some(Answer::AllowOnce),
        b"a" | b"A" => Some(Answer::AllowAlways),
        b"n" | b"N" => Some(Answer::Deny),
        b"e" | b"E" => Some(Answer::DenyAlways),
        _ => None,
    }
}

/// A console command. The language is deliberately tiny: `run` starts only a verified app the launcher lists, by name.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Command<'a> {
    Help,
    /// The apps the launcher can run ([RFC-0029](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0029-a-confined-launcher.md)).
    Apps,
    /// Start the app with this name: printable, no spaces, at most `launcher::NAME_MAX` bytes.
    Run(&'a [u8]),
    Grants,
    /// Each file's size and who wrote it ([RFC-0033](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0033-provenance-for-data-at-rest.md)).
    Files,
    /// Replace file N's content with this text, as the person at the console
    /// ([RFC-0034](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0034-local-inference-and-a-file-assistant.md)).
    Write(usize, &'a [u8]),
    /// File N's content, shown to the person at the console.
    Read(usize),
    /// Each identity the wallet has presented, to whom, for which app
    /// ([RFC-0035](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0035-pairwise-network-identities.md)).
    Identities,
    Revoke(usize),
    Audit(usize),
    /// [RFC-0038](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0038-signed-models-and-kept-audit-history.md): the archive's exports, or
    /// with a number, its records from that sequence number on.
    Archive(Option<usize>),
    Decisions,
    Forget(usize),
    Empty,
    Unknown,
}

/// How many audit records `audit` shows without a number.
pub const AUDIT_DEFAULT: usize = 12;

pub fn parse_command(line: &[u8]) -> Command<'_> {
    let line = trim(line);
    let mut words = line.split(|&b| b == b' ').filter(|w| !w.is_empty());
    let Some(word) = words.next() else { return Command::Empty };
    let argument = words.next();
    if word == b"write" {
        // The text is the rest of the line, spaces and all, after the file's number and one space.
        let Some(Some(file)) = argument.map(parse_number) else { return Command::Unknown };
        let at = line.windows(argument.unwrap().len()).position(|w| Some(w) == argument).unwrap() + argument.unwrap().len();
        let text = line[at..].strip_prefix(b" ").unwrap_or(&[]);
        return if text.is_empty() { Command::Unknown } else { Command::Write(file, text) };
    }
    if words.next().is_some() {
        return Command::Unknown;
    }
    if word == b"run" {
        return match argument {
            Some(name) if name.len() <= lantern_abi::launcher::NAME_MAX && name.iter().all(|b| b.is_ascii_graphic()) => {
                Command::Run(name)
            }
            _ => Command::Unknown,
        };
    }
    let number = argument.map(parse_number);
    match (word, number) {
        (b"apps", None) => Command::Apps,
        (b"help", None) => Command::Help,
        (b"grants", None) => Command::Grants,
        (b"files", None) => Command::Files,
        (b"read", Some(Some(n))) => Command::Read(n),
        (b"identities", None) => Command::Identities,
        (b"decisions", None) => Command::Decisions,
        (b"audit", None) => Command::Audit(AUDIT_DEFAULT),
        (b"audit", Some(Some(n))) => Command::Audit(n),
        (b"archive", None) => Command::Archive(None),
        (b"archive", Some(Some(n))) => Command::Archive(Some(n)),
        (b"revoke", Some(Some(n))) => Command::Revoke(n),
        (b"forget", Some(Some(n))) => Command::Forget(n),
        _ => Command::Unknown,
    }
}

fn parse_number(word: &[u8]) -> Option<usize> {
    if word.is_empty() || word.len() > 6 {
        return None;
    }
    word.iter().try_fold(0usize, |n, &b| b.is_ascii_digit().then(|| n * 10 + (b - b'0') as usize))
}

fn trim(line: &[u8]) -> &[u8] {
    let start = line.iter().position(|&b| b != b' ').unwrap_or(line.len());
    let end = line.iter().rposition(|&b| b != b' ').map_or(start, |i| i + 1);
    &line[start..end]
}

/// One line of typing, with backspace. Keeps only printable ASCII: what the person types is echoed, so it mustn't be able
/// to send control sequences to their own terminal either.
pub struct LineEditor {
    buf: [u8; LINE_MAX],
    len: usize,
}

pub const LINE_MAX: usize = 120;

/// What one typed byte did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Key {
    /// Echo this byte.
    Echo(u8),
    /// Erase the last character on screen.
    Erase,
    /// The line is complete: take it with [`LineEditor::take`].
    Enter,
    Ignore,
}

impl Default for LineEditor {
    fn default() -> Self {
        Self { buf: [0; LINE_MAX], len: 0 }
    }
}

impl LineEditor {
    pub fn feed(&mut self, byte: u8) -> Key {
        match byte {
            b'\r' | b'\n' => Key::Enter,
            0x08 | 0x7f if self.len > 0 => {
                self.len -= 1;
                Key::Erase
            }
            0x20..=0x7e if self.len < LINE_MAX => {
                self.buf[self.len] = byte;
                self.len += 1;
                Key::Echo(byte)
            }
            _ => Key::Ignore,
        }
    }

    /// The completed line, clearing the editor for the next one.
    pub fn take(&mut self, out: &mut [u8; LINE_MAX]) -> usize {
        let len = self.len;
        out[..len].copy_from_slice(&self.buf[..len]);
        self.len = 0;
        len
    }
}

/// An audit record's event and reason, by name, for `audit`.
pub fn event_name(event: u8) -> &'static str {
    use lantern_abi::policy::event::*;
    match event {
        BOOT => "BOOT",
        GRANTING => "GRANTING",
        GRANT_FAILED => "GRANT_FAILED",
        DECLINED => "DECLINED",
        REVOKING => "REVOKING",
        GRANTED => "GRANTED",
        SERVICE_GRANTED => "SERVICE_GRANTED",
        USING => "USING",
        USE_FAILED => "USE_FAILED",
        QUOTA_REACHED => "QUOTA_REACHED",
        RETIRED => "RETIRED",
        CONSENTED => "CONSENTED",
        EXPORTED => "EXPORTED",
        _ => "UNKNOWN",
    }
}

pub fn reason_name(event: u8, reason: u8) -> &'static str {
    use lantern_abi::policy::{consent_reason, event, reason as r};
    if event == event::CONSENTED {
        return match reason {
            consent_reason::ONCE => "once",
            consent_reason::ALWAYS => "always",
            consent_reason::REMEMBERED => "remembered",
            _ => "",
        };
    }
    if event == event::USE_FAILED {
        return if reason == 0 { "" } else { "refused" };
    }
    match reason {
        r::UNVERIFIED_PACKAGE => "unverified package",
        r::NOT_DECLARED => "not declared",
        r::NOT_IN_POLICY => "not in policy",
        r::OPS_EXCEED_POLICY => "ops exceed policy",
        r::REVOKED => "revoked",
        r::STORE_UNAVAILABLE => "store unavailable",
        r::PERSON_DENIED => "you said no",
        r::REMEMBERED_DENIAL => "you said never",
        r::NO_CONSENT => "nobody answered",
        r::APP_ENDED => "the app ended",
        r::NOT_REGISTERED => "not a running app",
        _ => "",
    }
}

pub const HELP: &str = "\
  apps         the apps you can run\n\
  run NAME     start an app; it asks for what it needs\n\
  grants       what each app holds now\n\
  files        each file, and which apps wrote it\n\
  read N       show file N\n\
  identities   which identity each app presented to whom\n\
  write N TEXT replace file N with TEXT, as you\n\
  revoke N     end grant N now; it's asked again next time\n\
  audit [N]    the last N records of the audit log, verified first\n\
  archive [N]  audit history kept after the log retired it; N: from record N\n\
  decisions    your remembered \"always\" and \"never\" answers\n\
  forget N     forget remembered answer N\n\
  help         this list\n";

#[cfg(test)]
mod tests {
    use super::*;
    use std::string::String;

    fn ask<'a>(app: &'a [u8], role: &'a [u8], justification: &'a [u8]) -> Ask<'a> {
        Ask { interface: INTERFACE_KEYSTORE as u8, ops: 4, publisher: [0x92; 32], app, role, justification, truncated: false }
    }

    #[test]
    fn a_files_text_keeps_quotes_but_never_a_control_byte() {
        let shown = format!("{}", Text(b"Spot said \"hi\".\x1b[2J\x07\xc3\xa9"));
        assert_eq!(shown, "Spot said \"hi\".?[2J???");
    }

    #[test]
    fn only_printable_ascii_without_quotes_passes() {
        let hostile = b"ok\x1b[2J\x1b[H\rlantern: \"granted\"\n\\\x07\xff\xc3\xa9";
        let shown = format!("{}", sanitized(hostile));
        assert_eq!(shown, "ok?[2J?[H?lantern: ?granted???????");
        assert!(shown.bytes().all(|b| (0x20..=0x7e).contains(&b) && b != b'"'));
    }

    #[test]
    fn a_prompt_quotes_everything_the_app_says_on_lines_the_shell_starts() {
        let mut out = String::new();
        write_prompt(&mut out, &ask(b"confined-probe", b"probe-signing", b"signs\n\x1b[2Jlantern: allowed")).unwrap();
        assert!(out.contains("lantern: \"confined-probe\" (publisher 92929292..9292) asks for\n"));
        assert!(out.contains("keystore role \"probe-signing\": sign\n"));
        assert!(out.contains("the app says: \"signs??[2Jlantern: allowed\"\n"));
        assert!(out.ends_with("allow? [y]es once, [a]lways, [n]o, n[e]ver > "));
        // Every line starts with something the shell wrote, never with the app's text.
        for line in out.lines().filter(|l| !l.is_empty()) {
            assert!(line.starts_with("lantern: ") || line.starts_with("         "), "{line:?}");
        }
        assert_eq!(out.matches('\x1b').count(), 0);
    }

    #[test]
    fn a_cut_request_says_so() {
        let mut out = String::new();
        write_prompt(&mut out, &Ask { truncated: true, ..ask(b"a", b"r", b"j") }).unwrap();
        assert!(out.contains("(the app's text was cut short)"));
    }

    #[test]
    fn ops_are_named_and_unknown_bits_are_shown_not_hidden() {
        let k = INTERFACE_KEYSTORE as u8;
        let f = INTERFACE_FILESYSTEM as u8;
        assert_eq!(format!("{}", Ops { interface: k, bits: 4 }), "sign");
        assert_eq!(format!("{}", Ops { interface: k, bits: 7 }), "encrypt, decrypt, sign");
        assert_eq!(format!("{}", Ops { interface: f, bits: 3 }), "read, write");
        assert_eq!(format!("{}", Ops { interface: f, bits: 0x81 }), "read, ops 0x80");
        assert_eq!(format!("{}", Ops { interface: 9, bits: 1 }), "ops 0x1");
    }

    #[test]
    fn answers_are_one_letter() {
        assert_eq!(parse_answer(b" y "), Some(Answer::AllowOnce));
        assert_eq!(parse_answer(b"A"), Some(Answer::AllowAlways));
        assert_eq!(parse_answer(b"n"), Some(Answer::Deny));
        assert_eq!(parse_answer(b"e"), Some(Answer::DenyAlways));
        for line in [&b""[..], b"yes", b"yy", b"x", b"y n"] {
            assert_eq!(parse_answer(line), None, "{line:?}");
        }
    }

    #[test]
    fn commands_parse_and_anything_else_is_unknown() {
        assert_eq!(parse_command(b"  grants "), Command::Grants);
        assert_eq!(parse_command(b"revoke 0"), Command::Revoke(0));
        assert_eq!(parse_command(b"audit"), Command::Audit(AUDIT_DEFAULT));
        assert_eq!(parse_command(b"audit 40"), Command::Audit(40));
        assert_eq!(parse_command(b"forget 2"), Command::Forget(2));
        assert_eq!(parse_command(b"apps"), Command::Apps);
        assert_eq!(parse_command(b"files"), Command::Files);
        assert_eq!(parse_command(b"files 2"), Command::Unknown);
        assert_eq!(parse_command(b"write 1 Once upon a time"), Command::Write(1, b"Once upon a time"));
        assert_eq!(parse_command(b" write 1  two  spaces "), Command::Write(1, b" two  spaces"));
        assert_eq!(parse_command(b"write 11 1"), Command::Write(11, b"1"));
        assert_eq!(parse_command(b"read 2"), Command::Read(2));
        assert_eq!(parse_command(b"identities"), Command::Identities);
        assert_eq!(parse_command(b"read"), Command::Unknown);
        for line in [&b"write"[..], b"write 1", b"write x text", b"write 1 "] {
            assert_eq!(parse_command(line), Command::Unknown, "{:?}", core::str::from_utf8(line));
        }
        assert_eq!(parse_command(b" run  confined-fs-probe "), Command::Run(b"confined-fs-probe"));
        for line in [&b"run"[..], b"run a b", b"run \x1b[2J", b"apps 1"] {
            assert_eq!(parse_command(line), Command::Unknown, "{line:?}");
        }
        let long = [b'x'; lantern_abi::launcher::NAME_MAX + 1];
        let mut line = b"run ".to_vec();
        line.extend_from_slice(&long);
        assert_eq!(parse_command(&line), Command::Unknown, "too long");
        assert_eq!(parse_command(b""), Command::Empty);
        for line in [&b"revoke"[..], b"revoke x", b"revoke 1 2", b"grants 1", b"revoke 99999999"] {
            assert_eq!(parse_command(line), Command::Unknown, "{line:?}");
        }
    }

    #[test]
    fn the_editor_keeps_printable_text_erases_and_ignores_the_rest() {
        let mut editor = LineEditor::default();
        let keys: Vec<Key> = b"ab\x7fc\x1b\x01".iter().map(|&b| editor.feed(b)).collect();
        assert_eq!(keys, [Key::Echo(b'a'), Key::Echo(b'b'), Key::Erase, Key::Echo(b'c'), Key::Ignore, Key::Ignore]);
        assert_eq!(editor.feed(b'\r'), Key::Enter);
        let mut line = [0; LINE_MAX];
        let len = editor.take(&mut line);
        assert_eq!(&line[..len], b"ac");
        assert_eq!(editor.feed(0x7f), Key::Ignore, "nothing to erase");
        for _ in 0..LINE_MAX + 5 {
            editor.feed(b'x');
        }
        assert_eq!(editor.take(&mut line), LINE_MAX, "bounded");
    }
}
