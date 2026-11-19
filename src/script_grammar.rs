//! script_grammar.rs — the narrow sed script and awk program a program manifest describes (PROGRAM_MANIFEST.md, "sed and awk").
//!
//! A sed script or an awk program is a second language inside one argument, and the commands that write a file or start
//! a program (`w`, `e`, `r`, `s///w`, `system()`, `print > f`, `cmd | getline`) live in it, not in the argv. A manifest
//! cannot list them as flags, so `script: "sed" | "awk"` on a command hands the text to these checkers. Each one ACCEPTS
//! only a small grammar and returns why anything else is refused; a refusal only makes the call ask. Neither interprets the
//! text: they decide whether every implementation the manifest describes would read nothing but those commands.
//!
//! Port of src/shell/script-grammar.ts, line for line. INDEXING: every index is a JS string index, that is a UTF-16 code
//! unit offset, so the scanners work on a `Vec<u16>` from `encode_utf16()`; a `char` delimiter outside the BMP can never
//! equal one unit, as in JS. The refusal messages are byte-identical to the TS ones (the extension shows them).

/// `JSON.stringify` of a string given as UTF-16 units: quotes, escapes control characters, and writes a lone surrogate
/// as `\udxxx`, as JS does.
fn json_str(units: &[u16]) -> String {
    let mut out = String::from("\"");
    for r in char::decode_utf16(units.iter().copied()) {
        match r {
            Ok('"') => out.push_str("\\\""),
            Ok('\\') => out.push_str("\\\\"),
            Ok('\n') => out.push_str("\\n"),
            Ok('\r') => out.push_str("\\r"),
            Ok('\t') => out.push_str("\\t"),
            Ok('\u{8}') => out.push_str("\\b"),
            Ok('\u{c}') => out.push_str("\\f"),
            Ok(c) if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            Ok(c) => out.push(c),
            Err(e) => out.push_str(&format!("\\u{:04x}", e.unpaired_surrogate())),
        }
    }
    out.push('"');
    out
}

const NL: u16 = b'\n' as u16;
const BACKSLASH: u16 = b'\\' as u16;
const LBRACKET: u16 = b'[' as u16;
const RBRACKET: u16 = b']' as u16;
const CARET: u16 = b'^' as u16;

/// `s[i]`, or None past the end (JS `undefined`).
fn at(s: &[u16], i: usize) -> Option<u16> {
    s.get(i).copied()
}

fn is_digit(c: Option<u16>) -> bool {
    matches!(c, Some(0x30..=0x39))
}

/// A delimiter given as a `char`, as the unit value it is compared with (a non-BMP one equals no single unit).
fn delim_val(d: char) -> u32 {
    d as u32
}

/// Where a delimited part ends that is not a regular expression (an `s` replacement, a `y` string), as both seds read it
/// (GNU `match_slash` with `regex` false, BSD `compile_subst`): a backslash escapes the next character, and the first
/// unescaped delimiter ends it. Returns the index just past the delimiter, or -1 when a newline or the end comes first.
fn plain_delimited_end_u(s: &[u16], at_: usize, delim: u32) -> i64 {
    let mut i = at_;
    while i < s.len() {
        let c = s[i];
        if c == NL {
            return -1;
        }
        if c as u32 == delim {
            return i as i64 + 1;
        }
        if c == BACKSLASH {
            i += 1;
            if i >= s.len() || s[i] == NL {
                return -1;
            }
        }
        i += 1;
    }
    -1
}

/// Where a bracket expression ends, as GNU sed's `snarf_char_class` reads it (sed/compile.c, 4.9): `at` is just past
/// the `[`. A leading `^`, then a leading `]`, are members; then a state machine where `[` followed by `.`, `:` or `=`
/// opens a class, that same character starts closing it, and a `]` then closes it (a `[` in that state does not reset
/// it, unlike BSD). Returns the index just past the bracket's `]`, or -1.
fn gnu_bracket_end(s: &[u16], at_: usize) -> i64 {
    let mut i = at_;
    if at(s, i) == Some(CARET) {
        i += 1;
    }
    if at(s, i) == Some(RBRACKET) {
        i += 1;
    }
    let mut state = 0u8;
    let mut delim = 0u16;
    while i < s.len() {
        let ch = s[i];
        if ch == NL {
            return -1;
        }
        if ch == b'.' as u16 || ch == b':' as u16 || ch == b'=' as u16 {
            if state == 1 {
                delim = ch;
                state = 2;
                i += 1;
                continue;
            }
            if state == 2 && ch == delim {
                state = 3;
                i += 1;
                continue;
            }
        } else if ch == LBRACKET {
            if state == 0 {
                state = 1;
            }
            i += 1;
            continue;
        } else if ch == RBRACKET {
            if state == 0 || state == 1 {
                return i as i64 + 1;
            }
            if state == 3 {
                state = 0;
            }
        }
        state &= !1;
        i += 1;
    }
    -1
}

/// Where a regular expression's delimited part ends, as GNU sed's `match_slash` reads it: the first delimiter ends it,
/// a backslash escapes the next character, and a bracket expression is skipped whole (`gnu_bracket_end`). Returns the
/// index just past the delimiter, or -1.
fn gnu_regex_end_u(s: &[u16], at_: usize, delim: u32) -> i64 {
    let mut i = at_;
    while i < s.len() {
        let c = s[i];
        if c == NL {
            return -1;
        }
        if c as u32 == delim {
            return i as i64 + 1;
        }
        if c == BACKSLASH {
            i += 1;
            if i >= s.len() || s[i] == NL {
                return -1;
            }
            i += 1;
            continue;
        }
        if c == LBRACKET {
            let e = gnu_bracket_end(s, i + 1);
            if e < 0 {
                return -1;
            }
            i = (e - 1) as usize;
        }
        i += 1;
    }
    -1
}

/// First index >= `from` where the two units `a`, `b` sit side by side (JS `indexOf` on a two-character string).
fn index_of_pair(s: &[u16], a: u16, b: u16, from: usize) -> Option<usize> {
    (from..s.len().saturating_sub(1)).find(|&k| s[k] == a && s[k + 1] == b)
}

/// Where a bracket expression starting at `at` (`[`) ends, as BSD sed's `compile_ccl` reads it: a leading `^`, then a
/// leading `]`, are members; `[:`, `[=` and `[.` open a class closed by `:]`, `=]` or `.]`. Returns the index just
/// past its `]`, or -1 when the text ends first.
fn bsd_bracket_end(s: &[u16], at_: usize) -> i64 {
    let mut i = at_ + 1;
    if at(s, i) == Some(CARET) {
        i += 1;
    }
    if at(s, i) == Some(RBRACKET) {
        i += 1;
    }
    while i < s.len() && s[i] != RBRACKET {
        if s[i] == NL {
            return -1;
        }
        let d = at(s, i + 1);
        if s[i] == LBRACKET
            && let Some(d) = d
            && (d == b'.' as u16 || d == b':' as u16 || d == b'=' as u16)
        {
            let Some(close) = index_of_pair(s, d, RBRACKET, i + 2) else {
                return -1;
            };
            if s[i + 2..close].contains(&NL) {
                return -1;
            }
            i = close + 1;
        }
        i += 1;
    }
    if i < s.len() { i as i64 + 1 } else { -1 }
}

/// Where a regular expression's delimited part ends, as BSD sed's `compile_delimited` reads it: a bracket expression is
/// skipped whole (so the delimiter inside one does not end it), and a backslash before the delimiter, `n`, `[` or `\`
/// escapes it. Returns the index just past the delimiter, or -1.
fn bsd_delimited_end_u(s: &[u16], at_: usize, delim: u32) -> i64 {
    let mut i = at_;
    while i < s.len() {
        let c = s[i];
        if c == NL {
            return -1;
        }
        if c == LBRACKET && delim != LBRACKET as u32 {
            let e = bsd_bracket_end(s, i);
            if e < 0 {
                return -1;
            }
            i = e as usize; // the TS sets i = e - 1 and continues through the loop's i++
            continue;
        }
        if c == BACKSLASH
            && let Some(n) = at(s, i + 1)
            && (n == LBRACKET || n as u32 == delim || n == b'n' as u16 || n == BACKSLASH)
        {
            i += 2;
            continue;
        }
        if c as u32 == delim {
            return i as i64 + 1;
        }
        i += 1;
    }
    -1
}

/// `plain_delimited_end` on a `&str`; the index is a UTF-16 offset. Where a delimited part ends that is not a regular
/// expression (an `s` replacement, a `y` string); -1 when it is not closed.
pub fn plain_delimited_end(s: &str, at: usize, delim: char) -> i64 {
    let u: Vec<u16> = s.encode_utf16().collect();
    plain_delimited_end_u(&u, at, delim_val(delim))
}

/// Where a regular expression's delimited part ends, as GNU sed reads it; the index is a UTF-16 offset, -1 when it is
/// not closed.
pub fn gnu_regex_end(s: &str, at: usize, delim: char) -> i64 {
    let u: Vec<u16> = s.encode_utf16().collect();
    gnu_regex_end_u(&u, at, delim_val(delim))
}

/// Where a regular expression's delimited part ends, as BSD sed reads it; the index is a UTF-16 offset, -1 when it is
/// not closed.
pub fn bsd_delimited_end(s: &str, at: usize, delim: char) -> i64 {
    let u: Vec<u16> = s.encode_utf16().collect();
    bsd_delimited_end_u(&u, at, delim_val(delim))
}

/// A regular expression's delimited part, read the same by both seds (Ok: the index past it), or why not (Err).
fn sed_regex_end(s: &[u16], at_: usize, delim: u32) -> Result<usize, String> {
    let g = gnu_regex_end_u(s, at_, delim);
    let b = bsd_delimited_end_u(s, at_, delim);
    if g < 0 || b < 0 {
        return Err("a regular expression is not closed on its own line".to_string());
    }
    if g != b {
        return Err(
            "a regular expression's bracket expression ends in different places for GNU and BSD sed".to_string()
        );
    }
    Ok(g as usize)
}

/// sed commands that take no argument and touch nothing but the pattern space, the hold space and stdout.
const SED_PLAIN: [u8; 12] = *b"pPdDnNhHgGx=";

/// A delimiter both seds accept for `s` and `y` and read as one byte: printable ASCII, not a backslash or a space.
fn sed_delim_ok(c: Option<u16>) -> bool {
    matches!(c, Some(0x21..=0x7e)) && c != Some(BACKSLASH)
}

/// The state of one `sed_script_refusal` scan: the script, the read position and the brace depth.
struct SedScan {
    s: Vec<u16>,
    i: usize,
    depth: usize,
}

impl SedScan {
    fn cur(&self) -> Option<u16> {
        at(&self.s, self.i)
    }

    fn space(&mut self) {
        while self.cur() == Some(b' ' as u16) || self.cur() == Some(b'\t' as u16) {
            self.i += 1;
        }
    }

    /// One address at `i`, or why not; leaves `i` after it. Returns false when there is none.
    fn address(&mut self) -> Result<bool, String> {
        if self.cur() == Some(b'$' as u16) {
            self.i += 1;
            return Ok(true);
        }
        let n = self.s[self.i.min(self.s.len())..].iter().take_while(|&&c| (0x30..=0x39).contains(&c)).count();
        if n > 0 {
            if self.s[self.i..self.i + n].iter().all(|&c| c == 0x30) {
                return Err("line address 0 is GNU's alone".to_string());
            }
            self.i += n;
            return Ok(true);
        }
        if self.cur() == Some(b'/' as u16) {
            let e = sed_regex_end(&self.s, self.i + 1, b'/' as u32)?;
            self.i = e;
            return Ok(true);
        }
        if self.cur() == Some(BACKSLASH) {
            return Err("an address with its own delimiter (\\cREc) is not described".to_string());
        }
        Ok(false)
    }

    /// After a command: blanks, then `;`, a newline, `}` or the end.
    fn end(&mut self, what: &str) -> Option<String> {
        self.space();
        match self.cur() {
            None => None,
            Some(c) if c == b';' as u16 || c == NL || c == b'}' as u16 => None,
            Some(c) => Some(format!("{} after {} is not described", json_str(&[c]), what)),
        }
    }
}

/// Why a sed script is not described, or None when it is: every command is one of `s y p P d D n N q = h H g G x
/// { } !`, separated by `;` or newlines; an address is a line number, `$` or `/re/`, or a range of two; `s` flags are
/// `g`, `p`, `i`, `I` and a number. Everything else is refused, whichever sed would accept it: `w`, `r`, `e` and their
/// `s` flags, which write a file or start a program, and also labels and branches, `a`/`i`/`c` text, comments, GNU's
/// address forms (`0,/re/`, `first~step`, `addr,+N`) and a custom address delimiter, so no reading of the text can
/// differ between the implementations. `q` with an exit code is GNU's alone.
///
/// `script` is the script: the first operand, or every `-e` value joined by newlines. `gnu` is whether GNU sed is the
/// detected flavour.
pub fn sed_script_refusal(script: &str, gnu: bool) -> Option<String> {
    let mut p = SedScan { s: script.encode_utf16().collect(), i: 0, depth: 0 };
    loop {
        while let Some(c) = p.cur() {
            if c == b' ' as u16 || c == b'\t' as u16 || c == b';' as u16 || c == NL {
                p.i += 1;
            } else {
                break;
            }
        }
        if p.i >= p.s.len() {
            break;
        }
        if p.cur() == Some(b'}' as u16) {
            if p.depth == 0 {
                return Some("a } closes no {".to_string());
            }
            p.depth -= 1;
            p.i += 1;
            if let Some(e) = p.end("}") {
                return Some(e);
            }
            continue;
        }
        let a1 = match p.address() {
            Ok(a) => a,
            Err(e) => return Some(e),
        };
        if a1 && p.cur() == Some(b',' as u16) {
            p.i += 1;
            match p.address() {
                Err(e) => return Some(e),
                Ok(false) => {
                    let lo = p.i.min(p.s.len());
                    let hi = (p.i + 2).min(p.s.len());
                    return Some(format!(
                        "the range's second address {} is not a line number, $ or /re/",
                        json_str(&p.s[lo..hi])
                    ));
                }
                Ok(true) => {}
            }
        }
        p.space();
        while p.cur() == Some(b'!' as u16) {
            p.i += 1;
            p.space();
        }
        let Some(c) = p.cur() else {
            return Some("an address with no command".to_string());
        };
        p.i += 1;
        if c == b'{' as u16 {
            p.depth += 1;
            continue;
        }
        if c < 0x80 && SED_PLAIN.contains(&(c as u8)) {
            if let Some(e) = p.end(&json_plain(c)) {
                return Some(e);
            }
            continue;
        }
        if c == b'q' as u16 {
            p.space();
            if gnu && is_digit(p.cur()) {
                while is_digit(p.cur()) {
                    p.i += 1;
                }
            }
            if let Some(e) = p.end("q") {
                return Some(e);
            }
            continue;
        }
        if c == b's' as u16 {
            let d = p.cur();
            if !sed_delim_ok(d) {
                return Some(format!(
                    "s with the delimiter {} is not described",
                    json_str(&d.map(|u| vec![u]).unwrap_or_default())
                ));
            }
            let d = d.unwrap();
            let re = match sed_regex_end(&p.s, p.i + 1, d as u32) {
                Ok(e) => e,
                Err(e) => return Some(e),
            };
            let rep = plain_delimited_end_u(&p.s, re, d as u32);
            if rep < 0 {
                return Some("an s replacement is not closed on its own line".to_string());
            }
            p.i = rep as usize;
            while let Some(f) = p.cur() {
                if f == b'g' as u16 || f == b'p' as u16 || f == b'i' as u16 || f == b'I' as u16 || is_digit(Some(f)) {
                    p.i += 1;
                } else {
                    break;
                }
            }
            if let Some(e) = p.end("an s command's flags") {
                // `/^"[wWeEmM]"/.test(e)`: the refused character is s[i], written bare inside the quotes.
                let flag = p.cur().unwrap();
                if flag < 0x80 && b"wWeEmM".contains(&(flag as u8)) {
                    return Some(format!(
                        "the s flag {} is not described: it writes a file, runs a command or changes what the regular expression matches",
                        json_str(&[flag])
                    ));
                }
                return Some(e);
            }
            continue;
        }
        if c == b'y' as u16 {
            let d = p.cur();
            if !sed_delim_ok(d) {
                return Some(format!(
                    "y with the delimiter {} is not described",
                    json_str(&d.map(|u| vec![u]).unwrap_or_default())
                ));
            }
            let d = d.unwrap() as u32;
            let from = plain_delimited_end_u(&p.s, p.i + 1, d);
            let to = if from < 0 { -1 } else { plain_delimited_end_u(&p.s, from as usize, d) };
            if to < 0 {
                return Some("a y command is not closed on its own line".to_string());
            }
            let to = to as usize;
            if p.s[(p.i + 1).min(to)..to].contains(&LBRACKET) {
                return Some("a y command holding [ is not described".to_string());
            }
            p.i = to;
            if let Some(e) = p.end("y") {
                return Some(e);
            }
            continue;
        }
        let extra = if c < 0x80 && b"wWrReF".contains(&(c as u8)) {
            ": it reads or writes a file, or runs a command"
        } else {
            ""
        };
        return Some(format!("the sed command {} is not described{}", json_str(&[c]), extra));
    }
    if p.depth > 0 {
        return Some("a { is not closed".to_string());
    }
    None
}

/// The command character as the TS passes it to `end(c)`: the bare character (not quoted).
fn json_plain(c: u16) -> String {
    String::from_utf16_lossy(&[c])
}

/// Words an awk program that is described never holds, as substrings: what runs a command, reads a file or the
/// environment the operands do not name, or changes which files are read (`ARGV`), and gawk's `@include`/`@load` and
/// indirect calls.
const AWK_REFUSED: [&str; 7] = ["system", "getline", "ENVIRON", "ARGV", "ARGC", "PROCINFO", "@"];

/// An awk operand that is an assignment (`n=1`), not a file: `/^[A-Za-z_][A-Za-z0-9_]*=/`.
pub fn is_awk_assignment(arg: &str) -> bool {
    let mut it = arg.bytes();
    match it.next() {
        Some(b) if b.is_ascii_alphabetic() || b == b'_' => {}
        _ => return false,
    }
    for b in it {
        if b == b'=' {
            return true;
        }
        if !(b.is_ascii_alphanumeric() || b == b'_') {
            return false;
        }
    }
    false
}

/// Why an awk program is not described, or None when it is. The text is checked WITHOUT a lexer, by substrings, so
/// no string, regular expression or comment can hide what is beneath it: it holds none of AWK_REFUSED, no `|` that is not
/// part of `||` (a pipe to or from a command), and no `>` after its first `print` (an output redirection needs a `print`
/// or `printf` before its `>`). A program that compares with `>` after a print is refused too; that only asks.
///
/// `text` is the program: the first operand.
pub fn awk_program_refusal(text: &str) -> Option<String> {
    if let Some(word) = AWK_REFUSED.iter().find(|w| text.contains(**w)) {
        return Some(format!(
            "the awk program holds {}, which can run a command, read a file or the environment, or change which files are read",
            json_str(&word.encode_utf16().collect::<Vec<_>>())
        ));
    }
    if text.replace("||", "").contains('|') {
        return Some("the awk program holds a | that is not ||: a pipe to or from a command".to_string());
    }
    if let Some(p) = text.find("print")
        && text[p..].contains('>')
    {
        return Some("the awk program holds a > after a print: an output redirection writes a file".to_string());
    }
    None
}
