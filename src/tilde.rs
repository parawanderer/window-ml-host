//! tilde.rs — expanding a leading `~` in an argument to the host's HOME, the one rule `spawn` applies to argv and
//! `cwd` before it resolves, judges or runs anything (PROTOCOL.md, "Tilde").

use std::path::Path;

use serde_json::{Value, json};

/// The `reason` of a tilde entry whose HOME is unset or empty. A fixed value the worker can switch on, never free text.
pub const NO_HOME: &str = "no-home";
/// The `reason` of a tilde entry whose HOME is relative.
pub const HOME_NOT_ABSOLUTE: &str = "home-not-absolute";

/// What became of one argument.
#[derive(Debug, PartialEq, Eq)]
pub enum Expanded {
    /// Not a tilde argument: left alone, and no fact.
    Untouched,
    /// Expanded to this.
    To(String),
    /// A tilde argument that stays literal because HOME is unusable; the reason.
    NoHome(&'static str),
}

/// Expands `arg` when it is exactly `~` or starts with `~/`. Nothing else expands: not `~user`, not `x=~/a`, not
/// `a~/b`, no glob and no `$VAR`. HOME counts as absent when unset, empty or not absolute.
pub fn expand(arg: &str, home: Option<&Path>) -> Expanded {
    let rest = if arg == "~" {
        ""
    } else if let Some(r) = arg.strip_prefix("~/") {
        r
    } else {
        return Expanded::Untouched;
    };
    // Unset, empty and not valid UTF-8 are all "no HOME"; a relative one is told apart.
    let Some(h) = home.and_then(Path::to_str).filter(|h| !h.is_empty()) else {
        return Expanded::NoHome(NO_HOME);
    };
    if !home.is_some_and(Path::is_absolute) {
        return Expanded::NoHome(HOME_NOT_ABSOLUTE);
    }
    if arg == "~" {
        return Expanded::To(h.to_string());
    }
    Expanded::To(format!("{}/{}", h.trim_end_matches('/'), rest))
}

/// Rewrites `arg` in place and returns its `tilde` fact entry, or `None` when it was not a tilde argument.
pub fn apply(arg: &mut String, index: Value, home: Option<&Path>) -> Option<Value> {
    match expand(arg, home) {
        Expanded::Untouched => None,
        Expanded::To(to) => {
            let from = std::mem::replace(arg, to.clone());
            Some(json!({ "index": index, "from": from, "to": to }))
        }
        Expanded::NoHome(why) => Some(json!({ "index": index, "from": arg, "to": null, "reason": why })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Option<&Path> {
        Some(Path::new(s))
    }

    #[test]
    fn a_whole_tilde_or_a_tilde_slash_prefix_expands() {
        assert_eq!(expand("~", h("/home/u")), Expanded::To("/home/u".into()));
        assert_eq!(expand("~/x/y", h("/home/u")), Expanded::To("/home/u/x/y".into()));
        assert_eq!(expand("~/", h("/home/u")), Expanded::To("/home/u/".into()));
    }

    #[test]
    fn a_home_of_slash_or_with_a_trailing_slash_does_not_double_it() {
        assert_eq!(expand("~/rest", h("/")), Expanded::To("/rest".into()));
        assert_eq!(expand("~/rest", h("/home/u/")), Expanded::To("/home/u/rest".into()));
        assert_eq!(expand("~", h("/")), Expanded::To("/".into()));
    }

    fn literal(a: &str) {
        assert_eq!(expand(a, h("/home/u")), Expanded::Untouched, "{a:?}");
    }

    #[test]
    fn tilde_user_stays_literal() {
        literal("~user");
        literal("~user/x");
    }

    #[test]
    fn a_tilde_after_the_start_stays_literal() {
        literal("a~b");
        literal("a~/b");
        literal("x/~");
        literal(" ~/x");
    }

    #[test]
    fn nothing_after_an_equals_sign_expands() {
        literal("--flag=~/x");
        literal("x=~/a");
    }

    #[test]
    fn double_tilde_and_a_trailing_space_stay_literal() {
        literal("~~");
        literal("~ ");
        literal("");
    }

    #[test]
    fn variables_and_globs_never_expand() {
        literal("$HOME/x");
        literal("*");
    }

    #[test]
    fn an_unusable_home_leaves_the_argument_with_a_reason() {
        assert_eq!(expand("~/x", None), Expanded::NoHome("no-home"));
        assert_eq!(expand("~", h("")), Expanded::NoHome("no-home"));
        assert_eq!(expand("~/x", h("rel/home")), Expanded::NoHome("home-not-absolute"));
        assert_eq!(expand("~/x", h(".")), Expanded::NoHome("home-not-absolute"));
        // A non-tilde argument is never touched, whatever HOME is.
        assert_eq!(expand("x", None), Expanded::Untouched);
    }

    #[test]
    fn apply_rewrites_and_reports_the_original() {
        let mut a = "~/n.txt".to_string();
        let f = apply(&mut a, json!(1), h("/home/u")).unwrap();
        assert_eq!(a, "/home/u/n.txt");
        assert_eq!(f, json!({ "index": 1, "from": "~/n.txt", "to": "/home/u/n.txt" }));

        let mut c = "~/p".to_string();
        let f = apply(&mut c, json!("cwd"), None).unwrap();
        assert_eq!(c, "~/p", "literal without HOME");
        assert_eq!(f, json!({ "index": "cwd", "from": "~/p", "to": null, "reason": "no-home" }));

        let mut p = "plain".to_string();
        assert!(apply(&mut p, json!(0), h("/h")).is_none());
    }
}
