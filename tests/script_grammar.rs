//! script_grammar.rs — the narrow sed script and awk program (src/script_grammar.rs, ported from window-ml's src/shell/script-grammar.ts): what each accepts, every form each refuses, and the two seds' delimiter scanners held to the shared vectors.

use std::fs;
use std::path::Path;

use serde_json::Value;
use window_ml_host::script_grammar::{
    awk_program_refusal, bsd_delimited_end, gnu_regex_end, is_awk_assignment, sed_script_refusal,
};

/// Asserts `got` is a refusal containing `why` (None means the script was described).
fn refused_with(got: Option<String>, why: &str, what: &str) {
    let got = got.unwrap_or_else(|| "DESCRIBED".to_string());
    assert!(got.contains(why), "{what:?}: {got:?} lacks {why:?}");
}

// --- sed: what is described ---

#[test]
fn a_sed_script_of_plain_commands_addresses_and_s_y_is_described_under_gnu_and_bsd_alike() {
    for s in [
        "p",
        "s/a/b/",
        "s/a/b/g",
        "s/a/b/2p",
        "s|a|b|gI",
        "s/a/b/i",
        "1d",
        "$p",
        "1,3p",
        "/re/,/re2/d",
        "/x/,$d",
        "/x/!d",
        "/x/ ! d",
        "/x/{s/a/b/;p;}",
        "/x/{\ns/a/b/\np\n}",
        "h;G",
        "=",
        "q",
        "y/abc/xyz/",
        "y,a\\,b,xyz,",
        "n;N;D;P;x;g;H",
        "p\nd",
        ";;p;;",
        "  p  ",
        "s/[/]/X/",
        "s/[[:alpha:]/]/X/",
        "s/a[]/]/X/",
        "s/[^]/]/X/",
        "s/\\//X/",
        "s/[\\]/X/",
        "",
        "s/a/b/;s/c/d/g",
    ] {
        assert_eq!(sed_script_refusal(s, false), None, "bsd or undetected: {s:?}");
        assert_eq!(sed_script_refusal(s, true), None, "gnu: {s:?}");
    }
}

#[test]
fn q_with_an_exit_code_is_gnus_alone() {
    assert_eq!(sed_script_refusal("q5", true), None);
    assert_eq!(sed_script_refusal("/x/q 3", true), None);
    refused_with(sed_script_refusal("q5", false), "\"5\" after q", "q5");
}

// --- sed: what is refused ---

#[test]
fn every_sed_command_that_reads_or_writes_a_file_or_runs_a_command_is_refused_and_so_is_every_s_flag_that_does() {
    for (s, why) in [
        ("w out", "\"w\" is not described: it reads or writes a file"),
        ("1w out", "\"w\""),
        ("W out", "\"W\""),
        ("r /etc/passwd", "\"r\""),
        ("R f", "\"R\""),
        ("e", "\"e\""),
        ("e ls", "\"e\""),
        ("F", "\"F\""),
        ("/x/w out", "\"w\""),
        ("s/a/b/w out", "the s flag \"w\""),
        ("s/a/b/gw out", "the s flag \"w\""),
        ("s/a/b/e", "the s flag \"e\""),
        ("s/a/b/m", "the s flag \"m\""),
        ("s/a/b/M", "the s flag \"M\""),
        ("s/a/b/ w out", "the s flag \"w\""),
        ("s/a/b/;w out", "\"w\""),
        ("p;w out", "\"w\""),
        ("p w out", "\"w\" after p"),
        ("{w out\n}", "\"w\""),
        ("s/a/b/\nw out", "\"w\""),
    ] {
        refused_with(sed_script_refusal(s, false), why, s);
    }
}

#[test]
fn labels_branches_text_commands_comments_and_the_rest_of_sed_are_refused_so_no_reading_of_them_can_differ() {
    for (s, why) in [
        (":a;N;ba", "\":\""),
        ("b", "\"b\""),
        ("t", "\"t\""),
        ("T", "\"T\""),
        ("a text", "\"a\""),
        ("a\\\ntext", "\"a\""),
        ("i x", "\"i\""),
        ("c x", "\"c\""),
        ("#n\np", "\"#\""),
        ("p # c", "\"#\" after p"),
        ("l", "\"l\""),
        ("L", "\"L\""),
        ("Q", "\"Q\""),
        ("z", "\"z\""),
        ("v", "\"v\""),
    ] {
        refused_with(sed_script_refusal(s, false), why, s);
    }
}

#[test]
fn gnus_address_forms_and_a_custom_address_delimiter_are_refused() {
    for (s, why) in [
        ("0,/x/d", "line address 0"),
        ("0p", "line address 0"),
        ("1~2p", "\"~\""),
        ("1,+2p", "second address"),
        ("1,~4p", "second address"),
        ("\\%x%d", "its own delimiter"),
        ("/x/Id", "\"I\""),
        ("/x/Md", "\"M\""),
        ("/x/,\\%y%d", "its own delimiter"),
    ] {
        refused_with(sed_script_refusal(s, true), why, s);
    }
}

#[test]
fn a_script_whose_braces_do_not_balance_or_an_address_with_no_command_is_refused() {
    refused_with(sed_script_refusal("}", false), "closes no {", "}");
    refused_with(sed_script_refusal("/x/{p", false), "not closed", "/x/{p");
    refused_with(sed_script_refusal("1", false), "no command", "1");
    refused_with(sed_script_refusal("1}", false), "\"}\" is not described", "1}");
}

#[test]
fn an_s_or_y_that_is_not_closed_on_its_own_line_or_uses_a_delimiter_both_seds_do_not_read_as_one_byte_is_refused() {
    for (s, why) in [
        ("s/a/b", Some("replacement is not closed")),
        ("s/a", Some("not closed")),
        ("s/a\nb/c/", Some("not closed")),
        ("s/a/b\nc/", Some("not closed")),
        ("s/a/b\\\nc/", Some("not closed")),
        ("s\\a\\b\\", Some(r#"delimiter "\\""#)),
        ("s a b ", Some("delimiter \" \"")),
        ("sxaxbx", None),
        ("s", Some("delimiter \"\"")),
        ("séaébé", Some("delimiter")),
        ("y/ab/x", Some("not closed")),
        ("y/[a/xy/", Some("holding [")),
    ] {
        let got = sed_script_refusal(s, false);
        match why {
            None => assert_eq!(got, None, "{s:?}"),
            Some(why) => refused_with(got, why, s),
        }
    }
}

// --- sed: the two delimiter scanners ---

#[test]
fn a_bracket_expression_gnu_and_bsd_sed_end_in_different_places_is_refused() {
    // Measured: GNU 4.9 snarf_char_class, Apple text_cmds compile_ccl. After a class's closing `:`, GNU keeps a `[`
    // closing and `]` closes it; BSD needs `:]`. So GNU ends the regex at the second /, and BSD never.
    let s = "s/[[:a:[]/]/Q/w F";
    assert_eq!(gnu_regex_end(s, 2, '/'), 12);
    assert_eq!(bsd_delimited_end(s, 2, '/'), -1);
    refused_with(sed_script_refusal("s/[[:a:[]/]/X/", false), "not closed", "s/[[:a:[]/]/X/");
}

#[test]
fn both_scanners_skip_a_bracket_expression_whole_and_agree_where_its_classes_close() {
    for (re, end) in [
        ("[/]/", 4),
        ("[[:alpha:]/]/", 13),
        ("a[]/]/", 6),
        ("[^]/]/", 6),
        ("[[.].]/]/", 9),
        ("[[=a=]/]/", 9),
        ("\\//", 3),
        ("[\\]/", 4),
        ("[[:a:]]]/", 9),
    ] {
        let s = format!("s/{re}X/");
        assert_eq!(gnu_regex_end(&s, 2, '/'), 2 + end, "gnu {re}");
        assert_eq!(bsd_delimited_end(&s, 2, '/'), 2 + end, "bsd {re}");
    }
}

#[test]
fn a_delimiter_that_is_itself_a_bracket_ends_the_regex_at_the_first_one_for_both() {
    assert_eq!(gnu_regex_end("s[a[b[", 2, '['), 4);
    assert_eq!(bsd_delimited_end("s[a[b[", 2, '['), 4);
    assert_eq!(sed_script_refusal("s[a[b[", false), None);
}

#[test]
fn both_scanners_end_every_shared_regex_where_the_measured_sed_did() {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors/program-manifests/scanners/regex-ends.json");
    let v: Value =
        serde_json::from_str(&fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))).unwrap();
    let rows = v["rows"].as_array().unwrap();
    let row = |r: &Value| (r[0].as_str().unwrap().to_string(), r[1].as_i64().unwrap(), r[2].as_i64().unwrap());
    assert!(rows.len() > 2000, "{} rows", rows.len());
    assert!(
        rows.iter().any(|r| {
            let (_, g, b) = row(r);
            g != b
        }),
        "the vectors hold rows where GNU and BSD differ"
    );
    let differ: Vec<String> = rows
        .iter()
        .filter_map(|r| {
            let (s, g, b) = row(r);
            let (gg, bb) = (gnu_regex_end(&s, 2, '/'), bsd_delimited_end(&s, 2, '/'));
            (gg != g || bb != b).then(|| format!("{s:?}: gnu {gg} (want {g}), bsd {bb} (want {b})"))
        })
        .collect();
    assert!(differ.is_empty(), "{} mismatches, first 10: {:#?}", differ.len(), &differ[..differ.len().min(10)]);
}

// --- awk ---

#[test]
fn an_awk_program_that_only_reads_its_operands_and_prints_to_stdout_is_described() {
    for p in [
        "{print $1}",
        "{ print $2, $1 }",
        "NR>1{print}",
        "$3 > 10 {print $1}",
        "BEGIN{FS=\":\"} {n++} END{print n}",
        "a || b {print}",
        "/x/{printf \"%s\\n\", $0}",
        "{s += $1} END {print s / NR}",
        "length($0) > 72",
        "{gsub(/a/, \"b\"); print}",
    ] {
        assert_eq!(awk_program_refusal(p), None, "{p}");
    }
}

#[test]
fn an_awk_program_that_can_run_a_command_read_another_file_or_the_environment_or_write_is_refused_by_substring() {
    for (p, why) in [
        ("BEGIN{system(\"rm -rf x\")}", "\"system\""),
        ("{\"date\" | getline d}", "\"getline\""),
        ("{getline < \"/etc/passwd\"}", "\"getline\""),
        ("BEGIN{print ENVIRON[\"HOME\"]}", "\"ENVIRON\""),
        ("BEGIN{ARGV[1]=\"/etc/passwd\"; ARGC=2}", "\"ARGV\""),
        ("BEGIN{ARGC=1}", "\"ARGC\""),
        ("BEGIN{print PROCINFO[\"pid\"]}", "\"PROCINFO\""),
        ("@include \"x.awk\"", "\"@\""),
        ("BEGIN{f=\"system\"; @f()}", "\"system\""),
        ("{print > \"out\"}", "> after a print"),
        ("{print >> \"out\"}", "> after a print"),
        ("{printf \"x\" > \"/dev/stderr\"}", "> after a print"),
        ("{print | \"sh\"}", "a | that is not ||"),
        ("{print |& \"sh\"}", "a |"),
        ("{print $1 ||| x}", "a |"),
        // The check has no lexer, so a word inside a string or a comparison after a print is refused too: that only asks.
        ("{print \"system\"}", "\"system\""),
        ("{print; if (a > b) n++}", "> after a print"),
    ] {
        refused_with(awk_program_refusal(p), why, p);
    }
}

#[test]
fn an_awk_operand_is_an_assignment_only_in_the_identifier_equals_value_form_awk_itself_reads_as_one() {
    for a in ["n=1", "FS=:", "_x9=", "a=b=c"] {
        assert!(is_awk_assignment(a), "{a}");
    }
    for a in ["./n=1", "1n=2", "=x", "a-b=1", "file", "dir/a=b"] {
        assert!(!is_awk_assignment(a), "{a}");
    }
}
