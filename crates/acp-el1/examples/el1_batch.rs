//! Evaluate a batch of EL-1 cases and print one verdict per line.
//!
//! Driven by `tools/check-el1-differential.py`, which generates the cases,
//! evaluates them with `reference/src/acp_executor.py`, and requires the two
//! implementations to agree on **every** one.
//!
//! # Why this exists
//!
//! `diff_prose.py` found Z1 by running two evaluators written independently
//! **from the prose** and diffing them on generated source text. That method
//! found the ambiguity; it says nothing about whether the two *production*
//! evaluators agree today. §1246 requires the parser conformance vectors to be
//! run "against the deployment's own parser", and this repository has two
//! deployments of one specification — so the same method, pointed at Python and
//! Rust, is the check that the fix actually holds in both.
//!
//! CLAUDE.md's framing: the first divergence between the reference and Rust on
//! a shared input is a **specification ambiguity**, which is exactly how Z1 was
//! found in the first place.
//!
//! # The line protocol, and why it is not JSON
//!
//! Input file, one case per line, tab-separated:
//!
//! ```text
//! <el1-source>\t<name>:<tag>:<value>\t<name>:<tag>:<value>...
//! ```
//!
//! `tag` is `str`, `num`, `tier` or `cidr` — the same four tags
//! `acp_executor.py` carries in its `(tag, value)` environment tuples.
//!
//! Output, one line per input line:
//!
//! ```text
//! OK<TAB>true | OK<TAB>false | ERR<TAB><clause><TAB><message>
//! ```
//!
//! No serialiser, for the reason `acp-crypto/examples/emit_signatures.rs`
//! gives: the generator picks every identifier and literal from a fixed
//! vocabulary with no tabs and no colons in it, so there is nothing to escape,
//! and a dependency added for typing convenience is still a dependency. It
//! matters more here than there — the whole point of `acp-el1` is that this
//! deployment can answer for its own parser.

use acp_el1::{parse, Env, Value};

fn main() {
    let path = match std::env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("usage: el1_batch <cases-file>");
            std::process::exit(2);
        }
    };
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("cannot read {path}: {e}");
            std::process::exit(2);
        }
    };

    let mut out = String::new();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split('\t');
        let src = parts.next().unwrap_or("");

        let mut env = Env::new();
        for binding in parts {
            // name:tag:value. `splitn(3, ..)` keeps a value containing a colon
            // intact even though the generator does not currently emit one --
            // a parser that silently drops the tail of its own input is the
            // defect `parse-trailing-tokens` exists to catch, one layer down.
            let mut f = binding.splitn(3, ':');
            let (Some(name), Some(tag), Some(val)) = (f.next(), f.next(), f.next()) else {
                eprintln!("malformed binding: {binding:?}");
                std::process::exit(2);
            };
            let value = match tag {
                "str" => Value::Str(val.to_string()),
                "num" => match val.parse::<i64>() {
                    Ok(n) => Value::Num(n),
                    Err(_) => {
                        eprintln!("bad num: {val:?}");
                        std::process::exit(2);
                    }
                },
                "tier" => match val.parse::<u8>() {
                    Ok(n) if n <= 3 => Value::Tier(n),
                    _ => {
                        eprintln!("bad tier: {val:?}");
                        std::process::exit(2);
                    }
                },
                "cidr" => match val.parse::<u8>() {
                    Ok(n) => Value::Cidr(n),
                    Err(_) => {
                        eprintln!("bad cidr: {val:?}");
                        std::process::exit(2);
                    }
                },
                // An unknown tag EXITS rather than defaulting to absent.
                // Defaulting would make a harness bug look like agreement:
                // both sides would evaluate against an empty environment and
                // dutifully report the same answer about nothing.
                other => {
                    eprintln!("unknown tag: {other:?}");
                    std::process::exit(2);
                }
            };
            env.insert(name.to_string(), value);
        }

        match parse(src) {
            Ok(tree) => {
                out.push_str("OK\t");
                out.push_str(if acp_el1::eval(&tree, &env) { "true" } else { "false" });
            }
            Err(e) => {
                out.push_str("ERR\t");
                out.push_str(e.clause);
                out.push('\t');
                // Newlines would desynchronise the line protocol. No message
                // contains one today; this is cheap and keeps that from
                // becoming a silent corruption if one ever does.
                out.push_str(&e.message.replace(['\n', '\t'], " "));
            }
        }
        out.push('\n');
    }
    print!("{out}");
}
