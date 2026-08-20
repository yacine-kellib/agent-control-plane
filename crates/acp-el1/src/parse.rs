//! The EL-1 lexer and parser.
//!
//! Grammar, from §8.3.1 as refined by EL-1:
//!
//! ```text
//! Expr       ::= AndExpr ("||" AndExpr)*
//! AndExpr    ::= Term ("&&" Term)*
//! Term       ::= "(" Expr ")" | Comparison
//! Comparison ::= Value ("==" | "!=" | "<" | "<=" | ">" | ">=") Value
//!              | Value "in" Set
//!              | Value ".prefixlen" "<=" Number
//! Value      ::= FieldRef | Literal | Number
//! FieldRef   ::= Identifier ("." Identifier)*
//! Literal    ::= String | TierLiteral
//! TierLiteral::= "T0" | "T1" | "T2" | "T3"
//! Set        ::= "[" Literal ("," Literal)* "]"
//! ```
//!
//! The two-production split of `Expr` IS the EL-1 fix. A single flat
//! `Expr ::= Term (("&&"|"||") Term)*` is the v1.3.3 text that permitted Z1:
//! it admits both `((a || b) && c)` and `(a || (b && c))` for one source
//! string, and 4.9% of mixed-connective expressions differ between them.
//! **Do not collapse these two functions back into one loop.** The nesting of
//! `and_expr` inside `expr` is the normative precedence, expressed as the only
//! structure that can express it.

use crate::{tier_ordinal, El1Error, Value};

/// A parsed EL-1 expression.
///
/// Public because §1246 requires the parser to be exercised as a distinct
/// artifact — the conformance obligation is on **source text producing a tree**,
/// so a test must be able to name the tree it expected. A `pub(crate)` AST
/// would force parser conformance to be inferred from evaluation results,
/// which is precisely the mistake that hid Z1: Annex B quantified over parsed
/// values and never looked at the parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    /// `lhs op rhs`, with `op` one of the six comparisons.
    Cmp(CmpOp, Operand, Operand),
    /// `lhs in [a, b, c]`.
    In(Operand, Vec<Operand>),
    /// `field.prefixlen <= n`. The field name is stored **without** the
    /// `.prefixlen` suffix, because that suffix names the operator, not the
    /// field: the environment holds `net`, and the expression asks about
    /// `net.prefixlen`.
    PrefixLen(String, Operand),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

/// One side of a comparison: either a literal or a reference to be resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operand {
    Lit(Value),
    Ref(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    /// A quoted string literal. Distinguished from `Word` so that `'T2'` is a
    /// string and `T2` is a tier — Python carries the same distinction by
    /// making one a tuple and the other a bare token.
    Str(String),
    Word(String),
    Sym(&'static str),
}

fn lex(src: &str) -> Result<Vec<Tok>, El1Error> {
    let b: Vec<char> = src.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == ' ' {
            i += 1;
            continue;
        }
        // Two-character operators first. Order matters: `<=` must be taken
        // before `<`, or `a <= b` lexes as `<` followed by a stray `=`.
        if i + 1 < b.len() {
            let two: String = b[i..i + 2].iter().collect();
            let m = match two.as_str() {
                "&&" => Some("&&"),
                "||" => Some("||"),
                "==" => Some("=="),
                "!=" => Some("!="),
                "<=" => Some("<="),
                ">=" => Some(">="),
                _ => None,
            };
            if let Some(sym) = m {
                out.push(Tok::Sym(sym));
                i += 2;
                continue;
            }
        }
        let one = match c {
            '(' => Some("("),
            ')' => Some(")"),
            '[' => Some("["),
            ']' => Some("]"),
            ',' => Some(","),
            '<' => Some("<"),
            '>' => Some(">"),
            _ => None,
        };
        if let Some(sym) = one {
            out.push(Tok::Sym(sym));
            i += 1;
            continue;
        }
        if c == '\'' {
            // An unterminated quote is a parse error, not a string running to
            // end of input. Python raises ValueError from str.index here, which
            // is a crash rather than a refusal; this refuses with the clause id
            // so the differential sees a stated reason on both sides.
            let close = (i + 1..b.len()).find(|&j| b[j] == '\'');
            let Some(j) = close else {
                return Err(El1Error::new("unterminated string literal"));
            };
            out.push(Tok::Str(b[i + 1..j].iter().collect()));
            i = j + 1;
            continue;
        }
        let start = i;
        while i < b.len() && (b[i].is_alphanumeric() || b[i] == '.' || b[i] == '_') {
            i += 1;
        }
        if i == start {
            return Err(El1Error::new(format!("illegal character {c:?}")));
        }
        out.push(Tok::Word(b[start..i].iter().collect()));
    }
    Ok(out)
}

struct P {
    t: Vec<Tok>,
    i: usize,
}

impl P {
    fn peek(&self) -> Option<&Tok> {
        self.t.get(self.i)
    }

    fn peek_sym(&self, s: &str) -> bool {
        matches!(self.peek(), Some(Tok::Sym(x)) if *x == s)
    }

    fn take(&mut self) -> Result<Tok, El1Error> {
        let t = self
            .t
            .get(self.i)
            .cloned()
            .ok_or_else(|| El1Error::new("unexpected end of expression"))?;
        self.i += 1;
        Ok(t)
    }

    /// `Expr ::= AndExpr ("||" AndExpr)*` — the loose level, left-associative.
    fn expr(&mut self) -> Result<Expr, El1Error> {
        let mut n = self.and_expr()?;
        while self.peek_sym("||") {
            self.i += 1;
            // Folding into the LEFT operand is what makes `||` left-associative:
            // `a || b || c` becomes `(a || b) || c`. `||` is associative so the
            // truth value is the same either way, but the TREE is what §1246
            // tests and what Annex B quantifies over, so it is built to the
            // rule rather than to the outcome.
            n = Expr::Or(Box::new(n), Box::new(self.and_expr()?));
        }
        Ok(n)
    }

    /// `AndExpr ::= Term ("&&" Term)*` — the tight level, left-associative.
    fn and_expr(&mut self) -> Result<Expr, El1Error> {
        let mut n = self.term()?;
        while self.peek_sym("&&") {
            self.i += 1;
            n = Expr::And(Box::new(n), Box::new(self.term()?));
        }
        Ok(n)
    }

    fn operand(&mut self) -> Result<Operand, El1Error> {
        Ok(match self.take()? {
            Tok::Str(s) => Operand::Lit(Value::Str(s)),
            Tok::Sym(s) => return Err(El1Error::new(format!("expected a value, found {s:?}"))),
            Tok::Word(w) => {
                if let Some(t) = tier_ordinal(&w) {
                    Operand::Lit(Value::Tier(t))
                } else {
                    match classify_word(&w)? {
                        Some(n) => Operand::Lit(Value::Num(n)),
                        None => Operand::Ref(w),
                    }
                }
            }
        })
    }

    /// `Term ::= "(" Expr ")" | Comparison`
    fn term(&mut self) -> Result<Expr, El1Error> {
        if self.peek_sym("(") {
            self.i += 1;
            let e = self.expr()?;
            if !self.peek_sym(")") {
                return Err(El1Error::new("unbalanced parenthesis"));
            }
            self.i += 1;
            return Ok(e);
        }

        let lhs = self.operand()?;
        let op = self.take()?;

        if matches!(&op, Tok::Word(w) if w == "in") {
            if !self.peek_sym("[") {
                return Err(El1Error::new("set literal expected"));
            }
            self.i += 1;
            let mut items = Vec::new();
            loop {
                items.push(self.operand()?);
                match self.take()? {
                    Tok::Sym("]") => break,
                    Tok::Sym(",") => continue,
                    _ => return Err(El1Error::new("malformed set")),
                }
            }
            // §8.3.1 static constraint: every Set MUST be non-empty. The loop
            // above pushes before it can break, so `items` cannot be empty and
            // this is unreachable today -- kept because the constraint is
            // normative and a future lexer change that admits `[]` should meet
            // a refusal here rather than an empty `any()` quietly yielding
            // false. Labelled a positive-path obligation, NOT a control: it
            // carries no mutant, because deleting it changes no outcome.
            if items.is_empty() {
                return Err(El1Error::new("empty set literal"));
            }
            return Ok(Expr::In(lhs, items));
        }

        // `.prefixlen <= n`. Recognised on the LEFT operand's spelling, which
        // is why it is checked before the general comparison arm: the suffix
        // names the operator, and `net.prefixlen` is not a field the
        // environment holds.
        if matches!(&op, Tok::Sym("<=")) {
            if let Operand::Ref(name) = &lhs {
                if let Some(field) = name.strip_suffix(".prefixlen") {
                    let field = field.to_string();
                    return Ok(Expr::PrefixLen(field, self.operand()?));
                }
            }
        }

        let cmp = match &op {
            Tok::Sym("==") => CmpOp::Eq,
            Tok::Sym("!=") => CmpOp::Ne,
            Tok::Sym("<") => CmpOp::Lt,
            Tok::Sym("<=") => CmpOp::Le,
            Tok::Sym(">") => CmpOp::Gt,
            Tok::Sym(">=") => CmpOp::Ge,
            other => {
                let shown = match other {
                    Tok::Word(w) => w.clone(),
                    Tok::Str(s) => format!("'{s}'"),
                    Tok::Sym(s) => s.to_string(),
                };
                return Err(El1Error::new(format!("unknown operator {shown}")));
            }
        };
        Ok(Expr::Cmp(cmp, lhs, self.operand()?))
    }
}

/// Classify a bare word: `Some(n)` a numeric literal, `None` a field
/// reference, `Err` a numeric literal this implementation cannot represent.
///
/// # The third case is the whole reason this is not an `Option`
///
/// It was one, and that was a defect — found by
/// `tools/check-el1-differential.py` probing the `i64` boundary, in code whose
/// own comment claimed the opposite behaviour.
///
/// An all-digit token beyond `i64` returned `None`, so it fell through to
/// `Operand::Ref` — a **field reference named "99999999999999999999"**, absent
/// from every environment, therefore `false` under totality. Python's integers
/// are arbitrary precision, so it compared the real value. The boundary is
/// exact: at `i64::MAX` both agree on all six operators; at `i64::MAX + 1`
/// they part on `<` and `!=`.
///
/// **The direction is what makes it serious.** A `raise_to` clause
/// `count < <huge>` fires in Python and does NOT fire here, so the recomputed
/// grade is *lower* in Rust. That is the permissive direction, arrived at
/// silently, in the fold that decides whether an action needs a human. It is
/// the RK-1/RV-1 lesson in a new place: a value that means "unknown" must
/// never take the permissive branch.
///
/// It is also a grammar point, not only a range point. §8.3.1 has
/// `FieldRef ::= Identifier ("." Identifier)*` and `Value ::= FieldRef |
/// Literal | Number`; a token of nothing but digits is a Number by the
/// grammar, and reinterpreting it as an identifier because it did not fit is
/// the parser choosing a reading the specification does not offer.
///
/// So an out-of-range numeric literal now fails **closed** at parse time under
/// clause `8.3.1`. Python still accepts it, and that residual divergence is
/// pinned and asserted from both sides in the differential — the ACP-54
/// pattern — so it going away or moving turns the check red rather than
/// passing quietly.
fn classify_word(tok: &str) -> Result<Option<i64>, El1Error> {
    let digits = tok.strip_prefix('-').unwrap_or(tok);
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
        return Ok(None); // a genuine field reference
    }
    match tok.parse::<i64>() {
        Ok(n) => Ok(Some(n)),
        Err(_) => Err(El1Error::new(format!(
            "integer literal {tok} is outside the representable range"
        ))),
    }
}

/// Parse EL-1 source into a tree, or fail closed with clause `8.3.1`.
pub fn parse(src: &str) -> Result<Expr, El1Error> {
    let mut p = P { t: lex(src)?, i: 0 };
    let e = p.expr()?;
    // Trailing tokens are a refusal, not a prefix-parse. An expression whose
    // tail was silently ignored is the shape where `a == 'x' garbage` grades as
    // `a == 'x'` -- the parser deciding, on its own, that part of a signed
    // policy did not matter.
    if p.i != p.t.len() {
        return Err(El1Error::new("trailing tokens"));
    }
    Ok(e)
}
