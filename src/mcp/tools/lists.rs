//! Lists to narrow down: the findings (with your verdicts) and the string
//! literals written in the code.

use crate::analysis::{injection, Finding, Severity};
use crate::app::findings::Findings;
use crate::mcp::args::{FindingsArgs, MinSeverity, StringsArgs};
use crate::mcp::format::{
    count, is_under, limit, more, name_of, place, shown, MAX_CODE_CHARS, MAX_TEXT_CHARS,
};
use crate::mcp::guard::{Guard, Shown, WARNING};
use crate::mcp::workspace::Workspace;

const DEFAULT_ROWS: usize = 50;
const MAX_ROWS: usize = 500;

/// The findings that pass the filters, most severe first.
pub fn findings(ws: &Workspace, args: &FindingsArgs) -> Result<String, String> {
    let limit = limit(args.limit, DEFAULT_ROWS, MAX_ROWS);
    let rule = args.rule.as_deref().map(|r| r.trim().to_lowercase());
    let include_dismissed = args.include_dismissed.unwrap_or(false);
    let mut dismissed = 0;
    let findings = ws.findings();
    let guard = ws.guard();
    let kept: Vec<(usize, &Finding)> = findings
        .all()
        .iter()
        .enumerate()
        .filter(|(_, f)| is_severe_enough(f.severity, args.severity))
        .filter(|(_, f)| is_under(&f.file, args.path.as_deref()))
        .filter(|(_, f)| {
            rule.as_deref()
                .is_none_or(|r| f.rule.to_lowercase().contains(r))
        })
        .filter(|(i, _)| {
            let is_dismissed = ws.verdict(&findings, *i).is_some_and(|v| v.is_dismissed());
            dismissed += usize::from(is_dismissed);
            include_dismissed || !is_dismissed
        })
        .collect();
    let mut lines = vec![summary(&kept, dismissed, include_dismissed)];
    lines.extend(
        kept.iter()
            .take(limit)
            .map(|(i, f)| finding_line(ws, &findings, &guard, (*i, f))),
    );
    lines.extend(more(
        limit,
        kept.len(),
        "narrow with path, severity or rule",
    ));
    Ok(lines.join("\n"))
}

fn is_severe_enough(severity: Severity, at_least: Option<MinSeverity>) -> bool {
    let floor = match at_least {
        None | Some(MinSeverity::Low) => Severity::Low,
        Some(MinSeverity::Medium) => Severity::Medium,
        Some(MinSeverity::High) => Severity::High,
    };
    // High sorts first.
    severity <= floor
}

/// `12 findings: 3 high, 9 medium (2 dismissed by your verdicts …)`.
fn summary(kept: &[(usize, &Finding)], dismissed: usize, include_dismissed: bool) -> String {
    let by_severity: Vec<String> = Severity::ALL
        .iter()
        .map(|s| (s, kept.iter().filter(|(_, f)| f.severity == *s).count()))
        .filter(|(_, n)| *n > 0)
        .map(|(s, n)| format!("{n} {}", s.label()))
        .collect();
    let mut line = match by_severity.is_empty() {
        true => "No findings".to_string(),
        false => format!(
            "{}: {}",
            count(kept.len(), "finding"),
            by_severity.join(", ")
        ),
    };
    if dismissed > 0 && !include_dismissed {
        line.push_str(&format!(
            " ({dismissed} more the user marked reviewed or false positive; include_dismissed lists them)"
        ));
    }
    line
}

/// `high  strcpy  main.c:6  in main  │ message  [verdict: …]  [tool]`.
fn finding_line(
    ws: &Workspace,
    findings: &Findings,
    guard: &Guard,
    (index, f): (usize, &Finding),
) -> String {
    let function = f
        .symbol
        .map(|id| format!("  in {}", name_of(ws, id)))
        .unwrap_or_default();
    let verdict = ws
        .verdict(findings, index)
        .map(|v| format!("  [verdict: {}]", v.label()))
        .unwrap_or_default();
    // A message may quote the line (an injection's words, a call's
    // arguments with a comment inside).
    let message = match (guard.status(&f.file, f.line), f.rule == injection::RULE) {
        (Some(Shown::Withheld), true) => guard.withheld().to_string(),
        (Some(Shown::Withheld), false) => {
            "‹message withheld: its line holds a prompt injection›".to_string()
        }
        (Some(Shown::Warned), false) => {
            format!("{}   {WARNING}", shown(&f.message, MAX_TEXT_CHARS))
        }
        (Some(Shown::Warned), true) | (None, _) => shown(&f.message, MAX_TEXT_CHARS),
    };
    format!(
        "{}  {}  {}{function}  │ {message}{verdict}  [{}]",
        f.severity.label(),
        shown(&f.rule, MAX_CODE_CHARS),
        place(&f.file, f.line),
        shown(&f.tool, MAX_CODE_CHARS)
    )
}

/// String literals containing `query`, ignoring case, by file.
pub fn strings(ws: &Workspace, args: &StringsArgs) -> Result<String, String> {
    let query = args.query.trim().to_lowercase();
    if query.is_empty() {
        return Err("Give text the strings should contain.".into());
    }
    let limit = limit(args.limit, DEFAULT_ROWS, MAX_ROWS);
    let mut files: Vec<_> = ws
        .graph()
        .strings
        .iter()
        .filter(|(file, _)| is_under(file, args.path.as_deref()))
        .collect();
    files.sort_by(|a, b| a.0.cmp(b.0));
    let guard = ws.guard();
    let found: Vec<String> = files
        .into_iter()
        .flat_map(|(file, strings)| strings.iter().map(move |s| (file, s)))
        .filter(|(_, s)| s.text.to_lowercase().contains(&query))
        .map(|(file, s)| {
            let function = s
                .function
                .map(|id| format!("  in {}", name_of(ws, id)))
                .unwrap_or_default();
            let text = match guard.status(file, s.span.line) {
                Some(Shown::Withheld) => guard.withheld().to_string(),
                Some(Shown::Warned) => format!("{}   {WARNING}", shown(&s.text, MAX_CODE_CHARS)),
                None => shown(&s.text, MAX_CODE_CHARS),
            };
            format!("{}{function}  {text}", place(file, s.span.line))
        })
        .collect();
    let shown_query = shown(&args.query, MAX_CODE_CHARS);
    if found.is_empty() {
        return Ok(format!("No string literal contains `{shown_query}`."));
    }
    let mut lines = vec![format!(
        "{} containing `{shown_query}`:",
        count(found.len(), "string")
    )];
    let total = found.len();
    lines.extend(found.into_iter().take(limit));
    lines.extend(more(limit, total, "narrow with path, or raise limit"));
    Ok(lines.join("\n"))
}

#[cfg(test)]
#[path = "lists_tests.rs"]
mod tests;
