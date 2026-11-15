//! The agent marking a finding: it names the finding (file, line, rule)
//! and a verdict. The app applies it (verdicts are the user's triage,
//! shown in Findings); a dismissing verdict, clearing one, or any verdict
//! on a possible prompt injection waits for the user's yes/no, so the code
//! can't clear its own findings unseen. An agent's verdict never makes the
//! project trusted.

use crate::analysis::injection;
use crate::mcp::args::{VerdictArgs, VerdictStatus};
use crate::mcp::format::{place, shown, MAX_CODE_CHARS, MAX_TEXT_CHARS};
use crate::mcp::workspace::Workspace;
use crate::notes::triage::TriageStatus;

/// A verdict to set on a finding, once it's been matched to a real one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerdictChange {
    pub file: String,
    pub line: u32,
    pub rule: String,
    /// `None` clears the verdict.
    pub status: Option<TriageStatus>,
    pub note: String,
    /// Whether the finding is a possible prompt injection.
    pub is_injection: bool,
}

impl VerdictChange {
    /// Whether it needs the user's approval: dismissing a finding, clearing
    /// one, or touching a possible prompt injection.
    pub fn needs_approval(&self) -> bool {
        self.is_injection
            || self.status.is_none()
            || matches!(
                self.status,
                Some(TriageStatus::Reviewed | TriageStatus::FalsePositive)
            )
    }

    /// `false positive on strcpy at main.c:6`, for the approval prompt.
    pub fn summary(&self) -> String {
        let status = match self.status {
            Some(status) => status.label().to_lowercase(),
            None => "clear the verdict".into(),
        };
        format!(
            "{status} on {} at {}",
            shown(&self.rule, MAX_CODE_CHARS),
            place(&self.file, self.line)
        )
    }
}

/// The verdict `args` asks for, matched to a real finding; or why not.
pub fn verdict_change(ws: &Workspace, args: &VerdictArgs) -> Result<VerdictChange, String> {
    let status = match args.status {
        VerdictStatus::Confirmed => Some(TriageStatus::ConfirmedBug),
        VerdictStatus::FalsePositive => Some(TriageStatus::FalsePositive),
        VerdictStatus::Reviewed => Some(TriageStatus::Reviewed),
        VerdictStatus::Clear => None,
    };
    let rule = args.rule.trim();
    let findings = ws.findings();
    let matched = findings
        .all()
        .iter()
        .find(|f| f.file == args.file && f.line == args.line && f.rule.eq_ignore_ascii_case(rule));
    let Some(finding) = matched else {
        return Err(format!(
            "No {} finding at {}. Use findings to see them, with their exact rule, file and line.",
            shown(rule, MAX_CODE_CHARS),
            place(&args.file, args.line)
        ));
    };
    let note = args
        .note
        .as_deref()
        .map(|n| shown(n.trim(), MAX_TEXT_CHARS))
        .unwrap_or_default();
    Ok(VerdictChange {
        file: finding.file.clone(),
        line: finding.line,
        rule: finding.rule.clone(),
        status,
        note,
        is_injection: finding.rule == injection::RULE,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::fixture::workspace;

    fn args(file: &str, line: u32, rule: &str, status: VerdictStatus) -> VerdictArgs {
        VerdictArgs {
            file: file.into(),
            line,
            rule: rule.into(),
            status,
            note: Some("the length is bounded".into()),
        }
    }

    #[test]
    fn a_verdict_is_matched_to_a_real_finding() {
        let ws = workspace();
        let change = verdict_change(&ws, &args("main.c", 6, "strcpy", VerdictStatus::Confirmed))
            .expect("match");
        assert_eq!(change.status, Some(TriageStatus::ConfirmedBug));
        assert!(!change.is_injection);
        assert!(
            !change.needs_approval(),
            "confirming a normal bug is not risky"
        );
        assert_eq!(change.note, "the length is bounded");
    }

    #[test]
    fn dismissing_and_clearing_need_approval() {
        let ws = workspace();
        let fp = verdict_change(
            &ws,
            &args("main.c", 6, "STRCPY", VerdictStatus::FalsePositive),
        )
        .expect("case-insensitive rule");
        assert!(fp.needs_approval());
        assert!(fp
            .summary()
            .contains("false positive on strcpy at main.c:6"));
        let clear =
            verdict_change(&ws, &args("main.c", 6, "strcpy", VerdictStatus::Clear)).expect("clear");
        assert!(clear.needs_approval());
        assert_eq!(clear.status, None);
    }

    #[test]
    fn a_verdict_on_a_finding_that_isnt_there_is_refused() {
        let ws = workspace();
        let error = verdict_change(&ws, &args("main.c", 6, "nope", VerdictStatus::Confirmed))
            .expect_err("no such finding");
        assert!(error.contains("findings"), "{error}");
        let error = verdict_change(&ws, &args("main.c", 99, "strcpy", VerdictStatus::Confirmed))
            .expect_err("wrong line");
        assert!(error.contains("No strcpy finding"), "{error}");
    }
}
