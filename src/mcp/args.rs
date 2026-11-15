//! What each tool takes. The doc comments become the descriptions the
//! agent reads in each tool's schema, so they say what to pass.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct FindSymbolArgs {
    /// Part of a name, matched fuzzily: `parse_hdr` finds `parse_header`,
    /// `dbimplwr` finds `DBImpl::Write`.
    pub query: String,
    /// Most results to list (default 20, at most 100).
    pub limit: Option<u32>,
}

#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct SymbolArgs {
    /// A function, type or variable: qualified (`Foo::bar`) or short (`bar`).
    pub name: String,
    /// The project-relative file it is in, when several share the name.
    pub file: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct ReadSourceArgs {
    /// A project-relative file, as tools list them: `net/parse.c`.
    pub file: String,
    /// First line to show, from 1.
    pub start_line: u32,
    /// Last line to show (default 80 lines on; at most 200 lines a call).
    pub end_line: Option<u32>,
}

#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct CallArgs {
    /// A function: qualified (`Foo::bar`) or short (`bar`).
    pub name: String,
    /// The project-relative file it is in, when several share the name.
    pub file: Option<String>,
    /// Levels to follow (default 1, at most 4).
    pub depth: Option<u32>,
}

#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct XrefsArgs {
    /// A symbol (`Foo::bar`, `bar`) or a library function the project calls
    /// (`memcpy`, `system`).
    pub name: String,
    /// The project-relative file the symbol is in, when several share it.
    pub file: Option<String>,
    /// Only references in this project-relative folder or file.
    pub path: Option<String>,
    /// Most references to list (default 100, at most 500).
    pub limit: Option<u32>,
}

#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct LibraryArgs {
    /// Part of a name, matched fuzzily; leave out to list the most called.
    pub query: Option<String>,
    /// Most functions to list (default 50, at most 500).
    pub limit: Option<u32>,
}

/// How severe a finding is, at least.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum MinSeverity {
    High,
    Medium,
    Low,
}

#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct FindingsArgs {
    /// Only findings at least this severe.
    pub severity: Option<MinSeverity>,
    /// Only findings in this project-relative folder or file.
    pub path: Option<String>,
    /// Only findings of rules whose name contains this (`strcpy`, `format`).
    pub rule: Option<String>,
    /// Also list findings the user marked reviewed or false positive.
    pub include_dismissed: Option<bool>,
    /// Most findings to list (default 50, at most 500).
    pub limit: Option<u32>,
}

#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct StringsArgs {
    /// Text the string literal contains, ignoring case.
    pub query: String,
    /// Only strings in this project-relative folder or file.
    pub path: Option<String>,
    /// Most strings to list (default 50, at most 500).
    pub limit: Option<u32>,
}

#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct NotesArgs {
    /// Only notes on lines of files in this project-relative folder or file.
    pub path: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct AddNoteArgs {
    /// What the note is on: a symbol (`Foo::bar`, `bar`) or a line
    /// (`net/parse.c:14`).
    pub target: String,
    /// The note. It is added below any note already there, marked as yours.
    pub text: String,
}

#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct FuzzTargetsArgs {
    /// Only functions in this project-relative folder or file.
    pub path: Option<String>,
    /// Most functions to list (default 20, at most 100).
    pub limit: Option<u32>,
}

/// Which fuzzer a harness is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Fuzzer {
    Libfuzzer,
    Afl,
}

#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct HarnessArgs {
    /// The function to fuzz: qualified (`Foo::bar`) or short (`bar`).
    pub name: String,
    /// The project-relative file it is defined in, when several define it.
    pub file: Option<String>,
    /// libfuzzer (default) or afl (AFL++ persistent mode).
    pub fuzzer: Option<Fuzzer>,
    /// The project-relative folder you'll save the files in, which the
    /// Makefile's paths are written for (default `.aavr/harnesses/<name>`).
    pub folder: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct InputPathsArgs {
    /// A function to show how input reaches; leave out for where input
    /// comes in and the findings it reaches.
    pub name: Option<String>,
    /// The project-relative file it is in, when several share the name.
    pub file: Option<String>,
    /// Most findings to list (default 50, at most 500).
    pub limit: Option<u32>,
}

/// Which way to follow a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum TraceDirection {
    /// Back to where it comes from (outside input, a constant, a parameter).
    Back,
    /// Forward to the risky calls it reaches.
    Forward,
    /// Forward to one call you name (sink_file, sink_line, sink_call).
    To,
}

#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct TraceArgs {
    /// The project-relative file the value is in.
    pub file: String,
    /// The line it is on.
    pub line: u32,
    /// The variable on that line. Leave out (with back) to trace the
    /// arguments of the risky call on that line.
    pub name: Option<String>,
    /// back (default), forward, or to.
    pub direction: Option<TraceDirection>,
    /// For to: the file of the call it should reach.
    pub sink_file: Option<String>,
    /// For to: the line of that call.
    pub sink_line: Option<u32>,
    /// For to: the function called there (`memcpy`).
    pub sink_call: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct DraftRuleArgs {
    /// The project-relative file of the code to find more of.
    pub file: String,
    /// Its first line.
    pub first_line: u32,
    /// Its last line (default: just the first).
    pub last_line: Option<u32>,
    /// Match the call with any arguments, not just ones shaped like these.
    pub any_values: Option<bool>,
}

#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct JournalArgs {
    /// The entry, in Markdown: what was done, found or ruled out in this
    /// phase. It is marked as yours.
    pub text: String,
    /// The project line it is about, as `file:line` (optional).
    pub place: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct ImportSarifArgs {
    /// The project-relative path of a SARIF report you wrote, such as
    /// `.aavr/runs/semgrep-1/results.sarif`.
    pub file: String,
}

/// A verdict the agent sets on a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum VerdictStatus {
    /// A real bug (also bookmarks the line).
    Confirmed,
    /// Not a real problem.
    FalsePositive,
    /// Looked at, left as is.
    Reviewed,
    /// Remove any verdict.
    Clear,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct VerdictArgs {
    /// The finding's project-relative file, as `findings` lists it.
    pub file: String,
    /// Its line.
    pub line: u32,
    /// Its rule, as `findings` lists it (`strcpy`, a semgrep id).
    pub rule: String,
    /// confirmed, false_positive, reviewed or clear.
    pub status: VerdictStatus,
    /// Why, in a few words (optional). Shown to the user.
    pub note: Option<String>,
}
