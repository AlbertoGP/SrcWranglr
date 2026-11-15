//! Whether a comment or string reads like instructions to an AI agent:
//! words telling it to drop its instructions, text addressed to it, a chat
//! template's markers, or text hidden in characters that don't show.
//!
//! This is a tripwire for review, not a filter: paraphrase, another
//! language or an encoding gets past any word list. Weak cues (asking for
//! a clean verdict, not to report something) count only when the same
//! text names an AI, so ordinary comments ("safe to call from IRQ
//! context", "do not report errors") don't trip it.

pub use crate::model::Cue;

/// Lower-case text some cue needs (besides the word "ai"), to pass most
/// comments cheaply.
const MAY_INSTRUCT: [&str; 31] = [
    "ignor",
    "disregard",
    "forget",
    "overrid",
    "bypass",
    "prompt",
    "jailbr",
    "you",
    "note",
    "message",
    "instruct",
    "remind",
    "attention",
    "notice",
    "memo",
    "warning",
    "hint",
    "dear",
    "hey",
    "hello",
    "attn",
    "psst",
    "llm",
    "gpt",
    "claude",
    "gemini",
    "copilot",
    "glm",
    "grok",
    "llama",
    "qwen",
];

/// Markers of the chat templates models are trained on.
const CHAT_TOKENS: [&str; 14] = [
    "<|im_start|>",
    "<|im_end|>",
    "<|system|>",
    "<|user|>",
    "<|assistant|>",
    "<|endoftext|>",
    "<|eot_id|>",
    "<|start_header_id|>",
    "[inst]",
    "[/inst]",
    "<<sys>>",
    "<</sys>>",
    "<start_of_turn>",
    "<end_of_turn>",
];

/// Words naming an AI model or assistant.
const AI_NAMES: &[&str] = &[
    "ai", "llm", "llms", "chatgpt", "gpt", "claude", "gemini", "copilot", "glm", "grok", "llama",
    "mistral", "deepseek", "qwen",
];

/// One word of a phrase: any of `words`, or (if `optional`) none.
struct Slot {
    words: &'static [&'static str],
    optional: bool,
}

const fn word(words: &'static [&'static str]) -> Slot {
    Slot {
        words,
        optional: false,
    }
}

const fn maybe(words: &'static [&'static str]) -> Slot {
    Slot {
        words,
        optional: true,
    }
}

const AI: Slot = word(AI_NAMES);

/// Phrases that are a cue on their own.
const STRONG: &[&[Slot]] = &[
    &[
        word(&["ignore", "disregard", "forget", "override", "bypass"]),
        maybe(&["all", "any", "the", "your", "these", "those", "every"]),
        maybe(&["of"]),
        maybe(&["the", "your", "my"]),
        word(&[
            "previous",
            "prior",
            "above",
            "earlier",
            "preceding",
            "initial",
            "original",
            "existing",
            "system",
            "safety",
            "security",
            "former",
        ]),
        word(&[
            "instructions",
            "instruction",
            "prompt",
            "prompts",
            "rules",
            "directions",
            "directives",
            "guidelines",
            "guidance",
            "context",
            "messages",
            "constraints",
            "guardrails",
        ]),
    ],
    &[
        word(&["ignore", "disregard", "forget"]),
        word(&["everything", "anything", "all"]),
        word(&["above", "before", "previously", "earlier"]),
    ],
    &[word(&["system"]), word(&["prompt", "prompts"])],
    &[
        word(&[
            "note",
            "message",
            "instructions",
            "instruction",
            "reminder",
            "attention",
            "notice",
            "memo",
            "warning",
            "hint",
        ]),
        word(&["to", "for"]),
        maybe(&["the", "any", "all", "an", "a", "every", "you"]),
        AI,
    ],
    &[
        word(&["dear", "hey", "hello", "hi", "attention", "attn", "psst"]),
        maybe(&["the", "you", "dear"]),
        AI,
    ],
    &[
        word(&["if"]),
        word(&["you"]),
        word(&["are", "re"]),
        maybe(&["a", "an", "the"]),
        word(&["ai", "llm", "assistant", "chatbot", "language"]),
    ],
    &[
        word(&["you"]),
        word(&["are", "re"]),
        maybe(&["now"]),
        maybe(&["a", "an", "the"]),
        maybe(&["helpful", "friendly", "new", "large"]),
        word(&[
            "ai",
            "llm",
            "assistant",
            "chatbot",
            "chatgpt",
            "claude",
            "gemini",
            "copilot",
            "glm",
        ]),
    ],
    &[word(&["jailbreak", "jailbroken", "jailbreaking"])],
    &[word(&["prompt"]), word(&["injection", "injections"])],
];

/// Phrases that are a cue only in text that names an AI.
const WEAK: &[&[Slot]] = &[
    &[
        word(&[
            "mark", "label", "classify", "report", "treat", "consider", "flag", "rate",
        ]),
        maybe(&["this", "it", "that", "the", "these"]),
        maybe(&[
            "code",
            "function",
            "file",
            "line",
            "finding",
            "issue",
            "bug",
            "module",
            "project",
            "repository",
            "repo",
        ]),
        word(&["as"]),
        maybe(&["a", "an"]),
        word(&[
            "safe", "secure", "benign", "harmless", "reviewed", "clean", "false", "fine", "ok",
            "okay", "trusted", "not",
        ]),
    ],
    &[
        word(&["do", "does", "should", "must", "will"]),
        word(&["not", "never"]),
        word(&[
            "report",
            "flag",
            "mention",
            "disclose",
            "reveal",
            "analyze",
            "analyse",
            "audit",
            "scan",
            "examine",
            "investigate",
            "review",
        ]),
    ],
    &[
        word(&["don't", "dont", "never"]),
        word(&[
            "report",
            "flag",
            "mention",
            "disclose",
            "reveal",
            "analyze",
            "analyse",
            "audit",
            "scan",
            "examine",
            "investigate",
            "review",
        ]),
    ],
    &[
        word(&["no", "zero"]),
        maybe(&["any", "known", "real", "security"]),
        word(&[
            "vulnerability",
            "vulnerabilities",
            "bugs",
            "issues",
            "findings",
        ]),
    ],
    &[
        word(&[
            "new", "updated", "real", "actual", "hidden", "secret", "revised",
        ]),
        word(&["instructions", "instruction", "directives", "orders"]),
    ],
];

/// What makes `text` read like instructions to an AI agent, if anything.
pub fn cue_in(text: &str) -> Option<Cue> {
    if text.chars().any(is_invisible_text) {
        return Some(Cue::InvisibleText);
    }
    let lower = text.to_lowercase();
    if let Some(token) = CHAT_TOKENS.iter().find(|t| lower.contains(*t)) {
        return Some(Cue::ChatToken(token));
    }
    if MAY_INSTRUCT.iter().any(|needle| lower.contains(needle)) || has_word(&lower, "ai") {
        if let Some(found) = phrase_in(&words(&lower)) {
            return Some(Cue::Phrase(found));
        }
    }
    text.chars()
        .any(is_hidden_character)
        .then_some(Cue::HiddenCharacters)
}

fn phrase_in(words: &[&str]) -> Option<String> {
    let found = first_match(STRONG, words);
    let is_named = || words.iter().any(|w| AI_NAMES.contains(w));
    found
        .or_else(|| is_named().then(|| first_match(WEAK, words)).flatten())
        .map(|matched| matched.join(" "))
}

/// The words of the first of `phrases` found in `words`.
fn first_match<'w>(phrases: &[&[Slot]], words: &[&'w str]) -> Option<Vec<&'w str>> {
    (0..words.len()).find_map(|start| {
        phrases.iter().find_map(|slots| {
            matched(slots, &words[start..]).map(|n| words[start..start + n].to_vec())
        })
    })
}

/// How many of `words` (from the first) `slots` match, if they do.
fn matched(slots: &[Slot], words: &[&str]) -> Option<usize> {
    let Some((slot, rest)) = slots.split_first() else {
        return Some(0);
    };
    let taken = words
        .first()
        .filter(|w| slot.words.contains(w))
        .and_then(|_| matched(rest, &words[1..]).map(|n| n + 1));
    match (taken, slot.optional) {
        (Some(n), _) => Some(n),
        (None, true) => matched(rest, words),
        (None, false) => None,
    }
}

/// Whether `word` appears in `lower` on its own, not inside another word.
fn has_word(lower: &str, word: &str) -> bool {
    let is_letter = |c: Option<char>| c.is_some_and(char::is_alphanumeric);
    lower.match_indices(word).any(|(at, _)| {
        !is_letter(lower[..at].chars().next_back())
            && !is_letter(lower[at + word.len()..].chars().next())
    })
}

/// `lower`'s words: letters, digits and apostrophes.
fn words(lower: &str) -> Vec<&str> {
    lower
        .split(|c: char| !(c.is_alphanumeric() || c == '\''))
        .map(|w| w.trim_matches('\''))
        .filter(|w| !w.is_empty())
        .collect()
}

/// Unicode tag characters and supplementary variation selectors: they
/// show as nothing, yet can spell out text a model reads.
fn is_invisible_text(c: char) -> bool {
    matches!(c, '\u{E0000}'..='\u{E007F}' | '\u{E0100}'..='\u{E01EF}')
}

/// Zero-width and text-direction characters.
fn is_hidden_character(c: char) -> bool {
    matches!(
        c,
        '\u{061C}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{FEFF}'
    )
}

#[cfg(test)]
#[path = "cues_tests.rs"]
mod tests;
