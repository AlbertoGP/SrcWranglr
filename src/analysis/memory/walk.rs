//! Walking a function body in source order to find use-after-free and
//! double-free. Each pointer variable that is freed is tracked; a later
//! dereference or pass-to-a-call of it is a use-after-free, a second free a
//! double-free. Branches merge conservatively: freed on every path stays
//! certain (high), freed on some path becomes "maybe" (medium). This is
//! intraprocedural and syntactic — a lead to confirm, like the other
//! findings.

use std::collections::{HashMap, HashSet};

use tree_sitter::{Node, Parser};

use super::names;
use super::state::{merge, Freed};
use crate::analysis::{Finding, Severity};
use crate::index::functions_holding_lines;
use crate::model::{CodeGraph, SymbolId};

const USE_AFTER_FREE: &str = "use-after-free";
const DOUBLE_FREE: &str = "double-free";

/// Which freed variables are live at a point, and where each was freed.
type State = HashMap<String, Freed>;

/// A use-after-free or double-free the walk found.
struct Violation {
    rule: &'static str,
    file: String,
    free_line: u32,
    at_line: u32,
    columns: Option<(u32, u32)>,
    variable: String,
    /// Freed on every path (high) rather than only some (medium).
    certain: bool,
}

/// Use-after-free and double-free findings across the project.
pub fn findings(graph: &CodeGraph) -> Vec<Finding> {
    let Some(mut parser) = new_parser() else {
        return Vec::new();
    };
    let mut violations = Vec::new();
    for (file, source) in &graph.file_contents {
        // Cheap gate: every free-like name contains "free".
        if !source.contains("free") {
            continue;
        }
        if let Some(tree) = parser.parse(source, None) {
            walk_functions(file, source, tree.root_node(), &mut violations);
        }
    }
    let places: Vec<(&str, u32)> = violations
        .iter()
        .map(|v| (v.file.as_str(), v.at_line))
        .collect();
    let symbols = functions_holding_lines(graph, &places);
    violations
        .into_iter()
        .zip(symbols)
        .map(|(violation, symbol)| violation.into_finding(symbol))
        .collect()
}

fn new_parser() -> Option<Parser> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .ok()?;
    Some(parser)
}

/// Walk each function definition in the tree with a fresh state.
fn walk_functions(file: &str, source: &str, root: Node, out: &mut Vec<Violation>) {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "function_definition" {
            if let Some(body) = node.child_by_field_name("body") {
                walk_stmt(file, source, body, &mut State::new(), out);
            }
            continue;
        }
        for child in named_children(node) {
            stack.push(child);
        }
    }
}

/// Carry the state through one statement, in source order.
fn walk_stmt(file: &str, source: &str, node: Node, state: &mut State, out: &mut Vec<Violation>) {
    match node.kind() {
        "compound_statement" => {
            for stmt in named_children(node) {
                walk_stmt(file, source, stmt, state, out);
            }
        }
        "if_statement" => walk_if(file, source, node, state, out),
        "for_statement" | "while_statement" | "do_statement" => {
            walk_loop(file, source, node, state, out);
        }
        "switch_statement" => walk_switch(file, source, node, state, out),
        _ => visit_expr(file, source, node, state, out),
    }
}

/// Both arms of an `if`, merged conservatively after the join.
fn walk_if(file: &str, source: &str, node: Node, state: &mut State, out: &mut Vec<Violation>) {
    if let Some(cond) = node.child_by_field_name("condition") {
        visit_expr(file, source, cond, state, out);
    }
    let mut arms = Vec::new();
    if let Some(cons) = node.child_by_field_name("consequence") {
        let mut branch = state.clone();
        walk_stmt(file, source, cons, &mut branch, out);
        arms.push(branch);
    }
    match node.child_by_field_name("alternative") {
        Some(alt) => {
            let mut branch = state.clone();
            walk_stmt(file, source, alt, &mut branch, out);
            arms.push(branch);
        }
        // No else: the other path leaves the state as it entered.
        None => arms.push(state.clone()),
    }
    *state = merge_states(&arms);
}

/// A loop body may or may not run, so a free inside it is only "maybe".
fn walk_loop(file: &str, source: &str, node: Node, state: &mut State, out: &mut Vec<Violation>) {
    if let Some(cond) = node.child_by_field_name("condition") {
        visit_expr(file, source, cond, state, out);
    }
    if let Some(body) = node.child_by_field_name("body") {
        let mut ran = state.clone();
        walk_stmt(file, source, body, &mut ran, out);
        *state = merge_states(&[state.clone(), ran]);
    }
}

/// A `switch`: walk the body, then weaken any frees to "maybe" since which
/// case ran is conditional.
fn walk_switch(file: &str, source: &str, node: Node, state: &mut State, out: &mut Vec<Violation>) {
    if let Some(body) = node.child_by_field_name("body") {
        let mut inner = state.clone();
        walk_stmt(file, source, body, &mut inner, out);
        for freed in inner.values_mut() {
            *freed = freed.demote();
        }
        *state = merge_states(&[state.clone(), inner]);
    }
}

/// Walk an expression (statement) for frees, reassignments and uses.
fn visit_expr(file: &str, source: &str, node: Node, state: &mut State, out: &mut Vec<Violation>) {
    match node.kind() {
        "assignment_expression" => {
            if let Some(right) = node.child_by_field_name("right") {
                visit_expr(file, source, right, state, out);
            }
            if let Some(left) = node.child_by_field_name("left") {
                if left.kind() == "identifier" {
                    // Reassigned: the variable is live again.
                    state.remove(text(source, left));
                } else {
                    // `*p = …`, `p->f = …`: a write through the pointer.
                    visit_expr(file, source, left, state, out);
                }
            }
        }
        "init_declarator" => {
            if let Some(value) = node.child_by_field_name("value") {
                visit_expr(file, source, value, state, out);
            }
            if let Some(name) = node
                .child_by_field_name("declarator")
                .and_then(declared_name)
            {
                state.remove(text(source, name));
            }
        }
        "call_expression" => visit_call(file, source, node, state, out),
        "pointer_expression" | "field_expression" | "subscript_expression" => {
            if let Some(base) = deref_base(node) {
                use_ident(file, source, base, state, out);
            }
            for child in named_children(node) {
                visit_expr(file, source, child, state, out);
            }
        }
        _ => {
            for child in named_children(node) {
                visit_expr(file, source, child, state, out);
            }
        }
    }
}

/// A call: `free(p)` frees `p`; any other call uses its simple arguments.
fn visit_call(file: &str, source: &str, node: Node, state: &mut State, out: &mut Vec<Violation>) {
    let name = node
        .child_by_field_name("function")
        .map(|f| text(source, f));
    let args = node.child_by_field_name("arguments");
    if let (Some(name), Some(args)) = (name, args) {
        if names::is_free(name) {
            if let Some(arg) = single_identifier(args) {
                free_variable(file, source, node, arg, state, out);
                return;
            }
        }
        // A normal call: a freed pointer passed in is a use.
        for arg in named_children(args) {
            if arg.kind() == "identifier" {
                use_ident(file, source, arg, state, out);
            } else {
                visit_expr(file, source, arg, state, out);
            }
        }
    }
}

/// Record a free of `ident`: double-free if already freed, then mark freed.
fn free_variable(
    file: &str,
    source: &str,
    call: Node,
    ident: Node,
    state: &mut State,
    out: &mut Vec<Violation>,
) {
    let name = text(source, ident);
    if let Some(freed) = state.get(name).copied() {
        out.push(Violation {
            rule: DOUBLE_FREE,
            file: file.to_string(),
            free_line: freed.line(),
            at_line: line_of(call),
            columns: columns_of(call),
            variable: name.to_string(),
            certain: freed.is_certain(),
        });
    }
    state.insert(name.to_string(), Freed::Always(line_of(call)));
}

/// Record a use of `ident` if it is a freed variable (then stop tracking it,
/// so one free yields one finding).
fn use_ident(file: &str, source: &str, ident: Node, state: &mut State, out: &mut Vec<Violation>) {
    let name = text(source, ident);
    if let Some(freed) = state.remove(name) {
        out.push(Violation {
            rule: USE_AFTER_FREE,
            file: file.to_string(),
            free_line: freed.line(),
            at_line: line_of(ident),
            columns: columns_of(ident),
            variable: name.to_string(),
            certain: freed.is_certain(),
        });
    }
}

/// Merge several branch states into the state after their join.
fn merge_states(states: &[State]) -> State {
    let keys: HashSet<&String> = states.iter().flat_map(HashMap::keys).collect();
    let mut out = State::new();
    for key in keys {
        let merged = states
            .iter()
            .map(|s| s.get(key).copied())
            .reduce(merge)
            .flatten();
        if let Some(freed) = merged {
            out.insert(key.clone(), freed);
        }
    }
    out
}

/// The pointer variable a `*p` / `p->f` / `p[i]` dereferences, if it is a
/// plain identifier.
fn deref_base(node: Node) -> Option<Node> {
    let base = node
        .child_by_field_name("argument")
        .or_else(|| node.named_child(0))?;
    (base.kind() == "identifier").then_some(base)
}

/// The identifier a declarator declares, e.g. `*p` or `p[8]` → `p`.
fn declared_name(declarator: Node) -> Option<Node> {
    let mut node = declarator;
    loop {
        if node.kind() == "identifier" {
            return Some(node);
        }
        node = node
            .child_by_field_name("declarator")
            .or_else(|| node.named_child(0))?;
    }
}

/// The one identifier argument of a call's argument list, if it has exactly
/// one and it is a plain identifier.
fn single_identifier(args: Node) -> Option<Node> {
    let children = named_children(args);
    match children.as_slice() {
        [arg] if arg.kind() == "identifier" => Some(*arg),
        _ => None,
    }
}

fn named_children(node: Node) -> Vec<Node> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

fn text<'a>(source: &'a str, node: Node) -> &'a str {
    source.get(node.byte_range()).unwrap_or_default()
}

fn line_of(node: Node) -> u32 {
    node.start_position().row as u32 + 1
}

/// The byte columns the node spans on its line, if it stays on one line.
fn columns_of(node: Node) -> Option<(u32, u32)> {
    let (start, end) = (node.start_position(), node.end_position());
    (start.row == end.row).then_some((start.column as u32, end.column as u32))
}

impl Violation {
    fn into_finding(self, symbol: Option<SymbolId>) -> Finding {
        let on_a_path = if self.certain { "" } else { " on some path" };
        let (cwe, message) = match self.rule {
            DOUBLE_FREE => (
                415,
                format!(
                    "`{}` is freed again{on_a_path}; it was already freed at line {}.",
                    self.variable, self.free_line
                ),
            ),
            _ => (
                416,
                format!(
                    "`{}` is used{on_a_path} after it was freed at line {}.",
                    self.variable, self.free_line
                ),
            ),
        };
        Finding {
            tool: "SrcWranglr".to_string(),
            rule: self.rule.to_string(),
            severity: if self.certain {
                Severity::High
            } else {
                Severity::Medium
            },
            message,
            fix: None,
            cwe: Some(cwe),
            file: self.file,
            line: self.at_line,
            columns: self.columns,
            symbol,
        }
    }
}
