use super::*;

fn write(root: &Path, path: &str, text: &str) {
    let path = root.join(AAVR_DIR).join(path);
    std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
    std::fs::write(path, text).expect("write");
}

#[test]
fn without_an_aavr_folder_there_is_no_run() {
    let dir = tempfile::tempdir().expect("tempdir");
    assert_eq!(read(dir.path()), None);
}

#[test]
fn phases_are_done_next_or_blocked_as_the_state_says() {
    let dir = tempfile::tempdir().expect("tempdir");
    write(
        dir.path(),
        "state.json",
        r#"{"target_revision": "abc123", "completed_phases": ["aavr-repository-recon", "build_baseline"],
            "next_phase": "attack-surface", "blocked_on": []}"#,
    );
    let run = read(dir.path()).expect("run");
    assert_eq!(run.revision, "abc123");
    assert_eq!(run.phases[0], ("Recon", PhaseStatus::Done));
    assert_eq!(run.phases[1], ("Build", PhaseStatus::Done));
    assert_eq!(run.phases[2], ("Attack surface", PhaseStatus::Next));
    assert_eq!(run.phases[3].1, PhaseStatus::Pending);
    write(
        dir.path(),
        "state.json",
        r#"{"next_phase": "build-baseline", "blocked_on": ["no compiler for arm64"]}"#,
    );
    let run = read(dir.path()).expect("run");
    assert_eq!(run.phases[1], ("Build", PhaseStatus::Blocked));
    assert_eq!(run.blocked_on, ["no compiler for arm64"]);
}

#[test]
fn triaged_findings_are_grouped_and_point_at_their_code() {
    let dir = tempfile::tempdir().expect("tempdir");
    write(
        dir.path(),
        "findings/AAVR-2.json",
        r#"{"id": "AAVR-2", "title": "overflow in parse_header", "classification": "likely",
            "severity": "high", "confidence": "medium", "sink": {"file": "net/parse.c", "line": 5}}"#,
    );
    write(
        dir.path(),
        "findings/AAVR-1.json",
        r#"{"id": "AAVR-1", "title": "system() on packet data", "classification": "confirmed",
            "evidence": ["ASan report", "see net/parse.c:14 for the call"]}"#,
    );
    write(dir.path(), "findings/candidates.jsonl", "{}\n{}\n\n{}\n");
    let run = read(dir.path()).expect("run");
    let ids: Vec<&str> = run.candidates.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(ids, ["AAVR-1", "AAVR-2"]);
    assert_eq!(run.candidates[0].classification, Classification::Confirmed);
    assert_eq!(run.candidates[0].place, Some(("net/parse.c".into(), 14)));
    assert_eq!(run.candidates[1].place, Some(("net/parse.c".into(), 5)));
    assert_eq!(run.raw_candidates, 3);
}

#[test]
fn surfaces_harness_crashes_and_report_are_read() {
    let dir = tempfile::tempdir().expect("tempdir");
    write(
        dir.path(),
        "surfaces/map.json",
        r#"[{"id": "SURFACE-001", "origin": "network packets", "entry_point": "handle_packet", "priority": "high"}]"#,
    );
    write(
        dir.path(),
        "harnesses/selection.json",
        r#"{"selected_target": "parse_header", "engine": "libFuzzer"}"#,
    );
    write(
        dir.path(),
        "crashes/crash-1/analysis.json",
        r#"{"reproducible": true, "classification": "out-of-bounds write",
            "root_cause_location": {"file": "net/parse.c", "line": 5}}"#,
    );
    write(dir.path(), "reports/aavr-report.md", "# Report\n");
    let run = read(dir.path()).expect("run");
    assert_eq!(run.surfaces[0].detail, "handle_packet");
    assert_eq!(run.surfaces[0].title, "SURFACE-001");
    assert_eq!(
        run.harness.as_ref().map(|h| h.target.as_str()),
        Some("parse_header")
    );
    assert_eq!(run.crashes[0].id, "crash-1");
    assert_eq!(run.crashes[0].is_reproducible, Some(true));
    assert_eq!(run.crashes[0].place, Some(("net/parse.c".into(), 5)));
    assert_eq!(run.report.as_deref(), Some(".aavr/reports/aavr-report.md"));
}

#[test]
fn surfaces_read_with_the_models_own_keys_and_find_a_place() {
    let dir = tempfile::tempdir().expect("tempdir");
    write(
        dir.path(),
        "surfaces/map.json",
        r#"{"surfaces": [{"name": "miniupnpd HTTP/SOAP",
            "entry": ["recv/SSL_read upnphttp.c:101", "ProcessHttpQuery upnphttp.c:896"],
            "reaches": ["upnpsoap.c handlers"], "notes": "root daemon"}]}"#,
    );
    let run = read(dir.path()).expect("run");
    assert_eq!(run.surfaces.len(), 1);
    assert_eq!(run.surfaces[0].title, "miniupnpd HTTP/SOAP");
    assert!(
        run.surfaces[0].detail.contains("upnphttp.c:101"),
        "{:?}",
        run.surfaces[0]
    );
    assert_eq!(run.surfaces[0].place, Some(("upnphttp.c".into(), 101)));
}

#[test]
fn hostile_files_are_reported_not_followed() {
    let dir = tempfile::tempdir().expect("tempdir");
    write(dir.path(), "state.json", "not json");
    let elsewhere = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        elsewhere.path().join("secret.json"),
        r#"{"classification": "confirmed"}"#,
    )
    .expect("write");
    let findings = dir.path().join(AAVR_DIR).join("findings");
    std::fs::create_dir_all(&findings).expect("mkdir");
    std::os::unix::fs::symlink(
        elsewhere.path().join("secret.json"),
        findings.join("x.json"),
    )
    .expect("symlink");
    write(
        dir.path(),
        "findings/big.json",
        &"x".repeat(MAX_FILE_BYTES + 10),
    );
    let run = read(dir.path()).expect("run");
    assert!(run.candidates.is_empty(), "{:?}", run.candidates);
    assert!(
        run.problems.iter().any(|p| p.contains("state.json")),
        "{:?}",
        run.problems
    );
    assert!(run.problems.len() >= 3, "{:?}", run.problems);
}

#[test]
fn a_passed_phase_reads_as_skipped_and_suffixed_names_still_count() {
    let dir = tempfile::tempdir().expect("tempdir");
    write(
        dir.path(),
        "state.json",
        r#"{"completed_phases": ["repository-recon", "attack-surface",
            "fuzz-campaign (runs 001-7)", "report (session 5 update)"], "blocked_on": []}"#,
    );
    let run = read(dir.path()).expect("run");
    let by = |label: &str| {
        run.phases
            .iter()
            .find(|(l, _)| *l == label)
            .map(|(_, s)| *s)
            .expect(label)
    };
    // The agent appends notes to phase names; the head still matches.
    assert_eq!(by("Campaign"), PhaseStatus::Done);
    assert_eq!(by("Report"), PhaseStatus::Done);
    assert_eq!(by("Recon"), PhaseStatus::Done);
    // Phases the run passed without marking read as skipped, not pending.
    assert_eq!(by("Build"), PhaseStatus::Skipped);
    assert_eq!(by("Static analysis"), PhaseStatus::Skipped);
    assert_eq!(by("Crashes"), PhaseStatus::Skipped);
}

#[test]
fn phases_after_the_furthest_reached_stay_pending() {
    let dir = tempfile::tempdir().expect("tempdir");
    write(
        dir.path(),
        "state.json",
        r#"{"completed_phases": ["repository-recon"], "blocked_on": []}"#,
    );
    let run = read(dir.path()).expect("run");
    let by = |label: &str| {
        run.phases
            .iter()
            .find(|(l, _)| *l == label)
            .map(|(_, s)| *s)
            .expect(label)
    };
    assert_eq!(by("Recon"), PhaseStatus::Done);
    // Nothing was passed, so later phases are pending, not skipped.
    assert_eq!(by("Build"), PhaseStatus::Pending);
    assert_eq!(by("Report"), PhaseStatus::Pending);
}
