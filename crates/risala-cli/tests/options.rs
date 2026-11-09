//! The options that need no server: `risala witness`, `--witness` and
//! `--witness-k`, and the warnings for development options.

use std::path::Path;
use std::process::Command;

/// Runs `risala` with this state directory; its exit code, output and
/// errors.
fn risala(state: &Path, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_risala"))
        .arg("--state")
        .arg(state)
        .args(args)
        .env("RISALA_LOG", "off")
        .output()
        .expect("running risala");
    (
        out.status.code().expect("an exit code"),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn the_witness_policy_changes_only_with_witness_set() {
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("state");
    let dev = risala_dev::witness_vkey();

    let (code, out, _) = risala(&state, &["witness", "show"]);
    assert_eq!(code, 0);
    assert_eq!(out, "0\t0\tdefault\n");

    // `--witness-k` alone is a bad argument.
    let (code, _, err) = risala(&state, &["--witness-k", "1", "whoami"]);
    assert_eq!(code, 2, "{err}");

    // `--witness` outside setting up is refused and saves nothing.
    let (code, _, err) = risala(&state, &["--witness", &dev, "whoami"]);
    assert_eq!(code, 2);
    assert!(err.contains("witness set"), "{err}");
    let (_, out, _) = risala(&state, &["witness", "show"]);
    assert_eq!(out, "0\t0\tdefault\n");

    // Set, it shows; risala-dev's witness is warned of, every run.
    let (code, _, err) = risala(&state, &["witness", "set", &dev]);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("risala-dev's witness"), "{err}");
    let (code, out, err) = risala(&state, &["witness", "show"]);
    assert_eq!(code, 0);
    assert_eq!(out, format!("1\t1\tsaved\n{dev}\n"));
    assert!(err.contains("risala-dev's witness"), "{err}");
    let (code, _, err) = risala(&state, &["whoami"]);
    assert_eq!(code, 0);
    assert!(err.contains("risala-dev's witness"), "{err}");

    // The same policy as an option is fine; another is an error.
    let (code, _, err) = risala(&state, &["--witness", &dev, "whoami"]);
    assert_eq!(code, 0, "{err}");
    let (code, _, err) = risala(&state, &["--witness", &dev, "--witness-k", "1", "whoami"]);
    assert_eq!(code, 0, "{err}");
    let (code, _, err) = risala(&state, &["--witness", "other+00000000+AA", "whoami"]);
    assert_eq!(code, 2);
    assert!(err.contains("differs"), "{err}");

    // Not a policy (k more than the list): refused, the old one kept.
    let (code, _, _) = risala(&state, &["witness", "set", &dev, "-k", "2"]);
    assert_eq!(code, 1);
    let (_, out, _) = risala(&state, &["witness", "show"]);
    assert!(out.starts_with("1\t1\tsaved\n"), "{out}");

    // Cleared: the default, and no warning.
    let (code, _, _) = risala(&state, &["witness", "clear"]);
    assert_eq!(code, 0);
    let (_, out, err) = risala(&state, &["witness", "show"]);
    assert_eq!(out, "0\t0\tdefault\n");
    assert!(!err.contains("warning"), "{err}");
}

/// Setting up a new state directory may take `--witness`, so that it can
/// be scripted: the policy is saved before the identity is made.
#[test]
fn create_on_a_new_state_directory_saves_the_witness_option() {
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("state");
    let dev = risala_dev::witness_vkey();
    // Nothing listens on port 1: creating fails, after the policy is saved.
    let (code, _, err) = risala(
        &state,
        &[
            "--connect-to",
            "127.0.0.1:1",
            "--witness",
            &dev,
            "create",
            "chat.test",
            "alice",
            "laptop",
        ],
    );
    assert_eq!(code, 1, "{err}");
    let (_, out, _) = risala(&state, &["witness", "show"]);
    assert_eq!(out, format!("1\t1\tsaved\n{dev}\n"));
}

#[test]
fn development_options_are_warned_of() {
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("state");
    let (code, _, err) = risala(&state, &["whoami"]);
    assert_eq!(code, 0);
    assert!(!err.contains("warning"), "{err}");
    let pem = root.path().join("none.pem");
    std::fs::write(&pem, "").unwrap();
    let cases: [(&[&str], &str); 3] = [
        (&["--ca", pem.to_str().unwrap()], "--ca"),
        (&["--resolve", "chat.test=127.0.0.1:1"], "--resolve"),
        (&["--short-waits"], "--short-waits"),
    ];
    for (args, option) in cases {
        let mut args = args.to_vec();
        args.push("whoami");
        let (code, _, err) = risala(&state, &args);
        assert_eq!(code, 0, "{err}");
        assert!(err.contains(&format!("warning: {option}:")), "{err}");
    }
}
