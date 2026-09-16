//! Host calls are WASM imports with no native symbol, so they no-op off-wasm to
//! keep everything else testable with a plain `cargo test`.

#[cfg(target_family = "wasm")]
pub(crate) use zellij_tile::shim::{
    close_self, close_terminal_pane, focus_terminal_pane, hide_self, open_command_pane, open_command_pane_floating,
    reload_plugin_with_id, run_command, send_sigint_to_pane_id, set_timeout, show_self, switch_session_with_focus,
    write_chars_to_pane_id,
};

#[cfg(target_family = "wasm")]
pub(crate) fn own_plugin_id() -> u32 {
    zellij_tile::shim::get_plugin_ids().plugin_id
}

/// Renames the pane this plugin is running in. Needs our own plugin id, which
/// only the host can tell us, so it is a single call rather than two.
#[cfg(target_family = "wasm")]
pub(crate) fn rename_own_pane(title: &str) {
    let ids = zellij_tile::shim::get_plugin_ids();
    zellij_tile::shim::rename_plugin_pane(ids.plugin_id, title);
}

/// Drops a permission verdict where the blocked hook is polling for it. The
/// plugin's WASI sandbox has no access to the host filesystem, so this shells
/// out rather than writing directly.
/// The verdict is one of two fixed literals and the path is passed as its own
/// argv element, so nothing user-influenced is ever parsed by a shell.
#[cfg(target_family = "wasm")]
pub(crate) fn write_verdict(path: &str, verdict: &str) {
    let mut ctx = std::collections::BTreeMap::new();
    ctx.insert("kind".to_string(), "verdict".to_string());
    // `cp` from /dev/stdin needs a pipe we do not have; `sh -c` with the path as
    // a positional arg keeps it out of the parsed command string.
    run_command(&["sh", "-c", "printf '%s' \"$1\" > \"$2\"", "sh", verdict, path], ctx);
}

#[cfg(target_family = "wasm")]
pub(crate) fn append_approve_rule(tool: &str) {
    let mut ctx = std::collections::BTreeMap::new();
    ctx.insert("kind".to_string(), "rule".to_string());
    run_command(
        &[
            "sh",
            "-c",
            "d=\"${ZJ_AGENT_APPROVE_RULES:-$HOME/.config/zj-agent-mob/approve.rules}\"; \
             mkdir -p \"$(dirname \"$d\")\" 2>/dev/null; \
             grep -qxF \"allow $1\" \"$d\" 2>/dev/null || printf 'allow %s\\n' \"$1\" >> \"$d\"",
            "sh",
            tool,
        ],
        ctx,
    );
}

#[cfg(target_family = "wasm")]
pub(crate) fn queue_followup(session: &str, pane_id: u32, text: &str) {
    let mut ctx = std::collections::BTreeMap::new();
    ctx.insert("kind".to_string(), "followup".to_string());
    run_command(
        &[
            "sh",
            "-c",
            "d=\"${TMPDIR:-/tmp}/zj-agent-mob\"; \
             [ -d \"$d\" ] || { mkdir -p \"$d\" 2>/dev/null && chmod 700 \"$d\" 2>/dev/null; }; \
             printf '%s' \"$3\" > \"$d/followup.$1.$2\" 2>/dev/null || true",
            "sh",
            session,
            &pane_id.to_string(),
            text,
        ],
        ctx,
    );
}

/// Fires a desktop notification through whichever notifier was detected.
///
/// The message carries task summaries and tool arguments, both of which come
/// from arbitrary repo content, so every one is its own argv element and none
/// is ever interpolated into a string a shell parses. `osascript` has no argv
/// form for `display notification`, so its text is bound to a variable via
/// `on run argv` instead of being spliced into the script.
#[cfg(target_family = "wasm")]
pub(crate) fn notify(notifier: &str, title: &str, body: &str, sound: bool) {
    let mut ctx = std::collections::BTreeMap::new();
    ctx.insert("kind".to_string(), "notify".to_string());
    match notifier {
        "osascript" => {
            let script = match sound {
                true => "on run argv\ndisplay notification (item 2 of argv) with title (item 1 of argv) sound name \"Ping\"\nend run",
                false => "on run argv\ndisplay notification (item 2 of argv) with title (item 1 of argv)\nend run",
            };
            run_command(&["osascript", "-e", script, title, body], ctx);
        }
        "terminal-notifier" => {
            run_command(
                &[
                    "terminal-notifier",
                    "-title",
                    title,
                    "-message",
                    body,
                    "-group",
                    "zj-agent-mob",
                ],
                ctx,
            );
        }
        "notify-send" => {
            run_command(&["notify-send", "-a", "zj-agent-mob", title, body], ctx);
        }
        _ => {}
    }
}

/// Opens a pane attached to a background agent from Claude Code's agent view.
///
/// A tiled pane rather than a floating one: the panel floats and hides itself
/// on the way out, and what lands is a full interactive session the user is
/// about to work in, not another overlay.
///
/// `cwd` is the agent's own working directory, so the pane opens where the
/// agent is rather than wherever the panel happened to be launched from.
#[cfg(target_family = "wasm")]
pub(crate) fn attach_agent(claude_bin: &str, id: &str, cwd: &str) {
    use zellij_tile::prelude::CommandToRun;
    let mut ctx = std::collections::BTreeMap::new();
    ctx.insert("kind".to_string(), "attach".to_string());
    open_command_pane(
        CommandToRun {
            path: std::path::PathBuf::from(claude_bin),
            args: vec!["attach".to_string(), id.to_string()],
            cwd: (!cwd.is_empty()).then(|| std::path::PathBuf::from(cwd)),
        },
        ctx,
    );
}

/// Stops a background agent. `claude stop` is the agent view's own verb, so the
/// daemon tears the session down and records it instead of the panel killing a
/// process out from under it.
///
/// The id is its own argv element and is validated as eight hex digits before
/// it ever gets here, so nothing user-influenced is parsed by a shell.
#[cfg(target_family = "wasm")]
pub(crate) fn stop_agent(claude_bin: &str, id: &str) {
    let mut ctx = std::collections::BTreeMap::new();
    ctx.insert("kind".to_string(), "stop".to_string());
    run_command(&[claude_bin, "stop", id], ctx);
}

/// Acts on a pane in another Zellij session by shelling out to the `zellij`
/// binary, which takes a session argument where the plugin shims cannot.
/// Every value is its own argv element.
#[cfg(target_family = "wasm")]
pub(crate) fn session_action(session: &str, args: &[&str], kind: &str) {
    let mut ctx = std::collections::BTreeMap::new();
    ctx.insert("kind".to_string(), kind.to_string());
    let mut argv = vec!["zellij", "--session", session, "action"];
    argv.extend_from_slice(args);
    run_command(&argv, ctx);
}

/// The script behind `publish_summary`, kept outside the wasm-only function so
/// the `@default` resolution can be tested against a real shell.
///
/// The summary reaches a file and a pipe, so it is bound as a positional rather
/// than spliced into the command string. The prose line and the `k=v` line are
/// written as two files, both atomically: a consumer reading mid-write would
/// otherwise see a truncated count and render it as fact.
///
/// `@default` is resolved here because only the host knows `$TMPDIR` and the
/// uid; see `DEFAULT_SUMMARY`.
#[cfg(any(target_family = "wasm", test))]
pub(crate) const SUMMARY_SCRIPT: &str = "p=$2; \
     if [ \"$p\" = @default ]; then \
       d=\"${TMPDIR:-/tmp}/zj-agent-mob-$(id -u 2>/dev/null || echo 0)\"; \
       [ -d \"$d\" ] || mkdir -p \"$d\" 2>/dev/null; \
       p=\"$d/summary\"; \
     fi; \
     printf '%s' \"$1\" > \"$p.tmp\" 2>/dev/null && mv -f \"$p.tmp\" \"$p\" 2>/dev/null; \
     printf '%s' \"$3\" > \"$p.kv.tmp\" 2>/dev/null && mv -f \"$p.kv.tmp\" \"$p.kv\" 2>/dev/null; \
     command -v zellij >/dev/null 2>&1 && zellij pipe --name zj-agent-mob-summary -- \"$1\" >/dev/null 2>&1 || true";

/// Publishes the one-line fleet summary for status bars to render. `zellij pipe`
/// with no `--plugin` reaches every listening plugin, and the spool file serves
/// consumers that are not plugins at all.
#[cfg(target_family = "wasm")]
pub(crate) fn publish_summary(summary: &str, path: &str, kv: &str) {
    let mut ctx = std::collections::BTreeMap::new();
    ctx.insert("kind".to_string(), "summary".to_string());
    run_command(&["sh", "-c", SUMMARY_SCRIPT, "sh", summary, path, kv], ctx);
}

#[cfg(not(target_family = "wasm"))]
mod stub {
    use std::collections::BTreeMap;
    use zellij_tile::prelude::{CommandToRun, FloatingPaneCoordinates, PaneId};
    pub(crate) fn set_timeout(_secs: f64) {}
    pub(crate) fn show_self(_float: bool) {}
    pub(crate) fn hide_self() {}
    pub(crate) fn focus_terminal_pane(_id: u32, _float: bool, _in_place: bool) {}
    pub(crate) fn close_terminal_pane(_id: u32) {}
    pub(crate) fn send_sigint_to_pane_id(_id: PaneId) {}
    pub(crate) fn run_command(_cmd: &[&str], _ctx: BTreeMap<String, String>) {}
    pub(crate) fn switch_session_with_focus(_name: &str, _tab: Option<usize>, _pane: Option<(u32, bool)>) {}
    pub(crate) fn rename_own_pane(_title: &str) {}
    pub(crate) fn close_self() {}
    pub(crate) fn own_plugin_id() -> u32 {
        0
    }
    pub(crate) fn reload_plugin_with_id(_id: u32) {}
    pub(crate) fn write_verdict(_path: &str, _verdict: &str) {}
    pub(crate) fn append_approve_rule(_tool: &str) {}
    pub(crate) fn queue_followup(_session: &str, _pane_id: u32, _text: &str) {}
    pub(crate) fn notify(_notifier: &str, _title: &str, _body: &str, _sound: bool) {}
    pub(crate) fn session_action(_session: &str, _args: &[&str], _kind: &str) {}
    pub(crate) fn publish_summary(_summary: &str, _path: &str, _kv: &str) {}
    pub(crate) fn attach_agent(_claude_bin: &str, _id: &str, _cwd: &str) {}
    pub(crate) fn stop_agent(_claude_bin: &str, _id: &str) {}
    pub(crate) fn write_chars_to_pane_id(_chars: &str, _id: PaneId) {}
    pub(crate) fn open_command_pane_floating(
        _cmd: CommandToRun,
        _coords: Option<FloatingPaneCoordinates>,
        _ctx: BTreeMap<String, String>,
    ) -> Option<PaneId> {
        None
    }
}
#[cfg(not(target_family = "wasm"))]
pub(crate) use stub::*;

#[cfg(test)]
mod summary_script_tests {
    use super::SUMMARY_SCRIPT;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    /// Runs the script with `$TMPDIR` pointed at a scratch dir and a `zellij`
    /// that does nothing, so the test never pipes into a real session.
    fn publish(tmp: &std::path::Path, path: &str) {
        let bin = tmp.join("bin");
        fs::create_dir_all(&bin).unwrap();
        let stub = bin.join("zellij");
        fs::write(&stub, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&stub, fs::Permissions::from_mode(0o755)).unwrap();
        let path_env = format!("{}:/usr/bin:/bin", bin.display());
        let status = Command::new("sh")
            .args([
                "-c",
                SUMMARY_SCRIPT,
                "sh",
                "1 waiting",
                path,
                "failed=0 waiting=1 total=1",
            ])
            .env("TMPDIR", tmp)
            .env("PATH", path_env)
            .status()
            .unwrap();
        assert!(status.success());
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("zjam-summary-{}-{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    /// The default lands beside the spool, where a status line can find it
    /// knowing only `$TMPDIR` and its own uid.
    #[test]
    fn the_default_token_resolves_beside_the_spool() {
        let tmp = scratch("default");
        publish(&tmp, "@default");
        let uid = String::from_utf8(Command::new("id").arg("-u").output().unwrap().stdout).unwrap();
        let dir = tmp.join(format!("zj-agent-mob-{}", uid.trim()));
        assert_eq!(fs::read_to_string(dir.join("summary")).unwrap(), "1 waiting");
        assert_eq!(
            fs::read_to_string(dir.join("summary.kv")).unwrap(),
            "failed=0 waiting=1 total=1"
        );
        assert!(
            !tmp.join("@default").exists(),
            "the token must never be used as a literal path"
        );
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn an_explicit_path_is_used_as_given() {
        let tmp = scratch("explicit");
        let target = tmp.join("custom.summary");
        publish(&tmp, target.to_str().unwrap());
        assert_eq!(fs::read_to_string(&target).unwrap(), "1 waiting");
        assert!(tmp.join("custom.summary.kv").exists());
        let _ = fs::remove_dir_all(&tmp);
    }
}
