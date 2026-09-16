//! Finding agents that have not reported.
//!
//! The panel only learns about an agent when its hook fires, so a reload or an
//! idle agent leaves the screen empty while agents are sitting right there. This
//! scans process environments instead: every agent inherits `ZELLIJ_PANE_ID` and
//! `ZELLIJ_SESSION_NAME` from its pane's pty, whether it was launched by the
//! layout or typed into an existing shell.

use std::collections::BTreeMap;

use crate::agent::is_job_id;
use crate::host;

pub(crate) const CTX_SCAN: &str = "discover-scan";

/// Executable basenames treated as agents. Matched against the process's own
/// name, not its command line: an agent started by typing `claude` into a shell
/// is a child of that shell, so a command-line pattern anchored at the start
/// misses it.
const TOOLS: [&str; 2] = ["claude", "codex"];

/// Background agents from Claude Code's own agent view (`claude agents`).
///
/// These have a pid but no pane, so the `ps` scan above cannot see them: it
/// keys on `ZELLIJ_PANE_ID`, which a daemon-spawned session never inherits.
/// `claude agents --json` is the same list the agent view renders, and it
/// answers in ~100ms, so it is affordable on every scan.
///
/// Two passes, because they answer different questions and one must not be able
/// to break the other:
///
/// - `jobs/<id>/state.json` says which agents **exist**, the way the process
///   scan does for panes, and carries everything a row renders: the agent
///   view's own detail line, `tempo`, the subagent fan-out and the token count.
///   It is the only thing that can create a row.
/// - `agents --json` only **refines** a row that already exists, with the pid
///   and the live status. Losing it costs liveness, never the row.
///
/// The passes are that way round because of a CLI quirk worth stating plainly:
/// **`claude agents --json` ignores `CLAUDE_CONFIG_DIR`.** It answers for
/// whichever account it resolves on its own, so asking it once per config dir
/// returns that same account's agents every time - the same rows duplicated,
/// not each account's. The job directories have no such problem, and a fleet
/// routinely spans several accounts, so the dirs are globbed and read directly.
/// That is also why the live pass runs exactly once, outside the loop.
///
/// `--json` lists only *active* sessions, so a row it omits is not necessarily
/// gone - it may simply have finished. Completed agents are therefore aged out
/// on `age` rather than culled for being absent from the live set.
///
/// `age` is seconds, computed here rather than sent as an epoch, because the
/// plugin has no wall clock - the same constraint that makes the hook compute
/// `tool_secs` itself and the spool date its records relative to each other.
///
/// The shell only concatenates; every decision about the payload is made in
/// `parse`, which is why the two passes are emitted as separate tagged lines
/// and joined on `id` in Rust rather than in jq.
fn job_scan() -> &'static str {
    r#"
if [ "${ZJ_AGENT_JOBS:-1}" != 0 ] && command -v jq >/dev/null 2>&1; then
  CLAUDE_BIN=$(command -v claude 2>/dev/null)
  if [ -z "$CLAUDE_BIN" ]; then
    for c in "$HOME/.local/sbin/claude" "$HOME/.local/bin/claude" /usr/local/bin/claude; do
      if [ -x "$c" ]; then CLAUDE_BIN="$c"; break; fi
    done
  fi
  if [ -n "$CLAUDE_BIN" ]; then
    "$CLAUDE_BIN" agents --json 2>/dev/null | jq -r '
      .[]? | select(.id != null) |
      "JOBLIVE id=\(.id),pid=\(.pid // 0),status=\(.status // ""),state=\(.state // ""),kind=\(.kind // "")"
    ' 2>/dev/null
  fi
  for cfg in "$HOME"/.claude "$HOME"/.claude-account-*; do
    [ -d "$cfg/jobs" ] || continue
    acct=$(basename "$cfg" | sed -e 's/^\.claude-account-//' -e 's/^\.claude$/default/')
    jq -r --arg acct "$acct" '
      select(.daemonShort != null) |
      (try ((.updatedAt // "") | sub("\\.[0-9]+";"") | fromdateiso8601) catch 0) as $u |
      (if $u > 0 then ((now - $u) | floor) else -1 end) as $age |
      "JOB id=\(.daemonShort),acct=\($acct),state=\(.state // ""),tempo=\(.tempo // ""),age=\($age),fan=\((.fan // []) | length),tokens=\(.tokens // 0),term=\(if .lastTerminalAt == null then 0 else 1 end),cwd=\(.cwd // ""),name=\(((.name // "") | gsub("\\s+";" ") | gsub(",";" "))[0:60]),detail=\(((.detail // "") | gsub("\\s+";" ") | gsub(",";" "))[0:160])"
    ' "$cfg"/jobs/*/state.json 2>/dev/null
  done
fi
"#
}

/// One `ps` for every process, filtered in awk, plus the spool and the job
/// scan - one dispatch for every source, since they are always consumed
/// together.
///
/// `ps axeww` is required to get environments. The POSIX `-e` and the BSD `e`
/// collide silently on macOS: `ps -e eww` still exits 0 and still prints a
/// process list, just with no environment at all, so the scan finds nothing.
pub(crate) fn scan_script(tools: &[&str]) -> String {
    let guard = tools
        .iter()
        .map(|t| format!("cmd != \"{}\"", t))
        .collect::<Vec<_>>()
        .join(" && ");
    let job_scan = job_scan();
    // One invocation for both sources: a second dispatch would double the poll
    // cost for data that is always consumed together.
    format!(
        r#"ps axeww -o pid=,command= 2>/dev/null | awk '
{{
  cmd = $2; sub(/.*\//, "", cmd)
  # One server per session; the socket path basename is the session name.
  # No apostrophes in this block: the awk program is one single-quoted word.
  if (cmd == "zellij" && $3 == "--server" && $4 != "") {{
    # Rejoin: a session name may contain spaces, so the path is not one field.
    s = ""
    for (i = 4; i <= NF; i++) {{
      if ($i ~ /^[A-Za-z_][A-Za-z0-9_]*=/) break
      s = (s == "" ? $i : s " " $i)
    }}
    sub(/.*\//, "", s)
    if (s != "") print "LIVE", s
  }}
  if ({guard}) next
  pane = ""; sess = ""
  for (i = 3; i <= NF; i++) {{
    if ($i ~ /^ZELLIJ_PANE_ID=/)      pane = substr($i, 16)
    if ($i ~ /^ZELLIJ_SESSION_NAME=/) sess = substr($i, 21)
  }}
  if (pane != "" && sess != "") print "SCAN", sess, pane, cmd
}}' | sort -u
SPOOL_DIR="${{ZJ_AGENT_SPOOL_DIR:-${{TMPDIR:-/tmp}}/zj-agent-mob-$(id -u 2>/dev/null || echo 0)/status}}"
grep -s -H '' "$SPOOL_DIR"/* 2>/dev/null | sed 's/^/SPOOL /'
{job_scan}
find "$SPOOL_DIR" -type f -mtime +1 -delete 2>/dev/null
# Beacons for panels that are gone, so fan-out stops chasing a session with
# nothing listening. The window is generous on purpose: a beacon is refreshed
# only when a scan runs, and a scan runs on pane and session events rather than
# on a schedule, so a quiet panel can legitimately go a long time without one.
# Sweeping too eagerly would silently switch fan-out off for an idle panel,
# which is the case it exists for. A stale beacon costs one wasted pipe.
find "$SPOOL_DIR" -name 'panel.*' -type f -mmin +720 -delete 2>/dev/null
printf 'SCANEND\n'"#
    )
}

pub(crate) fn dispatch() {
    let mut ctx = BTreeMap::new();
    ctx.insert(crate::install::CTX_KEY.to_string(), CTX_SCAN.to_string());
    host::run_command(&["sh", "-c", &scan_script(&TOOLS)], ctx);
}

/// Announces that a panel is open in this session, so hooks elsewhere know to
/// fan their urgent transitions out to it. Refreshed on every scan: a stale
/// beacon costs one wasted `zellij pipe`, and the sweep clears it eventually.
///
/// The filename is the sanitized name, so it is safe on any filesystem and can
/// be compared against the hook's own `$SESSION`. The *contents* are the real
/// name, because that is what `zellij --session` needs and sanitizing is lossy:
/// a session called "my session" is keyed `my_session`, which addresses nothing.
///
/// Both are passed as positionals rather than spliced into the command.
pub(crate) fn beacon_script() -> &'static str {
    "d=\"${ZJ_AGENT_SPOOL_DIR:-${TMPDIR:-/tmp}/zj-agent-mob-$(id -u 2>/dev/null || echo 0)/status}\"; \
     [ -d \"$d\" ] || { mkdir -p \"$d\" 2>/dev/null && chmod 700 \"$d\" 2>/dev/null; }; \
     [ -n \"$1\" ] && printf '%s' \"$2\" > \"$d/panel.$1\" 2>/dev/null || true"
}

pub(crate) fn announce_panel(sanitized: &str, real: &str) {
    if sanitized.is_empty() {
        return;
    }
    let mut ctx = BTreeMap::new();
    ctx.insert(crate::install::CTX_KEY.to_string(), "panel-beacon".to_string());
    host::run_command(&["sh", "-c", beacon_script(), "sh", sanitized, real], ctx);
}

/// A `session pane_id tool` triple from the scan.
pub(crate) struct Found {
    pub(crate) session: String,
    pub(crate) pane_id: u32,
    pub(crate) tool: String,
}

/// A background agent from Claude Code's agent view, read from its job state.
///
/// `id` is the daemon's short id - the first block of the session uuid, eight
/// lowercase hex digits - which is what `claude attach` and `claude stop` take.
pub(crate) struct Job {
    pub(crate) id: String,
    /// Which account's config dir it came from: `personal`, `work`, `default`.
    /// A fleet spans accounts and a bare row cannot say which one it is in.
    pub(crate) acct: String,
    /// `working`, `done` or `blocked`.
    pub(crate) state: String,
    /// `active`, `idle` or `blocked`.
    pub(crate) tempo: String,
    /// Seconds since the job last wrote its state, computed in the shell
    /// because the plugin has no wall clock. Negative when unknown.
    pub(crate) age: i64,
    /// Subagents in flight, the `fan` the agent view shows underneath a row.
    pub(crate) fan: u32,
    /// True once the job has terminated at least once (`lastTerminalAt` set).
    pub(crate) terminated: bool,
    pub(crate) cwd: String,
    pub(crate) name: String,
    pub(crate) detail: String,
}

/// The live half of the job scan: `claude agents --json`, which knows the pid
/// but only for the one account the CLI resolves. Refines a `Job`, never
/// creates one.
pub(crate) struct JobLive {
    pub(crate) id: String,
    /// `busy` or `idle`. The one thing this pass knows that the job record does
    /// not: whether an agent that calls itself working is actually working or
    /// sitting at a prompt.
    pub(crate) status: String,
}

/// One agent's status record, read from the spool.
pub(crate) struct Spooled {
    pub(crate) session: String,
    pub(crate) pane_id: u32,
    pub(crate) ts: f64,
    pub(crate) args: std::collections::BTreeMap<String, String>,
}

#[derive(Default)]
pub(crate) struct Scan {
    pub(crate) found: Vec<Found>,
    pub(crate) spooled: Vec<Spooled>,
    /// Background agents from the agent view. Keyed by their own short id
    /// rather than a pane, because they do not have one.
    pub(crate) jobs: Vec<Job>,
    pub(crate) job_live: Vec<JobLive>,
    /// Sanitized names of every session with a running Zellij server.
    /// `SessionUpdate` reports only the panel's own, so this is the only
    /// source that can speak for a foreign session's liveness.
    pub(crate) live: Vec<String>,
    /// The script ran to completion. Without this a truncated read looks like
    /// "no agents anywhere" and would cull every foreign row.
    pub(crate) complete: bool,
}

/// Splits `key=value,key=value` the way the pipe args arrive, so a spool record
/// and a pipe message parse into the same shape.
fn parse_args(rest: &str) -> std::collections::BTreeMap<String, String> {
    rest.split(',')
        .filter_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            Some((k.to_string(), v.to_string()))
        })
        .collect()
}

/// Ignores anything malformed rather than failing the whole scan: a partial
/// list is more useful than none, and `ps` output is not a stable contract.
pub(crate) fn parse(stdout: &str) -> Scan {
    let mut scan = Scan::default();
    let mut seen_files: Vec<String> = Vec::new();
    for line in stdout.lines() {
        if line == "SCANEND" {
            scan.complete = true;
            continue;
        }
        let Some((tag, rest)) = line.split_once(' ') else {
            continue;
        };
        match tag {
            "LIVE" => {
                let name = rest.trim();
                if name.is_empty() {
                    continue;
                }
                let sanitized = crate::agent::sanitize_session(name);
                if !scan.live.contains(&sanitized) {
                    scan.live.push(sanitized);
                }
            }
            "SCAN" => {
                let mut parts = rest.split_whitespace();
                let Some(session) = parts.next() else { continue };
                let Some(Ok(pane_id)) = parts.next().map(str::parse::<u32>) else {
                    continue;
                };
                let Some(tool) = parts.next() else { continue };
                if TOOLS.contains(&tool) {
                    scan.found.push(Found {
                        session: crate::agent::sanitize_session(session),
                        pane_id,
                        tool: tool.to_string(),
                    });
                }
            }
            // A background agent's job state. Same `key=value,...` shape as a
            // spool record, so it parses with the same splitter.
            "JOB" => {
                let args = parse_args(rest);
                let Some(id) = args.get("id").filter(|s| is_job_id(s)).cloned() else {
                    continue;
                };
                // First record wins. The same job can appear under two config
                // dirs when they share a jobs directory, and one agent must
                // not become two rows.
                if scan.jobs.iter().any(|j| j.id == id) {
                    continue;
                }
                let s = |k: &str| args.get(k).cloned().unwrap_or_default();
                scan.jobs.push(Job {
                    id,
                    acct: s("acct"),
                    state: s("state"),
                    tempo: s("tempo"),
                    age: args.get("age").and_then(|a| a.parse::<i64>().ok()).unwrap_or(-1),
                    fan: args.get("fan").and_then(|f| f.parse::<u32>().ok()).unwrap_or(0),
                    terminated: args.get("term").map(String::as_str) == Some("1"),
                    cwd: s("cwd"),
                    name: s("name"),
                    detail: s("detail"),
                });
            }
            "JOBLIVE" => {
                let args = parse_args(rest);
                let Some(id) = args.get("id").filter(|s| is_job_id(s)).cloned() else {
                    continue;
                };
                if scan.job_live.iter().any(|j| j.id == id) {
                    continue;
                }
                scan.job_live.push(JobLive {
                    id,
                    status: args.get("status").cloned().unwrap_or_default(),
                });
            }
            // `<path>:<record>`, one line per file from `grep -H`. The shell
            // only concatenates; every decision about the payload is made here.
            "SPOOL" => {
                let Some((path, record)) = rest.split_once(':') else {
                    continue;
                };
                let name = path.rsplit('/').next().unwrap_or(path);
                // A half-written record is still named `.tmp`; the rename into
                // place is what publishes it.
                if name.ends_with(".tmp") {
                    continue;
                }
                // Panel beacons and per-pane caches share the directory but
                // are not agent records.
                if name.starts_with("panel.") || name.starts_with("inflight.") || name.starts_with("git.") {
                    continue;
                }
                // First line wins: a file with more is malformed, and later
                // lines must not be read as separate agents.
                if seen_files.contains(&path.to_string()) {
                    continue;
                }
                seen_files.push(path.to_string());
                let args = parse_args(record);
                let (Some(ts), Some(pane_id)) = (
                    args.get("ts").and_then(|t| t.parse::<f64>().ok()),
                    args.get("pane_id").and_then(|p| p.parse::<u32>().ok()),
                ) else {
                    continue;
                };
                let Some(session) = args.get("session").filter(|s| !s.is_empty()).cloned() else {
                    continue;
                };
                // The filename is the authority on identity: a record claiming
                // a different pane than the file it lives in is malformed.
                if name != format!("{}.{}", session, pane_id) {
                    continue;
                }
                scan.spooled.push(Spooled {
                    session: crate::agent::sanitize_session(&session),
                    pane_id,
                    ts,
                    args,
                });
            }
            _ => {}
        }
    }
    scan
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan_of(lines: &str) -> Scan {
        parse(&format!("{}SCANEND\n", lines))
    }

    #[test]
    fn parses_session_pane_and_tool_triples() {
        let found = scan_of("SCAN mob 2 claude\nSCAN mob 3 codex\nSCAN other 11 claude\n").found;
        assert_eq!(found.len(), 3);
        assert_eq!(found[0].session, "mob");
        assert_eq!(found[0].pane_id, 2);
        assert_eq!(found[0].tool, "claude");
        assert_eq!(found[1].tool, "codex");
        assert_eq!(found[2].session, "other");
    }

    #[test]
    fn parses_a_background_agent_from_its_job_state() {
        let jobs = scan_of(
            "JOB id=3848ccf2,acct=personal,state=working,tempo=active,age=10,fan=2,tokens=51157,term=0,cwd=/repo,name=fork the plugin,detail=mapping code changes\n",
        )
        .jobs;
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].id, "3848ccf2");
        assert_eq!(jobs[0].acct, "personal");
        assert_eq!(jobs[0].state, "working");
        assert_eq!(jobs[0].tempo, "active");
        assert_eq!(jobs[0].age, 10);
        assert_eq!(jobs[0].fan, 2);
        assert!(!jobs[0].terminated);
        assert_eq!(jobs[0].name, "fork the plugin");
        assert_eq!(jobs[0].detail, "mapping code changes");
    }

    /// The id is packed into a `pane_id`, so anything that is not exactly eight
    /// hex digits would land as a plausible-looking pane number for a pane that
    /// exists and belongs to somebody else.
    #[test]
    fn rejects_an_id_that_is_not_a_job_id() {
        for id in ["", "3848ccf", "3848ccf22", "3848CCF2", "zzzzzzzz", "3848-cf2"] {
            let line = format!("JOB id={},acct=personal,state=working,age=1\n", id);
            assert!(scan_of(&line).jobs.is_empty(), "accepted {:?} as a job id", id);
        }
    }

    /// Two config dirs can name the same job. One agent, one row.
    #[test]
    fn the_same_job_under_two_accounts_is_one_row() {
        let jobs = scan_of(concat!(
            "JOB id=3848ccf2,acct=personal,state=working,age=1\n",
            "JOB id=3848ccf2,acct=work,state=done,age=9999\n",
        ))
        .jobs;
        assert_eq!(jobs.len(), 1, "one agent, not one per config dir");
        assert_eq!(jobs[0].acct, "personal", "first record wins");
    }

    #[test]
    fn parses_the_live_pass_separately() {
        let scan = scan_of(concat!(
            "JOBLIVE id=3848ccf2,pid=1124006,status=busy,state=working,kind=background\n",
            "JOB id=3848ccf2,acct=personal,state=working,age=1\n",
        ));
        assert_eq!(scan.job_live.len(), 1);
        assert_eq!(scan.job_live[0].status, "busy");
        assert_eq!(scan.jobs.len(), 1, "the live pass does not also create a job");
    }

    /// A missing `age` must not read as "0 seconds old", which would pin a row
    /// the window is supposed to age out.
    #[test]
    fn an_absent_age_is_unknown_rather_than_current() {
        let jobs = scan_of("JOB id=3848ccf2,acct=personal,state=done\n").jobs;
        assert_eq!(jobs[0].age, -1);
    }

    #[test]
    fn ignores_malformed_and_unknown_lines() {
        let found =
            scan_of("SCAN mob 2 claude\nSCAN mob notanumber claude\nSCAN mob 4\n\nSCAN mob 5 nvim\nSCAN mob 6 codex\n")
                .found;
        let ids: Vec<u32> = found.iter().map(|f| f.pane_id).collect();
        assert_eq!(ids, vec![2, 6], "only well-formed known tools survive");
    }

    /// Same pane number in two sessions is normal and must stay distinct.
    #[test]
    fn identical_pane_ids_in_different_sessions_are_separate() {
        let found = scan_of("SCAN mob 3 claude\nSCAN other 3 claude\n").found;
        assert_eq!(found.len(), 2);
        assert_ne!(found[0].session, found[1].session);
    }

    #[test]
    fn empty_output_finds_nothing() {
        let scan = scan_of("");
        assert!(scan.found.is_empty() && scan.spooled.is_empty());
    }

    /// Without the sentinel the output may be truncated, and treating a partial
    /// read as "nothing is running" would cull every foreign row.
    #[test]
    fn output_without_the_sentinel_is_incomplete() {
        assert!(!parse("SCAN mob 2 claude\n").complete);
        assert!(scan_of("SCAN mob 2 claude\n").complete);
    }

    fn rec(name: &str, body: &str) -> String {
        format!("SPOOL /tmp/s/{}:{}\n", name, body)
    }

    #[test]
    fn parses_a_spool_record() {
        let s = scan_of(&rec(
            "other.3",
            "ts=100,pane_id=3,session=other,tool=claude,status=waiting,task=Fix it",
        ));
        assert_eq!(s.spooled.len(), 1);
        assert_eq!(s.spooled[0].session, "other");
        assert_eq!(s.spooled[0].pane_id, 3);
        assert_eq!(s.spooled[0].ts, 100.0);
        assert_eq!(s.spooled[0].args.get("task").unwrap(), "Fix it");
    }

    /// The rename into place is what publishes a record; a `.tmp` is by
    /// definition still being written.
    /// An in-flight tool stamp shares the directory but is not an agent record.
    /// It parses to nothing today, so this pins the intent rather than the
    /// accident of a malformed line being dropped downstream.
    #[test]
    fn an_inflight_stamp_is_never_read_as_an_agent() {
        let scan = scan_of(&rec("inflight.mob.3", "1788584481 call-1"));
        assert!(scan.spooled.is_empty(), "a tool stamp must not become a row");
    }

    #[test]
    fn a_tmp_file_is_never_read() {
        let s = scan_of(&rec(
            "other.3.1234.tmp",
            "ts=100,pane_id=3,session=other,status=working",
        ));
        assert!(s.spooled.is_empty());
    }

    /// A torn or truncated record must be dropped, not half-applied.
    #[test]
    fn malformed_records_are_dropped() {
        for body in [
            "ts=notanumber,pane_id=3,session=other,status=working",
            "pane_id=3,session=other,status=working",
            "ts=100,session=other,status=working",
            "ts=100,pane_id=3,status=working",
            "ts=100,pane_id=3,session=,status=working",
            "garbage",
            "",
        ] {
            assert!(scan_of(&rec("other.3", body)).spooled.is_empty(), "body {:?}", body);
        }
    }

    /// The filename owns identity: a record claiming another agent's pane while
    /// living in this file is malformed and must not be attributed anywhere.
    #[test]
    fn a_record_disagreeing_with_its_filename_is_rejected() {
        let s = scan_of(&rec("other.3", "ts=100,pane_id=9,session=other,status=working"));
        assert!(s.spooled.is_empty(), "pane must match the filename");
        let s = scan_of(&rec("other.3", "ts=100,pane_id=3,session=elsewhere,status=working"));
        assert!(s.spooled.is_empty(), "session must match the filename");
    }

    /// A file with extra lines is malformed; later lines must not become rows.
    #[test]
    fn only_the_first_line_of_a_file_is_used() {
        let s = scan_of(&format!(
            "{}{}",
            rec("other.3", "ts=100,pane_id=3,session=other,status=waiting"),
            rec("other.3", "ts=200,pane_id=3,session=other,status=done"),
        ));
        assert_eq!(s.spooled.len(), 1);
        assert_eq!(s.spooled[0].ts, 100.0, "the first record wins");
    }

    #[test]
    fn scan_and_spool_are_parsed_from_one_stream() {
        let s = scan_of(&format!(
            "SCAN other 3 claude\n{}",
            rec("other.3", "ts=100,pane_id=3,session=other,status=working")
        ));
        assert_eq!(s.found.len(), 1);
        assert_eq!(s.spooled.len(), 1);
        assert!(s.complete);
    }

    /// The awk guard is negated, so every tool must be joined with `&&`: an `||`
    /// there would match nothing at all.
    #[test]
    fn script_filters_on_every_tool() {
        let s = scan_script(&["claude", "codex"]);
        assert!(s.contains(r#"cmd != "claude" && cmd != "codex""#), "{}", s);
        assert!(s.contains("axeww"), "BSD form is required for environments");
    }

    /// Runs the real script through `sh` against a stubbed `ps`, so the awk
    /// program is executed rather than pattern-matched. The awk is the part that
    /// can silently return nothing, which is indistinguishable from "no agents".
    mod script {
        use super::*;
        use std::io::Write;
        use std::process::Command;

        /// Lines are `pid command ENV=...`, matching `ps axeww -o pid=,command=`.
        ///
        /// `tag` keeps each case's stub in its own directory: tests run in
        /// parallel, and a shared path means one case's `ps` answers another's.
        fn run(tag: &str, ps_output: &str) -> String {
            run_with_spool(tag, ps_output, &[])
        }

        /// `spool` is `(filename, contents)`, staged into a real directory the
        /// script reads, so the spool branch is executed rather than assumed.
        fn run_with_spool(tag: &str, ps_output: &str, spool: &[(&str, &str)]) -> String {
            let dir = std::env::temp_dir().join(format!("zj-scan-{}-{}", std::process::id(), tag));
            std::fs::create_dir_all(&dir).unwrap();
            let ps = dir.join("ps");
            let mut f = std::fs::File::create(&ps).unwrap();
            write!(f, "#!/bin/sh\ncat <<'EOF'\n{}\nEOF\n", ps_output).unwrap();
            drop(f);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&ps, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            let spool_dir = dir.join("spool");
            if !spool.is_empty() {
                std::fs::create_dir_all(&spool_dir).unwrap();
                for (name, body) in spool {
                    std::fs::write(spool_dir.join(name), body).unwrap();
                }
            }
            let path = format!("{}:{}", dir.display(), std::env::var("PATH").unwrap_or_default());
            let out = Command::new("sh")
                .arg("-c")
                .arg(scan_script(&TOOLS))
                .env("PATH", path)
                .env("ZJ_AGENT_SPOOL_DIR", &spool_dir)
                // These assert the process-and-spool contract byte for byte, and
                // the job pass reads the real `$HOME`: left on, whichever agents
                // happen to be running on the machine would append themselves to
                // every expectation below. It has its own tests.
                .env("ZJ_AGENT_JOBS", "0")
                .output()
                .expect("sh runs");
            let _ = std::fs::remove_dir_all(&dir);
            String::from_utf8_lossy(&out.stdout).into_owned()
        }

        const PROCS: &str = concat!(
            "45985 claude ZELLIJ=0 ZELLIJ_PANE_ID=2 ZELLIJ_SESSION_NAME=mob\n",
            "47845 claude ZELLIJ=0 ZELLIJ_PANE_ID=3 ZELLIJ_SESSION_NAME=mob\n",
            "43820 codex ZELLIJ=0 ZELLIJ_PANE_ID=6 ZELLIJ_SESSION_NAME=mob\n",
            "67819 claude ZELLIJ=0 ZELLIJ_PANE_ID=11 ZELLIJ_SESSION_NAME=other\n",
            "1234 nvim ZELLIJ=0 ZELLIJ_PANE_ID=9 ZELLIJ_SESSION_NAME=mob\n",
            "5678 claude SOME=thing\n",
        );

        /// A server process is not an agent, and an agent is not a server.
        #[test]
        fn reports_a_running_server_for_every_session() {
            let procs = concat!(
                "45985 claude ZELLIJ=0 ZELLIJ_PANE_ID=2 ZELLIJ_SESSION_NAME=mob\n",
                "1743 /opt/homebrew/bin/zellij --server /tmp/zellij-501/contract_version_1/mob X=1\n",
                "6108 /opt/homebrew/bin/zellij --server /tmp/zellij-501/contract_version_1/other X=1\n",
                "540 /System/Library/CoreServices/appleeventsd --server\n",
            );
            let scan = parse(&run("live", procs));
            assert_eq!(
                scan.live,
                vec!["mob".to_string(), "other".to_string()],
                "one entry per zellij server, and nothing else's --server"
            );
            assert_eq!(scan.found.len(), 1, "a server process is not an agent");
        }

        /// Keyed the same way a row is, or the liveness lookup misses.
        #[test]
        fn a_servers_session_name_is_sanitized() {
            let procs = "1743 /opt/homebrew/bin/zellij --server /tmp/zellij-501/contract_version_1/my session\n";
            let scan = parse(&run("sanitize", procs));
            assert_eq!(scan.live, vec![crate::agent::sanitize_session("my session")]);
        }

        /// Every session at once: the scan is no longer scoped to one.
        #[test]
        fn finds_agents_across_every_session() {
            assert_eq!(
                run("all", PROCS),
                "SCAN mob 2 claude\nSCAN mob 3 claude\nSCAN mob 6 codex\nSCAN other 11 claude\nSCANEND\n"
            );
        }

        /// `sort -u` keys on the whole line, so a pane number repeated in another
        /// session must survive rather than being deduplicated away.
        #[test]
        fn same_pane_id_in_two_sessions_both_survive() {
            let procs = concat!(
                "1 claude ZELLIJ_PANE_ID=3 ZELLIJ_SESSION_NAME=mob\n",
                "2 claude ZELLIJ_PANE_ID=3 ZELLIJ_SESSION_NAME=other\n",
            );
            assert_eq!(run("dup", procs), "SCAN mob 3 claude\nSCAN other 3 claude\nSCANEND\n");
        }

        /// An agent typed into an existing shell is a child of that shell. It is
        /// still its own process, so the executable-name match finds it where a
        /// command-line pattern anchored at the start would not.
        #[test]
        fn finds_a_shell_launched_agent() {
            let procs = "999 /opt/homebrew/bin/claude ZELLIJ_PANE_ID=4 ZELLIJ_SESSION_NAME=mob\n";
            assert_eq!(
                run("shell", procs),
                "SCAN mob 4 claude\nSCANEND\n",
                "absolute paths must match on basename"
            );
        }

        /// A process with no Zellij environment at all must not be attributed to
        /// whatever session is being scanned.
        #[test]
        fn a_process_outside_zellij_is_skipped() {
            let procs = "5678 claude SOME=thing\n";
            assert_eq!(run("nozellij", procs), "SCANEND\n");
        }

        /// A pane id with no session cannot be attributed to anything.
        #[test]
        fn a_pane_without_a_session_is_skipped() {
            let procs = "1 claude ZELLIJ_PANE_ID=2\n";
            assert_eq!(run("nosess", procs), "SCANEND\n");
        }

        /// The script must emit both sources in one invocation, so the poll cost
        /// stays at one command rather than two.
        #[test]
        fn one_invocation_returns_scan_and_spool() {
            let procs = "1 claude ZELLIJ_PANE_ID=3 ZELLIJ_SESSION_NAME=other\n";
            let out = run_with_spool(
                "both",
                procs,
                &[("other.3", "ts=100,pane_id=3,session=other,status=working\n")],
            );
            let scan = parse(&out);
            assert_eq!(scan.found.len(), 1, "{:?}", out);
            assert_eq!(scan.spooled.len(), 1, "{:?}", out);
            assert!(scan.complete);
        }

        /// A missing spool directory is the normal first-run state, not an error,
        /// and must not stop the scan half of the output.
        #[test]
        fn a_missing_spool_directory_is_silent() {
            let procs = "1 claude ZELLIJ_PANE_ID=3 ZELLIJ_SESSION_NAME=other\n";
            let out = run("nospool", procs);
            assert_eq!(out, "SCAN other 3 claude\nSCANEND\n", "no error output");
            assert!(parse(&out).complete);
        }

        /// An empty directory is the state right after a cleanup.
        #[test]
        fn an_empty_spool_directory_is_silent() {
            let out = run_with_spool("emptyspool", "", &[("ignored", "")]);
            let scan = parse(&out);
            assert!(scan.spooled.is_empty() && scan.complete, "{:?}", out);
        }

        /// A killed agent fires no SessionEnd, so without a sweep its record
        /// would sit in the directory forever. Anything this old is far past
        /// STALE_AFTER and can never render, so deleting it loses nothing.
        #[test]
        fn the_sweep_removes_orphans_but_keeps_current_records() {
            let dir = std::env::temp_dir().join(format!("zj-sweep-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            let spool = dir.join("spool");
            std::fs::create_dir_all(&spool).unwrap();
            let fresh = spool.join("other.3");
            let orphan = spool.join("gone.9");
            std::fs::write(&fresh, "ts=100,pane_id=3,session=other,status=working\n").unwrap();
            std::fs::write(&orphan, "ts=1,pane_id=9,session=gone,status=working\n").unwrap();

            let old = std::time::SystemTime::now() - std::time::Duration::from_secs(60 * 60 * 48);
            let f = std::fs::File::options().write(true).open(&orphan).unwrap();
            f.set_modified(old).unwrap();
            drop(f);

            let out = Command::new("sh")
                .arg("-c")
                .arg(scan_script(&TOOLS))
                .env("ZJ_AGENT_SPOOL_DIR", &spool)
                .output()
                .expect("sh runs");
            assert!(parse(&String::from_utf8_lossy(&out.stdout)).complete);
            assert!(fresh.exists(), "a current record must survive the sweep");
            assert!(!orphan.exists(), "a day-old orphan must be swept");
            let _ = std::fs::remove_dir_all(&dir);
        }

        /// Multi-line and half-written files reach the parser as real bytes here,
        /// rather than as hand-written fixtures.
        #[test]
        fn real_files_are_filtered_by_the_parser() {
            let out = run_with_spool(
                "filtered",
                "",
                &[
                    ("other.3", "ts=100,pane_id=3,session=other,status=working\nextra\n"),
                    ("other.4.9.tmp", "ts=100,pane_id=4,session=other,status=working\n"),
                ],
            );
            let scan = parse(&out);
            assert_eq!(scan.spooled.len(), 1, "tmp skipped, extra line ignored: {:?}", out);
            assert_eq!(scan.spooled[0].pane_id, 3);
        }
    }
}

/// Runs the real scan against the real machine, which is the only thing that
/// exercises the shell, jq, the CLI and the parser together. Machine-dependent
/// by nature - it asserts the scan is well-formed, never what it finds - so it
/// is opt-in:
///
///     cargo test --lib real_scan -- --ignored --nocapture
#[cfg(test)]
mod real_scan {
    use super::*;

    #[test]
    #[ignore = "depends on the agents running on this machine"]
    fn the_whole_scan_script_runs_and_parses() {
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(scan_script(&TOOLS))
            .output()
            .expect("sh runs");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);

        // The job pass sits between the spool read and the beacon sweep, so a
        // broken fragment shows up as a truncated scan rather than a loud error.
        assert!(stderr.is_empty(), "the scan must be silent, got: {}", stderr);
        let scan = parse(&stdout);
        assert!(scan.complete, "SCANEND must still terminate the scan");

        for j in &scan.jobs {
            assert!(crate::agent::job_pane_id(&j.id).is_some(), "unusable id {:?}", j.id);
            assert!(!j.acct.is_empty(), "every job knows its account");
        }
        eprintln!(
            "live sessions: {:?}\npane agents:   {}\nbackground:    {}",
            scan.live,
            scan.found.len(),
            scan.jobs.len()
        );
        for j in &scan.jobs {
            eprintln!(
                "  {} [{}] {}/{} fan={} age={}s  {}",
                j.id, j.acct, j.state, j.tempo, j.fan, j.age, j.name
            );
        }
    }
}
