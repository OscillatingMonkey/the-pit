//! Completion and hints, for the console and for zsh, bash and fish.
//!
//! One engine answers both: commands and subcommands, flags, flag values, and
//! names from the vault — projects, channels at any depth, secrets,
//! destinations, connections, contacts, tickets, settings — each with a short
//! description. Never values. Names come from the agent over the `complete`
//! client, which may only read listings and does not keep a session awake.

use std::cell::RefCell;
use std::collections::HashMap;
use std::time::{Duration, Instant};

use clap::{Arg, ArgAction, Command, CommandFactory, ValueHint};
use serde_json::{json, Value};

use crate::cli::Cli;
use crate::protocol;

/// Printed by `pit __complete` when the shell should complete a file path.
pub const FILES: &str = "::files";

/// Words the console understands on top of the CLI's commands.
pub const CONSOLE_WORDS: [(&str, &str); 4] = [
    (
        "use",
        "Set a PROJECT/CHANNEL context for the commands that follow",
    ),
    ("help", "List commands, or explain one: help COMMAND"),
    ("exit", "Leave the console"),
    ("quit", "Leave the console"),
];

/// Events worth filtering `pit log` by.
const EVENTS: &[(&str, &str)] = &[
    ("push", "a push to a destination"),
    ("reveal", "a value shown"),
    ("run", "values given to a program"),
    ("unlock", "the pit opened"),
    ("lock", "the pit closed"),
    ("approve", "an approval given"),
    ("approval.window", "one approval covering a run of changes"),
    ("elevate", "sensitive actions opened for a while"),
    ("secret.set", "a value set"),
    ("secret.declare", "a secret declared"),
    ("secret.import", "values imported"),
    ("secret.rm", "a secret deleted"),
    ("share.send", "a secret shared with someone"),
    ("share.accept", "a shared secret saved"),
    ("share.request", "a receive window opened"),
    ("channel.add", "a channel added"),
    ("channel.rm", "a channel deleted"),
    ("project.add", "a project added"),
    ("project.rm", "a project deleted"),
    ("dest.add", "a destination added"),
    ("conn.add", "a connection added"),
    ("bundle.export", "a bundle exported"),
    ("bundle.import", "a bundle imported"),
];

const DURATIONS: &[(&str, &str)] = &[
    ("5m", "five minutes"),
    ("15m", "fifteen minutes"),
    ("30m", "half an hour"),
    ("1h", "an hour"),
    ("8h", "a working day"),
];

const ON_OFF: &[(&str, &str)] = &[("on", "turn it on"), ("off", "turn it off")];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub value: String,
    pub help: String,
}

fn cand(value: impl Into<String>, help: impl Into<String>) -> Candidate {
    Candidate {
        value: value.into(),
        help: help.into(),
    }
}

fn from_pairs(p: &[(&str, &str)]) -> Vec<Candidate> {
    p.iter().map(|(v, h)| cand(*v, *h)).collect()
}

/// What the engine knows about: listings fetched from the agent (names only),
/// cached briefly, and the scope commands use when theirs is left out.
#[derive(Default)]
pub struct Engine {
    pub context: Option<String>,
    /// Include the console's own words (`use`, `help`, `exit`).
    pub console: bool,
    cache: RefCell<HashMap<&'static str, (Instant, Value)>>,
    /// Tests fill the cache and never reach an agent.
    offline: bool,
}

impl Engine {
    pub fn console() -> Self {
        Engine {
            console: true,
            ..Default::default()
        }
    }

    /// For a shell: the folder's `.pit.toml` link is the context.
    pub fn shell() -> Self {
        Engine {
            context: crate::cli::link_scope(),
            ..Default::default()
        }
    }

    #[cfg(test)]
    pub fn with(listings: &[(&'static str, Value)]) -> Self {
        let e = Engine {
            console: true,
            offline: true,
            ..Default::default()
        };
        for (op, v) in listings {
            e.cache.borrow_mut().insert(op, (Instant::now(), v.clone()));
        }
        e
    }

    fn get(&self, op: &'static str) -> Value {
        if let Some((at, v)) = self.cache.borrow().get(op) {
            if self.offline || at.elapsed() < Duration::from_secs(5) {
                return v.clone();
            }
        }
        if self.offline {
            return Value::Null;
        }
        let v = protocol::peek(op).unwrap_or(Value::Null);
        self.cache
            .borrow_mut()
            .insert(op, (Instant::now(), v.clone()));
        v
    }

    // -----------------------------------------------------------------------
    // names from the vault

    /// Every scope: `global`, projects, and channels at every depth.
    fn scopes(&self) -> Vec<Candidate> {
        let t = self.get("tree");
        let mut out = vec![];
        if !t.is_null() {
            out.push(cand("global", "secrets shared by every project"));
        }
        for p in arr(&t["projects"]) {
            let pn = s(&p["name"]);
            out.push(cand(pn, or(s(&p["description"]), "project")));
            for c in arr(&p["channels"]) {
                let mut help = or(s(&c["description"]), "channel").to_string();
                if c["protected"] == json!(true) {
                    help.push_str(" [protected]");
                }
                out.push(cand(format!("{pn}/{}", s(&c["name"])), help));
            }
        }
        out
    }

    fn projects(&self) -> Vec<Candidate> {
        arr(&self.get("tree")["projects"])
            .iter()
            .map(|p| cand(s(&p["name"]), or(s(&p["description"]), "project")))
            .collect()
    }

    fn is_scope(&self, w: &str) -> bool {
        self.scopes().iter().any(|c| c.value == w)
    }

    /// Secret names visible from a scope: its own, those of every channel
    /// above it and its project (while it inherits), and globals.
    fn secrets_in(&self, scope: &str) -> Vec<Candidate> {
        let t = self.get("tree");
        let mut out: Vec<Candidate> = vec![];
        let mut add = |list: &Value, from: &str| {
            for x in arr(list) {
                let n = s(&x["name"]).to_string();
                if out.iter().any(|c| c.value == n) {
                    continue;
                }
                let d = s(&x["description"]);
                let state = if x["set"] == json!(false) {
                    ", empty"
                } else {
                    ""
                };
                out.push(cand(
                    n,
                    format!("{}{state} · {from}", or(d, s(&x["protection"]))),
                ));
            }
        };
        let (project, channel) = match scope.split_once('/') {
            Some((p, c)) => (p, Some(c)),
            None => (scope, None),
        };
        if scope == "global" {
            add(&t["globals"], "global");
            return out;
        }
        for p in arr(&t["projects"])
            .iter()
            .filter(|p| s(&p["name"]) == project)
        {
            let chans = arr(&p["channels"]);
            // nearest first, so a nearer secret's description wins
            let mut at = channel;
            let mut inherits = true;
            while let Some(c) = at {
                let Some(ch) = chans.iter().find(|x| s(&x["name"]) == c) else {
                    break;
                };
                add(&ch["secrets"], &format!("{project}/{c}"));
                inherits = ch["inherit"] != json!(false);
                if !inherits {
                    break;
                }
                at = crate::model::parent_channel(c);
            }
            if inherits {
                add(&p["secrets"], project);
            }
        }
        add(&t["globals"], "global");
        out
    }

    fn destinations_in(&self, scope: &str) -> Vec<Candidate> {
        let Some((project, channel)) = scope.split_once('/') else {
            return vec![];
        };
        let t = self.get("tree");
        arr(&t["projects"])
            .iter()
            .filter(|p| s(&p["name"]) == project)
            .flat_map(|p| arr(&p["channels"]))
            .filter(|c| s(&c["name"]) == channel)
            .flat_map(|c| arr(&c["destinations"]))
            .map(|d| {
                cand(
                    s(&d["name"]),
                    format!("{} {}", s(&d["kind"]), s(&d["address"])),
                )
            })
            .collect()
    }

    fn connections(&self) -> Vec<Candidate> {
        arr(&self.get("tree")["connections"])
            .iter()
            .map(|c| cand(s(&c["name"]), s(&c["kind"])))
            .collect()
    }

    fn listing(&self, op: &'static str, list: &str, value: &str, help: &str) -> Vec<Candidate> {
        arr(&self.get(op)[list])
            .iter()
            .map(|x| cand(s(&x[value]), s(&x[help])))
            .collect()
    }

    fn backup_targets(&self) -> Vec<Candidate> {
        crate::backup::Config::load()
            .map(|c| {
                c.all_targets()
                    .iter()
                    .map(|t| cand(t.name.clone(), crate::backup::describe(t)))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn settings(&self) -> Vec<Candidate> {
        let v = self.get("settings.get");
        v.as_object()
            .map(|m| {
                m.iter()
                    .map(|(k, v)| cand(k.clone(), format!("now {v}")))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The scope a command works in: the first scope typed, else the context.
    fn scope_of(&self, typed: &[&str]) -> Option<String> {
        typed
            .iter()
            .find(|w| self.is_scope(w))
            .map(|w| w.to_string())
            .or_else(|| self.context.clone())
    }

    // -----------------------------------------------------------------------
    // the command line

    /// Candidates for the word being typed (`partial`), after the words before it.
    pub fn candidates(&self, before: &[&str], partial: &str) -> Vec<Candidate> {
        let mut out = self.raw(before, partial);
        out.retain(|c| c.value == FILES || c.value.starts_with(partial));
        fold_paths(&mut out, partial);
        out.sort_by(|a, b| a.value.cmp(&b.value));
        out.dedup_by(|a, b| a.value == b.value);
        out
    }

    fn raw(&self, before: &[&str], partial: &str) -> Vec<Candidate> {
        if before.is_empty() {
            let mut all = commands(&Cli::command());
            if self.console {
                all.extend(from_pairs(&CONSOLE_WORDS));
            }
            return all;
        }
        if self.console && (before[0] == "help" || before[0] == "?") {
            let (cmd, depth) = walk(&before[1..]);
            return if depth == before.len() - 1 {
                commands(&cmd)
            } else {
                vec![]
            };
        }
        if self.console && before[0] == "use" {
            return if before.len() == 1 {
                self.scopes()
            } else {
                vec![]
            };
        }
        let (cmd, depth) = walk(before);
        if depth == 0 {
            return vec![];
        }
        let path: Vec<&str> = before[..depth].to_vec();
        let rest = &before[depth..];
        if rest.contains(&"--") {
            return vec![];
        }
        // A flag waiting for its value.
        if let Some(last) = rest.last() {
            if let Some(a) = flag(&cmd, last) {
                if takes_value(a) && !last.contains('=') {
                    let typed = positionals(&cmd, rest);
                    return self.values(&path, a, 0, &typed, rest);
                }
            }
        }
        if partial.starts_with('-') {
            return flags(&cmd, rest);
        }
        let typed = positionals(&cmd, rest);
        if cmd.has_subcommands() {
            return if typed.is_empty() {
                commands(&cmd)
            } else {
                vec![]
            };
        }
        match positional_at(&cmd, typed.len()) {
            Some((a, k)) => self.values(&path, a, k, &typed, rest),
            None => vec![],
        }
    }

    /// Values for one argument. `k` is the position within a multi-word
    /// argument such as `[SCOPE] NAME`; `typed` are the positionals so far.
    fn values(
        &self,
        path: &[&str],
        a: &Arg,
        k: usize,
        typed: &[&str],
        rest: &[&str],
    ) -> Vec<Candidate> {
        let pv: Vec<Candidate> = a
            .get_possible_values()
            .iter()
            .filter(|v| !v.is_hide_set())
            .map(|v| {
                cand(
                    v.get_name(),
                    v.get_help().map(|h| h.to_string()).unwrap_or_default(),
                )
            })
            .collect();
        if !pv.is_empty() {
            return pv;
        }
        if matches!(
            a.get_value_hint(),
            ValueHint::AnyPath | ValueHint::FilePath | ValueHint::DirPath
        ) {
            return vec![cand(FILES, "")];
        }
        let top = path.first().copied().unwrap_or("");
        let sub = path.get(1).copied().unwrap_or("");
        let scope = self.scope_of(typed);
        let channels = || -> Vec<Candidate> {
            self.scopes()
                .into_iter()
                .filter(|c| c.value != "global")
                .collect()
        };
        match a.get_id().as_str() {
            "target" => channels(),
            "args" => match k {
                0 => {
                    let mut v = self.scopes();
                    if let Some(ctx) = &self.context {
                        v.extend(self.secrets_in(ctx));
                    }
                    v
                }
                1 if self.is_scope(typed[0]) => self.secrets_in(typed[0]),
                1 if top == "mv" => self.scopes(),
                2 if top == "mv" => self.scopes(),
                _ => vec![],
            },
            "into" | "to" if top != "share" && top != "backup" => self.scopes(),
            "to" if top == "share" => vec![cand(FILES, "")],
            "to" | "from" if top == "backup" => self.backup_targets(),
            "name" if top == "project" && sub != "add" => self.projects(),
            "name" if top == "disconnect" => self.connections(),
            "name" if top == "dest" && sub != "add" => {
                scope.map(|s| self.destinations_in(&s)).unwrap_or_default()
            }
            "name" if top == "backup" && sub == "untarget" => self.backup_targets(),
            "destination" | "destinations" | "dest" => {
                scope.map(|s| self.destinations_in(&s)).unwrap_or_default()
            }
            "only" | "select" => {
                let mut v = vec![cand("*", "every secret the channel sees")];
                if let Some(s) = scope {
                    v.extend(self.secrets_in(&s));
                }
                v
            }
            "project" | "projects" => self.projects(),
            "connection" | "verify" => self.connections(),
            "ticket" => self.listing("approvals", "pending", "ticket", "reason"),
            "forget" => self.listing("contact.list", "contacts", "name", "identity"),
            "cancel" => self.listing("share.pending", "windows", "window", "expires"),
            "key" => self.settings(),
            "value" if top == "settings" => {
                let key = typed.first().copied().unwrap_or("");
                if key.ends_with("_approval") {
                    from_pairs(&[("true", "ask"), ("false", "do not ask")])
                } else if key.ends_with("_secs") {
                    from_pairs(DURATIONS)
                } else {
                    vec![]
                }
            }
            "state" => from_pairs(ON_OFF),
            // destination settings for the kind given with --kind (or the existing destination's)
            "sets" => {
                let kind = rest
                    .iter()
                    .position(|w| *w == "--kind")
                    .and_then(|i| rest.get(i + 1))
                    .map(|k| k.to_string());
                crate::rail::KINDS
                    .iter()
                    .filter(|k| kind.as_deref().map(|x| x == k.kind).unwrap_or(true))
                    .flat_map(|k| {
                        k.config.iter().map(move |(key, h)| {
                            cand(format!("{key}="), format!("{h} ({})", k.kind))
                        })
                    })
                    .collect()
            }
            "dur" => from_pairs(DURATIONS),
            "event" => from_pairs(EVENTS),
            "a" | "b" | "what" => vec![cand("latest", "the newest backup")],
            _ => vec![],
        }
    }

    /// A hint for the console: the rest of the word being typed, or what the
    /// command expects next. `(shown, inserted on →)`.
    pub fn hint(&self, line: &str) -> Option<(String, String)> {
        let start = line.rfind(char::is_whitespace).map(|i| i + 1).unwrap_or(0);
        let partial = &line[start..];
        let before: Vec<&str> = line[..start].split_whitespace().collect();
        if !partial.is_empty() {
            let c: Vec<Candidate> = self
                .candidates(&before, partial)
                .into_iter()
                .filter(|c| c.value != FILES)
                .collect();
            let first = c.first()?;
            let common = c.iter().fold(first.value.clone(), |acc, x| {
                acc.chars()
                    .zip(x.value.chars())
                    .take_while(|(a, b)| a == b)
                    .map(|(a, _)| a)
                    .collect()
            });
            let rest = common.get(partial.len()..).unwrap_or("").to_string();
            return match c.len() {
                1 if !first.help.is_empty() => Some((format!("{rest}  {}", first.help), rest)),
                _ if !rest.is_empty() => Some((rest.clone(), rest)),
                _ => None,
            };
        }
        if before.is_empty() {
            return None;
        }
        Some((self.expects(&before)?, String::new()))
    }

    /// What a command wants next, from its own definition.
    fn expects(&self, before: &[&str]) -> Option<String> {
        let (cmd, depth) = walk(before);
        if depth == 0 {
            return None;
        }
        let rest = &before[depth..];
        if let Some(a) = rest.last().and_then(|l| flag(&cmd, l)) {
            if takes_value(a) && !rest.last()?.contains('=') {
                return Some(format!("{}  {}", value_name(a), help(a)));
            }
        }
        let typed = positionals(&cmd, rest);
        if cmd.has_subcommands() && typed.is_empty() {
            let subs: Vec<String> = commands(&cmd).into_iter().map(|c| c.value).collect();
            return Some(subs.join(" | "));
        }
        let mut parts = vec![];
        if let Some((a, k)) = positional_at(&cmd, typed.len()) {
            let mut names = value_name(a);
            if k > 0 {
                names = names
                    .split_whitespace()
                    .skip(k)
                    .collect::<Vec<_>>()
                    .join(" ");
            }
            parts.push(format!("{names}  {}", help(a)));
        }
        let required: Vec<String> = cmd
            .get_arguments()
            .filter(|a| a.get_long().is_some() && a.is_required_set())
            .filter(|a| {
                !rest.iter().any(|w| {
                    flag(&cmd, w)
                        .map(|f| f.get_id() == a.get_id())
                        .unwrap_or(false)
                })
            })
            .map(|a| format!("--{} {}", a.get_long().unwrap_or(""), value_name(a)))
            .collect();
        parts.extend(required);
        if parts.is_empty() {
            let any = cmd
                .get_arguments()
                .any(|a| a.get_long().is_some() && !a.is_hide_set());
            return any.then(|| "--… for options".to_string());
        }
        Some(parts.join("  "))
    }
}

// ---------------------------------------------------------------------------
// reading the command definition

fn s(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}
fn arr(v: &Value) -> Vec<Value> {
    v.as_array().cloned().unwrap_or_default()
}
fn or<'a>(a: &'a str, b: &'a str) -> &'a str {
    if a.is_empty() {
        b
    } else {
        a
    }
}

fn help(a: &Arg) -> String {
    a.get_help()
        .map(|h| h.to_string())
        .unwrap_or_default()
        .lines()
        .next()
        .unwrap_or("")
        .to_string()
}

fn value_name(a: &Arg) -> String {
    match a.get_value_names() {
        Some(n) if !n.is_empty() => n
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(" "),
        _ => a.get_id().as_str().to_uppercase(),
    }
}

/// Visible subcommands of `cmd` (and their aliases), with what each does.
fn commands(cmd: &Command) -> Vec<Candidate> {
    let mut out = vec![];
    for c in cmd.get_subcommands().filter(|c| !c.is_hide_set()) {
        let about = c.get_about().map(|a| a.to_string()).unwrap_or_default();
        out.push(cand(c.get_name(), about.clone()));
        for al in c.get_visible_aliases() {
            out.push(cand(al, format!("same as {}", c.get_name())));
        }
    }
    out
}

/// The deepest (sub)command the typed words name, and how many words that took.
fn walk(words: &[&str]) -> (Command, usize) {
    let mut cmd = Cli::command();
    let mut depth = 0;
    while let Some(w) = words.get(depth) {
        let next = cmd
            .get_subcommands()
            .find(|c| c.get_name() == *w || c.get_all_aliases().any(|a| a == *w))
            .cloned();
        match next {
            Some(sub) => {
                cmd = sub;
                depth += 1;
            }
            None => break,
        }
    }
    (cmd, depth)
}

fn flag<'a>(cmd: &'a Command, word: &str) -> Option<&'a Arg> {
    let w = word.split('=').next().unwrap_or(word);
    if let Some(l) = w.strip_prefix("--") {
        return cmd.get_arguments().find(|a| a.get_long() == Some(l));
    }
    let short = w.strip_prefix('-')?.chars().next()?;
    if w.len() != 2 {
        return None;
    }
    cmd.get_arguments().find(|a| a.get_short() == Some(short))
}

fn takes_value(a: &Arg) -> bool {
    matches!(a.get_action(), ArgAction::Set | ArgAction::Append)
        && a.get_num_args().map(|n| n.takes_values()).unwrap_or(true)
}

/// The positional words typed so far (flags and their values left out).
fn positionals<'a>(cmd: &Command, rest: &[&'a str]) -> Vec<&'a str> {
    let mut out = vec![];
    let mut i = 0;
    while i < rest.len() {
        let w = rest[i];
        if w.starts_with('-') && w.len() > 1 {
            if let Some(a) = flag(cmd, w) {
                if takes_value(a) && !w.contains('=') {
                    i += 1;
                }
            }
        } else {
            out.push(w);
        }
        i += 1;
    }
    out
}

/// Which positional argument the `n`th positional word belongs to, and its
/// place within that argument.
fn positional_at(cmd: &Command, n: usize) -> Option<(&Arg, usize)> {
    let mut at: usize = 0;
    for a in cmd.get_positionals().filter(|a| !a.is_hide_set()) {
        let max = a.get_num_args().map(|r| r.max_values()).unwrap_or(1);
        if n < at.saturating_add(max) {
            return Some((a, n - at));
        }
        at = at.saturating_add(max);
    }
    None
}

/// Flags not yet given (repeatable ones always), each with its help.
fn flags(cmd: &Command, rest: &[&str]) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = cmd
        .get_arguments()
        .filter(|a| !a.is_hide_set() && !a.is_positional())
        .filter(|a| {
            matches!(a.get_action(), ArgAction::Append | ArgAction::Count)
                || !rest.iter().any(|w| {
                    flag(cmd, w)
                        .map(|f| f.get_id() == a.get_id())
                        .unwrap_or(false)
                })
        })
        .filter_map(|a| a.get_long().map(|l| cand(format!("--{l}"), help(a))))
        .collect();
    out.push(cand("--help", "how to use this command"));
    out
}

/// Long paths come one level at a time: `myapp/production/eu/fra` offers
/// `myapp/production/` until the person goes deeper.
fn fold_paths(list: &mut Vec<Candidate>, partial: &str) {
    let mut deeper: HashMap<String, usize> = HashMap::new();
    list.retain(|c| {
        let rest = &c.value[partial.len().min(c.value.len())..];
        match rest.find('/') {
            Some(i) if i + 1 < rest.len() => {
                let stem = format!("{}{}", &c.value[..partial.len()], &rest[..=i]);
                *deeper.entry(stem).or_default() += 1;
                false
            }
            _ => true,
        }
    });
    for (stem, n) in deeper {
        list.push(cand(stem, format!("{n} more inside")));
    }
}

// ---------------------------------------------------------------------------
// shells

/// `pit __complete WORD…`: the last word is the one being typed. One line per
/// candidate, `value<TAB>help`; `::files` asks the shell for file names.
pub fn print_for_shell(words: &[String]) {
    let (partial, before) = match words.split_last() {
        Some((p, b)) => (p.as_str(), b.iter().map(|s| s.as_str()).collect::<Vec<_>>()),
        None => ("", vec![]),
    };
    for c in Engine::shell().candidates(&before, partial) {
        let help = c.help.replace(['\t', '\n'], " ");
        if c.help.is_empty() {
            println!("{}", c.value);
        } else {
            println!("{}\t{help}", c.value);
        }
    }
}

pub fn script(shell: &str) -> Option<&'static str> {
    Some(match shell {
        "zsh" => ZSH,
        "bash" => BASH,
        "fish" => FISH,
        _ => return None,
    })
}

const ZSH: &str = r#"#compdef pit
# The Pit: completion for zsh. Load with: eval "$(pit completions zsh)"
_pit() {
  local -a lines words_in more done_vals more_desc done_desc
  local line v d files=0
  lines=("${(@f)$(pit __complete -- "${(@)words[2,CURRENT]}" 2>/dev/null)}")
  for line in $lines; do
    [[ -z $line ]] && continue
    if [[ $line == "::files" ]]; then files=1; continue; fi
    v=${line%%$'\t'*}
    if [[ $line == *$'\t'* ]]; then d=${line#*$'\t'}; else d=""; fi
    if [[ $v == */ ]]; then
      more+=("$v"); more_desc+=("${(r:28:)v} -- $d")
    else
      done_vals+=("$v"); done_desc+=("${(r:28:)v}${d:+ -- $d}")
    fi
  done
  (( ${#done_vals} )) && compadd -l -d done_desc -- "${done_vals[@]}"
  (( ${#more} )) && compadd -l -S '' -d more_desc -- "${more[@]}"
  (( files )) && _files
  return 0
}
compdef _pit pit
"#;

const BASH: &str = r#"# The Pit: completion for bash. Load with: eval "$(pit completions bash)"
_pit() {
  local cur=${COMP_WORDS[COMP_CWORD]} line files=0
  COMPREPLY=()
  while IFS= read -r line; do
    [[ -z $line ]] && continue
    if [[ $line == "::files" ]]; then files=1; continue; fi
    COMPREPLY+=("${line%%$'\t'*}")
  done < <(pit __complete -- "${COMP_WORDS[@]:1:COMP_CWORD}" 2>/dev/null)
  if (( files )); then
    local IFS=$'\n'
    COMPREPLY+=($(compgen -f -- "$cur"))
  fi
  if [[ ${#COMPREPLY[@]} -eq 1 && ${COMPREPLY[0]} == */ ]]; then
    compopt -o nospace 2>/dev/null
  fi
}
complete -F _pit pit
"#;

const FISH: &str = r#"# The Pit: completion for fish. Load with: pit completions fish | source
function __pit_complete
    set -l tokens (commandline -opc) (commandline -ct)
    for line in (pit __complete -- $tokens[2..-1] 2>/dev/null)
        if test "$line" = "::files"
            __fish_complete_path (commandline -ct)
        else
            echo $line
        end
    end
end
complete -c pit -f -a '(__pit_complete)'
"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> Engine {
        let tree = json!({
            "globals": [{"name": "SHARED_TOKEN", "description": "", "protection": "sealed"}],
            "connections": [{"name": "vercel-main", "kind": "vercel"}],
            "projects": [{
                "name": "myapp", "description": "",
                "secrets": [{"name": "PROJECT_KEY", "description": "", "protection": "sealed"}],
                "channels": [
                    {"name": "production", "description": "live", "protected": true,
                     "secrets": [{"name": "STRIPE_KEY", "description": "payments", "protection": "sealed"}],
                     "destinations": [{"name": "web", "kind": "vercel", "address": "x"}]},
                    {"name": "production/eu", "protected": true, "secrets": [{"name": "EU_ONLY", "protection": "sealed"}], "destinations": []},
                    {"name": "production/eu/fra", "protected": true, "secrets": [{"name": "FRA_ONLY", "protection": "sealed"}], "destinations": []},
                    {"name": "development", "secrets": [{"name": "DEV_ONLY", "protection": "sealed"}], "destinations": []}
                ]
            }]
        });
        Engine::with(&[
            ("tree", tree),
            (
                "approvals",
                json!({"pending": [{"ticket": "abc123", "reason": "push myapp/production"}]}),
            ),
            (
                "contact.list",
                json!({"contacts": [{"name": "sam", "identity": "PIT-ID-X"}]}),
            ),
            (
                "settings.get",
                json!({"idle_secs": 1800, "run_needs_approval": true}),
            ),
        ])
    }

    fn complete(e: &Engine, line: &str) -> Vec<String> {
        let start = line.rfind(' ').map(|i| i + 1).unwrap_or(0);
        let before: Vec<&str> = line[..start].split_whitespace().collect();
        e.candidates(&before, &line[start..])
            .into_iter()
            .map(|c| c.value)
            .collect()
    }

    #[test]
    fn commands_aliases_and_console_words() {
        let e = engine();
        assert!(complete(&e, "rev").contains(&"reveal".to_string()));
        assert!(complete(&e, "vi").contains(&"view".to_string()));
        assert!(complete(&e, "us").contains(&"use".to_string()));
        assert_eq!(complete(&e, "backup li"), vec!["list"]);
        assert!(!complete(&e, "").iter().any(|c| c.starts_with("__")));
    }

    #[test]
    fn nested_channels_one_level_at_a_time() {
        let e = engine();
        assert_eq!(
            complete(&e, "reveal myapp/p"),
            vec!["myapp/production", "myapp/production/"]
        );
        assert_eq!(
            complete(&e, "reveal myapp/production/"),
            vec!["myapp/production/eu", "myapp/production/eu/"]
        );
        assert_eq!(
            complete(&e, "reveal myapp/production/eu/"),
            vec!["myapp/production/eu/fra"]
        );
    }

    #[test]
    fn secrets_seen_from_a_nested_channel() {
        let e = engine();
        assert_eq!(
            complete(&e, "reveal myapp/production/eu/fra "),
            vec![
                "EU_ONLY",
                "FRA_ONLY",
                "PROJECT_KEY",
                "SHARED_TOKEN",
                "STRIPE_KEY"
            ]
        );
        assert!(!complete(&e, "reveal myapp/production ").contains(&"DEV_ONLY".to_string()));
        assert_eq!(complete(&e, "push myapp/production "), vec!["web"]);
    }

    #[test]
    fn flags_and_flag_values() {
        let e = engine();
        assert!(complete(&e, "reveal --").contains(&"--copy".to_string()));
        assert_eq!(
            complete(&e, "set myapp/production X --protection "),
            vec!["hashed", "plain", "sealed"]
        );
        assert_eq!(complete(&e, "set myapp/production X -p s"), vec!["sealed"]);
        assert!(complete(&e, "receive x --into myapp/d").contains(&"myapp/development".to_string()));
        assert_eq!(complete(&e, "approve "), vec!["abc123"]);
        assert_eq!(complete(&e, "contacts --forget "), vec!["sam"]);
        assert_eq!(
            complete(&e, "settings "),
            vec!["idle_secs", "run_needs_approval"]
        );
        assert_eq!(
            complete(&e, "settings run_needs_approval "),
            vec!["false", "true"]
        );
        assert_eq!(
            complete(&e, "dest add myapp/production web --kind v"),
            vec!["vercel"]
        );
        assert_eq!(complete(&e, "reveal x --out "), vec![FILES]);
        assert_eq!(complete(&e, "completions "), vec!["bash", "fish", "zsh"]);
        // a flag already given is not offered again
        assert!(!complete(&e, "reveal --copy --").contains(&"--copy".to_string()));
    }

    #[test]
    fn context_lets_the_scope_be_left_out() {
        let mut e = engine();
        e.context = Some("myapp/development".into());
        assert_eq!(complete(&e, "reveal D"), vec!["DEV_ONLY"]);
    }

    #[test]
    fn hints_finish_words_and_say_what_comes_next() {
        let e = engine();
        let (shown, insert) = e.hint("reve").unwrap();
        assert_eq!(insert, "al");
        assert!(shown.contains("Show a secret"), "{shown}");
        let (shown, insert) = e.hint("share ").unwrap();
        assert!(insert.is_empty());
        assert!(shown.contains("--to"), "{shown}");
        assert!(e.hint("channel ").unwrap().0.contains("add"));
        assert!(e
            .hint("set myapp/production X --protection ")
            .unwrap()
            .0
            .contains("sealed"));
    }

    /// Every command, subcommand and option explains itself, so every
    /// completion has a hint.
    #[test]
    fn everything_has_help() {
        fn check(cmd: &Command, path: &str, missing: &mut Vec<String>) {
            for a in cmd.get_arguments() {
                if a.is_hide_set() || ["help", "version"].contains(&a.get_id().as_str()) {
                    continue;
                }
                if a.get_help().is_none() {
                    missing.push(format!("{path} {}", a.get_id()));
                }
            }
            for c in cmd.get_subcommands().filter(|c| !c.is_hide_set()) {
                let p = format!("{path} {}", c.get_name());
                if c.get_about().is_none() {
                    missing.push(p.clone());
                }
                check(c, &p, missing);
            }
        }
        let mut missing = vec![];
        check(&Cli::command(), "pit", &mut missing);
        assert!(missing.is_empty(), "no help text:\n{}", missing.join("\n"));
    }
}
