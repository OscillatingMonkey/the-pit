//! Terminal output. Prints names, fingerprints and outcomes — never values.

use std::io::IsTerminal;

use serde_json::Value;

fn color() -> bool {
    std::io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

fn paint(code: &str, s: &str) -> String {
    if color() {
        format!("\x1b[{code}m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}

pub fn bold(s: &str) -> String {
    paint("1", s)
}
pub fn dim(s: &str) -> String {
    if s.is_empty() {
        String::new()
    } else {
        paint("2", s)
    }
}
pub fn ok(s: &str) {
    eprintln!("{} {s}", paint("32", "✓"));
}
pub fn warn(s: &str) {
    eprintln!("{} {s}", paint("33", "!"));
}
pub fn note(s: &str) {
    if !s.is_empty() {
        eprintln!("{} {s}", paint("36", "·"));
    }
}
pub fn error(s: &str) {
    eprintln!("{} {s}", paint("31", "✗"));
}
pub fn title(s: &str) {
    println!("\n{}", bold(s));
}

pub fn dur(secs: u64) -> String {
    match secs {
        s if s >= 3600 => format!("{}h{:02}m", s / 3600, (s % 3600) / 60),
        s if s >= 60 => format!("{}m", s / 60),
        s => format!("{s}s"),
    }
}

pub fn print_json(v: &Value) {
    println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
}

pub fn secret_line(s: &Value, indent: &str) {
    let name = s["name"].as_str().unwrap_or("");
    let state = if s["set"] == serde_json::json!(true) {
        format!("{} {}", paint("32", "●"), s["fp"].as_str().unwrap_or(""))
    } else {
        format!("{} {:<12}", paint("33", "○"), "empty")
    };
    let prot = match s["protection"].as_str().unwrap_or("") {
        "sealed" => "sealed",
        "hashed" => "one-way",
        "plain" => "plain",
        o => o,
    };
    let kind = if s["kind"] == "file" { " file" } else { "" };
    let stranded = s["unpushable_to"].as_array().map(|a| a.len()).unwrap_or(0);
    if stranded > 0 {
        println!(
            "{indent}{:<34} {}",
            name,
            paint(
                "33",
                &format!("! one-way but pushed to {stranded} destination(s) — it will not be sent")
            )
        );
    }
    println!(
        "{indent}{:<34} {} {:<7}{}  {}",
        name,
        state,
        prot,
        kind,
        dim(s["description"]
            .as_str()
            .unwrap_or("")
            .chars()
            .take(90)
            .collect::<String>()
            .as_str())
    );
}
