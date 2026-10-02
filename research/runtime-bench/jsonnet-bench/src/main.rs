use jrsonnet_evaluator::{trace::PathResolver, State};
use jrsonnet_stdlib::ContextInitializer;
use std::time::Instant;

const CODE: &str = r#"
local b = std.parseJson(std.extVar("body"));
local event = std.extVar("event");
if !std.member(["push", "create", "delete"], event) || std.startsWith(b.ref, "refs/vulcan/") then ""
else std.manifestJsonMinified({repo: b.repository.full_name, ref: b.ref, n: std.length(b.commits)})
"#;
const CORE: &str = r#"
local event = std.extVar("event"); local ref = std.extVar("ref"); local repo = std.extVar("repo"); local n = std.extVar("n");
if !std.member(["push", "create", "delete"], event) || std.startsWith(ref, "refs/vulcan/") then ""
else repo + "|" + ref + "|" + n
"#;

fn run(code: &str, vars: &[(&str, &str)]) -> Result<String, String> {
    let init = ContextInitializer::new(PathResolver::new_cwd_fallback());
    for (k, v) in vars { init.add_ext_str((*k).into(), (*v).into()); }
    let mut builder = State::builder(); builder.context_initializer(init); let state = builder.build();
    let val = state.evaluate_snippet("pipeline.jsonnet", code).map_err(|e| e.to_string())?;
    Ok(val.to_string().map_err(|e| e.to_string())?.to_string())
}
fn stats(name: &str, iters: usize, mut f: impl FnMut()) {
    for _ in 0..50 { f(); }
    let mut s = Vec::new();
    for _ in 0..iters { let t = Instant::now(); f(); s.push(t.elapsed().as_nanos() as f64 / 1000.0); }
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    println!("  {name:<28} mean {:>9.2} µs  p50 {:>9.2}  p99 {:>9.2}  (n={iters})", s.iter().sum::<f64>() / s.len() as f64, s[s.len() / 2], s[s.len() * 99 / 100]);
}
fn rss_kb() -> u64 { std::fs::read_to_string("/proc/self/status").unwrap().lines().find(|l| l.starts_with("VmHWM")).and_then(|l| l.split_whitespace().nth(1)).and_then(|v| v.parse().ok()).unwrap_or(0) }

fn main() {
    let mode = std::env::args().nth(1).unwrap_or("perf".into());
    let commits: Vec<serde_json::Value> = (0..3).map(|i| serde_json::json!({"id": format!("{:040x}", i + 1), "message": format!("Update page {i}\n\nSome longer commit message text to make the payload realistic."), "url": format!("https://forge.example/eric/wiki/commit/{i}"), "author": {"name": "Eric", "email": "eric@example.com", "username": "eric"}, "added": ["a.md"], "removed": [], "modified": ["index.md", "notes/b.md"]})).collect();
    let push = serde_json::json!({"ref": "refs/heads/main", "before": "0".repeat(40), "after": "f".repeat(40), "repository": {"id": 7, "full_name": "eric/wiki", "private": true, "html_url": "https://forge.example/eric/wiki", "owner": {"login": "eric", "email": "eric@example.com"}, "description": "My wiki, with a description."}, "pusher": {"login": "eric", "email": "eric@example.com"}, "sender": {"login": "eric"}, "commits": commits, "total_commits": 3}).to_string();
    let vulcan = serde_json::json!({"ref":"refs/vulcan/notifications","repository":{"full_name":"eric/wiki"},"commits":[]}).to_string();
    match mode.as_str() {
        "perf" => {
            let out = run(CODE, &[("event", "push"), ("body", &push)]).expect("push");
            assert_eq!(serde_json::from_str::<serde_json::Value>(&out).unwrap(), serde_json::json!({"repo":"eric/wiki","ref":"refs/heads/main","n":3}), "{out}");
            assert_eq!(run(CODE, &[("event", "push"), ("body", &vulcan)]).unwrap(), "");
            assert_eq!(run(CORE, &[("event", "push"), ("ref", "refs/heads/main"), ("repo", "eric/wiki"), ("n", "3")]).unwrap(), "eric/wiki|refs/heads/main|3");
            println!("jsonnet (jrsonnet 0.5.0-pre98): correct on both workloads (payload {} bytes)", push.len());
            let r0 = rss_kb();
            stats("per event: new state+parse+run", 3000, || { let _ = run(CODE, &[("event", "push"), ("body", &push)]).unwrap(); });
            stats("per event: drop (vulcan ref)", 3000, || { let _ = run(CODE, &[("event", "push"), ("body", &vulcan)]).unwrap(); });
            stats("per event: core, no JSON", 5000, || { let _ = run(CORE, &[("event", "push"), ("ref", "refs/heads/main"), ("repo", "eric/wiki"), ("n", "3")]).unwrap(); });
            println!("  peak RSS {} KB (before {} KB)  [no compile-once path with changing ext vars; every event rebuilds state]", rss_kb(), r0);
        }
        "scale" => {
            print!("jsonnet         ");
            for n in [3usize, 100, 1000, 5000] {
                let commits: Vec<serde_json::Value> = (0..n).map(|i| serde_json::json!({"id": format!("{:040x}", i + 1), "message": format!("Update page {i}\n\nSome longer commit message text to make the payload realistic."), "url": format!("https://forge.example/eric/wiki/commit/{i}"), "author": {"name": "Eric", "email": "eric@example.com", "username": "eric"}, "added": ["a.md"], "removed": [], "modified": ["index.md", "notes/b.md"]})).collect();
                let body = serde_json::json!({"ref": "refs/heads/main", "repository": {"full_name": "eric/wiki"}, "commits": commits}).to_string();
                let iters = if n >= 1000 { 10 } else { 100 };
                let mut v = Vec::new();
                for _ in 0..iters { let t = Instant::now(); let _ = run(CODE, &[("event", "push"), ("body", &body)]).unwrap(); v.push(t.elapsed().as_micros() as f64); }
                v.sort_by(|a, b| a.partial_cmp(b).unwrap());
                print!(" | {:>6} KB {:>9.0} µs", body.len() / 1024, v[v.len() / 2]);
            }
            println!();
        }
        "runaway" => { let t = Instant::now(); let r = run("local f(n) = f(n + 1); f(0)", &[]); println!("jsonnet infinite recursion: ended after {:?}: {:?}", t.elapsed(), r.err().map(|e| e.lines().next().unwrap_or("").to_string())); }
        "loop" => { let t = Instant::now(); let r = run("std.foldl(function(a, b) a + b, std.range(1, 300000000), 0)", &[]); println!("jsonnet 300M-step fold: ended after {:?}: {:?}", t.elapsed(), r.map(|s| s.chars().take(20).collect::<String>())); }
        "membomb" => { let t = Instant::now(); let r = run(r#"std.length(std.repeat("xxxxxxxxxx", 300000000))"#, &[]); println!("jsonnet 3e9 range: ended after {:?}: {:?}", t.elapsed(), r.map(|s| s.chars().take(20).collect::<String>())); }
        _ => {}
    }
}
