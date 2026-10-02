use std::time::{Duration, Instant};
const JS: &str = r#"
function fib(n){ return n < 2 ? n : fib(n-1) + fib(n-2); }
function loop_sum(n){ let s = 0; for (let i = 0; i < n; i++) { s += (i*2) % 7; } return s; }
function list_sum(n){ const a = []; for (let i = 0; i < n; i++) a.push(i); return a.filter(x => x % 2 === 0).map(x => x*x).reduce((p, c) => p + c, 0); }
function add(a, b){ return a + b; }
function handle(event, bodyJson) {
  const b = JSON.parse(bodyJson);
  if (!["push","create","delete"].includes(event) || b.ref.startsWith("refs/vulcan/")) return "";
  return JSON.stringify({repo: b.repository.full_name, ref: b.ref, n: b.commits.length});
}
"#;
fn rss_kb() -> u64 { std::fs::read_to_string("/proc/self/status").unwrap().lines().find(|l| l.starts_with("VmRSS")).and_then(|l| l.split_whitespace().nth(1)).and_then(|v| v.parse().ok()).unwrap_or(0) }
fn body() -> String {
    let commits: Vec<serde_json::Value> = (0..3).map(|i| serde_json::json!({"id": format!("{:040x}", i + 1), "message": format!("Update page {i}\n\nSome longer commit message text to make the payload realistic."), "url": format!("https://forge.example/eric/wiki/commit/{i}"), "author": {"name": "Eric", "email": "eric@example.com", "username": "eric"}, "added": ["a.md"], "removed": [], "modified": ["index.md", "notes/b.md"]})).collect();
    serde_json::json!({"ref": "refs/heads/main", "before": "0".repeat(40), "after": "f".repeat(40), "repository": {"id": 7, "full_name": "eric/wiki", "private": true, "html_url": "https://forge.example/eric/wiki", "owner": {"login": "eric", "email": "eric@example.com"}, "description": "My wiki, with a description."}, "pusher": {"login": "eric", "email": "eric@example.com"}, "sender": {"login": "eric"}, "commits": commits, "total_commits": 3}).to_string()
}
fn call_num(scope: &mut v8::PinScope, name: &str, args: &[f64]) -> f64 {
    let ctx = scope.get_current_context(); let global = ctx.global(scope);
    let key = v8::String::new(scope, name).unwrap(); let f = global.get(scope, key.into()).unwrap(); let f = v8::Local::<v8::Function>::try_from(f).unwrap();
    let a: Vec<v8::Local<v8::Value>> = args.iter().map(|x| v8::Number::new(scope, *x).into()).collect();
    f.call(scope, global.into(), &a).unwrap().number_value(scope).unwrap()
}
fn setup(isolate: &mut v8::OwnedIsolate) {
    v8::scope!(let scope, isolate);
    let context = v8::Context::new(scope, Default::default());
    let scope = &mut v8::ContextScope::new(scope, context);
    let code = v8::String::new(scope, JS).unwrap(); let script = v8::Script::compile(scope, code, None).unwrap(); script.run(scope).unwrap();
}
fn main() {
    let platform = v8::new_default_platform(0, false).make_shared(); v8::V8::initialize_platform(platform); v8::V8::initialize();
    let mode = std::env::args().nth(1).unwrap_or("compute".into());
    let mut isolate = v8::Isolate::new(Default::default());
    if mode == "compute" {
        v8::scope!(let scope, &mut isolate);
        let context = v8::Context::new(scope, Default::default()); let scope = &mut v8::ContextScope::new(scope, context);
        let code = v8::String::new(scope, JS).unwrap(); v8::Script::compile(scope, code, None).unwrap().run(scope).unwrap();
        print!("v8 (JIT)        ");
        let t = Instant::now(); let r = call_num(scope, "fib", &[30.0]); assert_eq!(r, 832040.0); print!(" | fib(30) {:>7.1} ms", t.elapsed().as_secs_f64() * 1000.0);
        let t = Instant::now(); let r = call_num(scope, "loop_sum", &[1e7]); assert_eq!(r, 29999997.0); print!(" | loop 10M {:>7.1} ms", t.elapsed().as_secs_f64() * 1000.0);
        let t = Instant::now(); let r = call_num(scope, "list_sum", &[2e5]); assert_eq!(r, 1333313333400000.0); print!(" | list 200k {:>6.1} ms", t.elapsed().as_secs_f64() * 1000.0);
        let t = Instant::now(); for i in 0..200_000 { assert_eq!(call_num(scope, "add", &[i as f64, 1.0]), i as f64 + 1.0); }
        println!(" | call {:.2} µs/call", t.elapsed().as_secs_f64() * 1e6 / 200_000.0);
        // JSON handle, warm
        let b = body(); let ctx = scope.get_current_context(); let global = ctx.global(scope);
        let key = v8::String::new(scope, "handle").unwrap(); let f = v8::Local::<v8::Function>::try_from(global.get(scope, key.into()).unwrap()).unwrap();
        let ev = v8::String::new(scope, "push").unwrap(); let bj = v8::String::new(scope, &b).unwrap();
        for _ in 0..2000 { f.call(scope, global.into(), &[ev.into(), bj.into()]).unwrap(); }
        let t = Instant::now(); for _ in 0..20_000 { f.call(scope, global.into(), &[ev.into(), bj.into()]).unwrap(); }
        println!("v8 warm JSON accept+reshape (1.4 KB): {:.2} µs/event", t.elapsed().as_secs_f64() * 1e6 / 20_000.0);
    } else if mode == "cold" {
        drop(isolate);
        let b = body();
        let t = Instant::now();
        for _ in 0..300 {
            let mut iso = v8::Isolate::new(Default::default()); setup(&mut iso);
            v8::scope!(let scope, &mut iso);
            let context = v8::Context::new(scope, Default::default()); let scope = &mut v8::ContextScope::new(scope, context);
            let code = v8::String::new(scope, JS).unwrap(); v8::Script::compile(scope, code, None).unwrap().run(scope).unwrap();
            let global = context.global(scope); let key = v8::String::new(scope, "handle").unwrap(); let f = v8::Local::<v8::Function>::try_from(global.get(scope, key.into()).unwrap()).unwrap();
            let ev = v8::String::new(scope, "push").unwrap(); let bj = v8::String::new(scope, &b).unwrap(); f.call(scope, global.into(), &[ev.into(), bj.into()]).unwrap();
        }
        println!("v8 fresh isolate + context + script + 1 event: {:.0} µs", t.elapsed().as_secs_f64() * 1e6 / 300.0);
    } else if mode == "mem" {
        drop(isolate);
        let before = rss_kb(); let mut v = Vec::new();
        for _ in 0..50 { let mut iso = v8::Isolate::new(Default::default()); setup(&mut iso); v.push(iso); }
        let after = rss_kb(); println!("v8: 50 warm isolates: +{} KB total, ~{} KB each", after - before, (after - before) / 50); while let Some(i) = v.pop() { drop(i); }
    } else if mode == "runaway" {
        let handle = isolate.thread_safe_handle();
        std::thread::spawn(move || { std::thread::sleep(Duration::from_millis(200)); handle.terminate_execution(); });
        v8::scope!(let scope, &mut isolate);
        let context = v8::Context::new(scope, Default::default()); let scope = &mut v8::ContextScope::new(scope, context);
        let code = v8::String::new(scope, "while(true){}").unwrap(); let script = v8::Script::compile(scope, code, None).unwrap();
        let t = Instant::now(); let r = script.run(scope); println!("v8 runaway via terminate_execution at 200 ms: stopped after {:?}: result is_none={}", t.elapsed(), r.is_none());
    }
}
