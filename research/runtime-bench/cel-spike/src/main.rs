use cel::{Context, Program};
use std::time::Instant;
fn rss_kb() -> u64 {
    std::fs::read_to_string("/proc/self/status").unwrap().lines()
        .find(|l| l.starts_with("VmHWM")).and_then(|l| l.split_whitespace().nth(1)).and_then(|v| v.parse().ok()).unwrap_or(0)
}
fn main() {
    let which = std::env::args().nth(1).unwrap();
    let n: i64 = std::env::args().nth(2).and_then(|v| v.parse().ok()).unwrap_or(100);
    let items: Vec<i64> = (0..n).collect();
    let body = serde_json::json!({"items": items});
    let mut ctx = Context::default();
    ctx.add_variable("body", body).unwrap();
    ctx.add_function("double", |n: i64| n * 2);
    let expr = match which.as_str() {
        "amplify" => "body.items.map(a, body.items).size()",
        "string" => r#"["aaaaaaaaaa"].map(s, s+s+s+s+s+s+s+s+s+s).map(s, s+s+s+s+s+s+s+s+s+s).map(s, s+s+s+s+s+s+s+s+s+s).map(s, s+s+s+s+s+s+s+s+s+s)[0].size()"#,
        "hostfn" => "double(21)",
        _ => "1",
    };
    let t = Instant::now();
    let p = Program::compile(expr).unwrap();
    println!("{which} n={n}: {:?} in {:?}, peak rss {} KB", p.execute(&ctx).map(|v| format!("{v:?}")), t.elapsed(), rss_kb());
    if which == "hostfn" { println!("refs: {:?}", Program::compile("body.items.all(a, a>=0)").unwrap().references().variables()); }
}
