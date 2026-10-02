use mlua::{Function, Lua};
use std::time::Instant;
const LUA: &str = r#"
function fib(n) if n < 2 then return n end return fib(n-1) + fib(n-2) end
function loop_sum(n) local s = 0 for i = 0, n-1 do s = s + (i*2) % 7 end return s end
function list_sum(n) local a = {} for i = 1, n do a[i] = i-1 end local s = 0 for _, x in ipairs(a) do if x % 2 == 0 then s = s + x*x end end return s end
function add(a, b) return a + b end
"#;
fn main() {
    if std::env::args().nth(1).as_deref() == Some("limits") { limits(); return; }
    let lua = Lua::new(); lua.load(LUA).exec().unwrap();
    let mut t = |label: &str, name: &str, n: f64| { let f: Function = lua.globals().get(name).unwrap(); let t = Instant::now(); let r: f64 = f.call(n).unwrap(); print!(" | {label} {:>8.1} ms ({r})", t.elapsed().as_secs_f64() * 1000.0); };
    print!("luajit          ");
    t("fib(30)", "fib", 30.0); t("loop 10M", "loop_sum", 1e7); t("list 200k", "list_sum", 2e5);
    let f: Function = lua.globals().get("add").unwrap(); let t0 = Instant::now();
    for i in 0..200_000 { let r: f64 = f.call((i as f64, 1.0)).unwrap(); assert_eq!(r, i as f64 + 1.0); }
    println!(" | call {:.2} µs/call", t0.elapsed().as_secs_f64() * 1e6 / 200_000.0);
    // cold start
    let t0 = Instant::now(); for _ in 0..300 { let l = Lua::new(); l.load(LUA).exec().unwrap(); }
    println!("fresh luajit state + load script: {:.0} µs", t0.elapsed().as_secs_f64() * 1e6 / 300.0);
}
#[allow(dead_code)]
pub fn limits() {
    use mlua::{HookTriggers, VmState};
    let lua = Lua::new(); let deadline = Instant::now() + std::time::Duration::from_millis(200);
    lua.set_hook(HookTriggers { every_nth_instruction: Some(1000), ..Default::default() }, move |_, _| if Instant::now() > deadline { Err(mlua::Error::runtime("deadline")) } else { Ok(VmState::Continue) }).unwrap();
    let t = Instant::now(); let r = lua.load("while true do end").exec(); println!("luajit runaway via hook: stopped after {:?}: {:?}", t.elapsed(), r.err().map(|e| e.to_string().lines().next().unwrap_or("").to_string()));
    let lua = Lua::new(); println!("luajit set_memory_limit: {:?}", lua.set_memory_limit(64 << 20).map(|_| "ok"));
    let t = Instant::now(); let r = lua.load("local a = {} while true do a[#a+1] = string.rep('x', 100000) end").exec();
    println!("luajit membomb with limit: ended after {:?}: {:?}", t.elapsed(), r.err().map(|e| e.to_string().lines().next().unwrap_or("").to_string()));
}
