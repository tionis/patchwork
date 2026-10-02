use std::time::{Duration, Instant};

pub const PUSH_EVENT: &str = "push";
fn body_push() -> String { body_push_n(3) }
fn body_push_n(n: usize) -> String {
    let commits: Vec<serde_json::Value> = (0..n).map(|i| serde_json::json!({
        "id": format!("{:040x}", i + 1), "message": format!("Update page {i}\n\nSome longer commit message text to make the payload realistic."),
        "url": format!("https://forge.example/eric/wiki/commit/{i}"),
        "author": {"name": "Eric", "email": "eric@example.com", "username": "eric"},
        "added": ["a.md"], "removed": [], "modified": ["index.md", "notes/b.md"]
    })).collect();
    serde_json::json!({
        "ref": "refs/heads/main", "before": "0".repeat(40), "after": "f".repeat(40),
        "repository": {"id": 7, "full_name": "eric/wiki", "private": true, "html_url": "https://forge.example/eric/wiki",
            "owner": {"login": "eric", "email": "eric@example.com"}, "description": "My wiki, with a description."},
        "pusher": {"login": "eric", "email": "eric@example.com"}, "sender": {"login": "eric"},
        "commits": commits, "total_commits": n
    }).to_string()
}
fn body_vulcan() -> String { serde_json::json!({"ref":"refs/vulcan/notifications","repository":{"full_name":"eric/wiki"},"commits":[]}).to_string() }
fn expected() -> serde_json::Value { serde_json::json!({"repo":"eric/wiki","ref":"refs/heads/main","n":3}) }

pub trait Num {
    /// Calls a script function with numeric args; Err("n/a") when unsupported.
    fn num(&mut self, name: &str, args: &[f64]) -> Result<f64, String> { let _ = (name, args); Err("n/a".into()) }
}
pub trait Engine {
    fn has_json(&self) -> bool { true }
    fn handle(&mut self, event: &str, body: &str) -> Result<String, String>;
    fn core(&mut self, event: &str, git_ref: &str, repo: &str, n: i64) -> Result<String, String>;
}

#[cfg(feature = "qjs")]
mod qjs {
    use super::*;
    use rquickjs::{Context, Function, Runtime};
    const JS: &str = r#"
function handle(event, bodyJson) {
  const b = JSON.parse(bodyJson);
  if (!["push","create","delete"].includes(event) || b.ref.startsWith("refs/vulcan/")) return "";
  return JSON.stringify({repo: b.repository.full_name, ref: b.ref, n: b.commits.length});
}
function core(event, ref, repo, n) {
  if (!["push","create","delete"].includes(event) || ref.startsWith("refs/vulcan/")) return "";
  return repo + "|" + ref + "|" + n;
}
function fib(n){ return n < 2 ? n : fib(n-1) + fib(n-2); }
function loop_sum(n){ let s = 0; for (let i = 0; i < n; i++) { s += (i*2) % 7; } return s; }
function list_sum(n){ const a = []; for (let i = 0; i < n; i++) a.push(i); return a.filter(x => x % 2 === 0).map(x => x*x).reduce((p, c) => p + c, 0); }
function add(a, b){ return a + b; }
"#;
    pub struct E { pub rt: Runtime, pub ctx: Context }
    pub fn new() -> E {
        let rt = Runtime::new().unwrap();
        if std::env::var_os("LIMITS").is_some() {
            // Production shape: hard memory cap + wall-clock interrupt handler always installed.
            rt.set_memory_limit(64 << 20); rt.set_max_stack_size(512 << 10);
            let deadline = Instant::now() + Duration::from_secs(3600);
            rt.set_interrupt_handler(Some(Box::new(move || Instant::now() > deadline)));
        }
        let ctx = Context::full(&rt).unwrap(); ctx.with(|c| c.eval::<(), _>(JS).unwrap()); E { rt, ctx }
    }
    impl Engine for E {
        fn handle(&mut self, event: &str, body: &str) -> Result<String, String> {
            self.ctx.with(|c| { let f: Function = c.globals().get("handle").unwrap(); f.call::<_, String>((event, body)).map_err(|e| e.to_string()) })
        }
        fn core(&mut self, event: &str, r: &str, repo: &str, n: i64) -> Result<String, String> {
            self.ctx.with(|c| { let f: Function = c.globals().get("core").unwrap(); f.call::<_, String>((event, r, repo, n)).map_err(|e| e.to_string()) })
        }
    }
    impl Num for E {
        fn num(&mut self, name: &str, a: &[f64]) -> Result<f64, String> {
            self.ctx.with(|c| { let f: Function = c.globals().get(name).map_err(|e| e.to_string())?;
                match a.len() { 1 => f.call::<_, f64>((a[0],)), _ => f.call::<_, f64>((a[0], a[1])) }.map_err(|e| e.to_string()) })
        }
    }
    /// Isolation like the Starlark frozen shape: one Runtime (with limits), fresh Context + re-eval of the script per event.
    pub fn fresh_ctx() -> String {
        let rt = Runtime::new().unwrap(); rt.set_memory_limit(64 << 20); rt.set_max_stack_size(512 << 10);
        let deadline = Instant::now() + Duration::from_secs(3600);
        rt.set_interrupt_handler(Some(Box::new(move || Instant::now() > deadline)));
        let push = body_push(); let vulcan = body_vulcan(); let big = body_push_n(100);
        let mut out = String::new();
        for (label, body, iters) in [("push 1.4KB", &push, 20_000usize), ("vulcan drop", &vulcan, 20_000), ("push 100 commits (~37KB)", &big, 2_000)] {
            let go = || { let ctx = Context::full(&rt).unwrap(); ctx.with(|c| { c.eval::<(), _>(JS).unwrap(); let f: Function = c.globals().get("handle").unwrap(); f.call::<_, String>((PUSH_EVENT, body.as_str())).unwrap() }) };
            if label == "push 1.4KB" { assert_eq!(serde_json::from_str::<serde_json::Value>(&go()).unwrap(), expected()); }
            for _ in 0..200 { go(); }
            let mut s = Vec::with_capacity(iters);
            for _ in 0..iters { let t = Instant::now(); go(); s.push(t.elapsed().as_nanos() as f64 / 1000.0); }
            s.sort_by(|a, b| a.partial_cmp(b).unwrap());
            out += &format!("  fresh ctx+eval {label:<26} mean {:>8.2} µs p50 {:>8.2} p99 {:>8.2}\n", s.iter().sum::<f64>() / s.len() as f64, s[s.len()/2], s[s.len()*99/100]);
        }
        out + format!("  peak RSS {} KB\n", rss_kb()).as_str()
    }
    pub fn runaway(ms: u64) -> String {
        let e = new(); let deadline = Instant::now() + Duration::from_millis(ms);
        e.rt.set_interrupt_handler(Some(Box::new(move || Instant::now() > deadline)));
        let t = Instant::now(); let r = e.ctx.with(|c| c.eval::<(), _>("while(true){}").map_err(|e| e.to_string()));
        format!("stopped after {:?}: {:?}", t.elapsed(), r.err())
    }
    pub fn membomb() -> String {
        let e = new(); e.rt.set_memory_limit(64 << 20);
        let t = Instant::now(); let r = e.ctx.with(|c| c.eval::<(), _>("const a=[]; while(true){a.push(new Array(100000).fill(1))}").map_err(|e| e.to_string()));
        format!("stopped after {:?}: {:?}", t.elapsed(), r.err())
    }
}

#[cfg(feature = "boa")]
mod boa {
    use super::*;
    use boa_engine::{js_string, Context, JsValue, Source, object::JsObject};
    const JS: &str = super::qjs_js::JS;
    pub struct E { pub ctx: Context, handle: JsObject, core: JsObject }
    pub fn new() -> E {
        let mut ctx = Context::default(); ctx.eval(Source::from_bytes(JS)).unwrap();
        let handle = ctx.global_object().get(js_string!("handle"), &mut ctx).unwrap().as_object().unwrap().clone();
        let core = ctx.global_object().get(js_string!("core"), &mut ctx).unwrap().as_object().unwrap().clone();
        E { ctx, handle, core }
    }
    impl Engine for E {
        fn handle(&mut self, event: &str, body: &str) -> Result<String, String> {
            let args = [JsValue::from(js_string!(event)), JsValue::from(js_string!(body))];
            let r = self.handle.call(&JsValue::undefined(), &args, &mut self.ctx).map_err(|e| e.to_string())?;
            Ok(r.to_string(&mut self.ctx).map_err(|e| e.to_string())?.to_std_string_escaped())
        }
        fn core(&mut self, event: &str, r: &str, repo: &str, n: i64) -> Result<String, String> {
            let args = [JsValue::from(js_string!(event)), JsValue::from(js_string!(r)), JsValue::from(js_string!(repo)), JsValue::from(n as i32)];
            let r = self.core.call(&JsValue::undefined(), &args, &mut self.ctx).map_err(|e| e.to_string())?;
            Ok(r.to_string(&mut self.ctx).map_err(|e| e.to_string())?.to_std_string_escaped())
        }
    }
    impl Num for E {
        fn num(&mut self, name: &str, a: &[f64]) -> Result<f64, String> {
            let f = self.ctx.global_object().get(js_string!(name), &mut self.ctx).map_err(|e| e.to_string())?;
            let f = f.as_callable().ok_or("not callable")?.clone();
            let args: Vec<JsValue> = a.iter().map(|x| JsValue::from(*x)).collect();
            let r = f.call(&JsValue::undefined(), &args, &mut self.ctx).map_err(|e| e.to_string())?;
            r.to_number(&mut self.ctx).map_err(|e| e.to_string())
        }
    }
    pub fn runaway(_ms: u64) -> String {
        let mut e = new(); e.ctx.runtime_limits_mut().set_loop_iteration_limit(50_000_000);
        let t = Instant::now(); let r = e.ctx.eval(Source::from_bytes("while(true){}")).map(|_| ()).map_err(|e| e.to_string());
        format!("stopped after {:?} (iteration limit 50M, no deadline API): {:?}", t.elapsed(), r.err())
    }
    pub fn membomb() -> String {
        let mut e = new(); e.ctx.runtime_limits_mut().set_loop_iteration_limit(50_000_000);
        let t = Instant::now(); let r = e.ctx.eval(Source::from_bytes("const a=[]; while(true){a.push(new Array(100000).fill(1))}")).map(|_| ()).map_err(|e| e.to_string());
        format!("ended after {:?}: {:?} (no memory limit API)", t.elapsed(), r.err())
    }
}
#[cfg(any(feature = "boa"))]
mod qjs_js { pub const JS: &str = r#"
function handle(event, bodyJson) {
  const b = JSON.parse(bodyJson);
  if (!["push","create","delete"].includes(event) || b.ref.startsWith("refs/vulcan/")) return "";
  return JSON.stringify({repo: b.repository.full_name, ref: b.ref, n: b.commits.length});
}
function core(event, ref, repo, n) {
  if (!["push","create","delete"].includes(event) || ref.startsWith("refs/vulcan/")) return "";
  return repo + "|" + ref + "|" + n;
}
function fib(n){ return n < 2 ? n : fib(n-1) + fib(n-2); }
function loop_sum(n){ let s = 0; for (let i = 0; i < n; i++) { s += (i*2) % 7; } return s; }
function list_sum(n){ const a = []; for (let i = 0; i < n; i++) a.push(i); return a.filter(x => x % 2 === 0).map(x => x*x).reduce((p, c) => p + c, 0); }
function add(a, b){ return a + b; }
"#; }

#[cfg(feature = "lua")]
mod lua {
    use super::*;
    use mlua::{Function, HookTriggers, Lua, LuaSerdeExt, VmState};
    const LUA: &str = r#"
local function ok_event(e) return e == "push" or e == "create" or e == "delete" end
function handle(event, body_json)
  local b = json_decode(body_json)
  if not ok_event(event) or string.sub(b.ref, 1, 12) == "refs/vulcan/" then return "" end
  return json_encode({repo = b.repository.full_name, ref = b.ref, n = #b.commits})
end
function core(event, ref, repo, n)
  if not ok_event(event) or string.sub(ref, 1, 12) == "refs/vulcan/" then return "" end
  return repo .. "|" .. ref .. "|" .. n
end
function fib(n) if n < 2 then return n end return fib(n-1) + fib(n-2) end
function loop_sum(n) local s = 0 for i = 0, n-1 do s = s + (i*2) % 7 end return s end
function list_sum(n) local a = {} for i = 1, n do a[i] = i-1 end local s = 0 for _, x in ipairs(a) do if x % 2 == 0 then s = s + x*x end end return s end
function add(a, b) return a + b end"#;
    pub struct E { pub lua: Lua, handle: Function, core: Function }
    pub fn new() -> E {
        let lua = Lua::new();
        lua.globals().set("json_decode", lua.create_function(|lua, s: String| { let v: serde_json::Value = serde_json::from_str(&s).map_err(mlua::Error::external)?; lua.to_value(&v) }).unwrap()).unwrap();
        lua.globals().set("json_encode", lua.create_function(|lua, t: mlua::Value| { let v: serde_json::Value = lua.from_value(t)?; serde_json::to_string(&v).map_err(mlua::Error::external) }).unwrap()).unwrap();
        lua.load(LUA).exec().unwrap();
        let handle: Function = lua.globals().get("handle").unwrap(); let core: Function = lua.globals().get("core").unwrap();
        E { lua, handle, core }
    }
    impl Engine for E {
        fn handle(&mut self, event: &str, body: &str) -> Result<String, String> { self.handle.call::<String>((event, body)).map_err(|e| e.to_string()) }
        fn core(&mut self, event: &str, r: &str, repo: &str, n: i64) -> Result<String, String> { self.core.call::<String>((event, r, repo, n)).map_err(|e| e.to_string()) }
    }
    impl Num for E {
        fn num(&mut self, name: &str, a: &[f64]) -> Result<f64, String> {
            let f: Function = self.lua.globals().get(name).map_err(|e| e.to_string())?;
            match a.len() { 1 => f.call::<f64>(a[0]), _ => f.call::<f64>((a[0], a[1])) }.map_err(|e| e.to_string())
        }
    }
    pub fn runaway(ms: u64) -> String {
        let e = new(); let deadline = Instant::now() + Duration::from_millis(ms);
        e.lua.set_hook(HookTriggers { every_nth_instruction: Some(1000), ..Default::default() }, move |_, _| if Instant::now() > deadline { Err(mlua::Error::runtime("deadline")) } else { Ok(VmState::Continue) }).unwrap();
        let t = Instant::now(); let r = e.lua.load("while true do end").exec().map_err(|e| e.to_string());
        format!("stopped after {:?}: {:?}", t.elapsed(), r.err().map(|s| s.lines().next().unwrap_or("").to_string()))
    }
    pub fn membomb() -> String {
        let e = new(); e.lua.set_memory_limit(64 << 20).unwrap();
        let t = Instant::now(); let r = e.lua.load("local a = {} while true do a[#a+1] = string.rep('x', 100000) end").exec().map_err(|e| e.to_string());
        format!("stopped after {:?}: {:?}", t.elapsed(), r.err().map(|s| s.lines().next().unwrap_or("").to_string()))
    }
}

#[cfg(feature = "cel")]
mod celeng {
    use super::*;
    use cel::{Context, Program, Value};
    pub struct E { handle: Program, core: Program, add: Program }
    pub fn new() -> E {
        E {
            add: Program::compile("a + b").unwrap(),
            handle: Program::compile(r#"!(headers.event in ["push","create","delete"]) || body.ref.startsWith("refs/vulcan/") ? "" : {"repo": body.repository.full_name, "ref": body.ref, "n": size(body.commits)}"#).unwrap(),
            core: Program::compile(r#"!(event in ["push","create","delete"]) || ref.startsWith("refs/vulcan/") ? "" : repo + "|" + ref + "|" + string(n)"#).unwrap(),
        }
    }
    impl Num for E {
        fn num(&mut self, name: &str, a: &[f64]) -> Result<f64, String> {
            if name != "add" { return Err("n/a".into()); }
            let p = Program::compile("a + b").map_err(|e| e.to_string())?; let _ = p;
            let mut ctx = Context::default(); ctx.add_variable("a", a[0] as i64).unwrap(); ctx.add_variable("b", a[1] as i64).unwrap();
            match self.add.execute(&ctx).map_err(|e| e.to_string())? { Value::Int(i) => Ok(i as f64), v => Err(format!("{v:?}")) }
        }
    }
    fn to_json(v: &Value) -> serde_json::Value {
        match v {
            Value::Map(m) => serde_json::Value::Object(m.map.iter().map(|(k, v)| (format!("{k}").trim_matches('"').to_string(), to_json(v))).collect()),
            Value::String(s) => serde_json::Value::String(s.to_string()),
            Value::Int(i) => serde_json::json!(i),
            _ => serde_json::Value::Null,
        }
    }
    impl Engine for E {
        fn handle(&mut self, event: &str, body: &str) -> Result<String, String> {
            let parsed: serde_json::Value = serde_json::from_str(body).map_err(|e| e.to_string())?;
            let mut ctx = Context::default();
            ctx.add_variable("headers", serde_json::json!({"event": event})).map_err(|e| e.to_string())?;
            ctx.add_variable("body", parsed).map_err(|e| e.to_string())?;
            match self.handle.execute(&ctx).map_err(|e| e.to_string())? {
                Value::String(s) => Ok(s.to_string()),
                v => Ok(to_json(&v).to_string()),
            }
        }
        fn core(&mut self, event: &str, r: &str, repo: &str, n: i64) -> Result<String, String> {
            let mut ctx = Context::default();
            ctx.add_variable("event", event).map_err(|e| e.to_string())?; ctx.add_variable("ref", r).map_err(|e| e.to_string())?;
            ctx.add_variable("repo", repo).map_err(|e| e.to_string())?; ctx.add_variable("n", n).map_err(|e| e.to_string())?;
            match self.core.execute(&ctx).map_err(|e| e.to_string())? { Value::String(s) => Ok(s.to_string()), v => Ok(format!("{v:?}")) }
        }
    }
}


#[cfg(feature = "rune")]
mod runeeng {
    use super::*;
    use rune::runtime::budget;
    use rune::{Context, Source, Sources, Unit, Vm};
    use std::sync::Arc;
    const SRC: &str = r#"
fn ok_event(e) { e == "push" || e == "create" || e == "delete" }
pub fn handle(event, body_json) {
    let b = json::from_string(body_json).unwrap();
    if !ok_event(event) || b["ref"].starts_with("refs/vulcan/") { return String::new(); }
    json::to_string(#{"repo": b["repository"]["full_name"], "ref": b["ref"], "n": b["commits"].len()}).unwrap()
}
pub fn core(event, git_ref, repo, n) {
    if !ok_event(event) || git_ref.starts_with("refs/vulcan/") { return String::new(); }
    format!("{}|{}|{}", repo, git_ref, n)
}
pub fn fib(n) { if n < 2 { n } else { fib(n - 1) + fib(n - 2) } }
pub fn loop_sum(n) { let s = 0; for i in 0..n { s += (i * 2) % 7; } s }
pub fn list_sum(n) { let a = Vec::new(); for i in 0..n { a.push(i); } let s = 0; for x in a { if x % 2 == 0 { s += x * x; } } s }
pub fn add(a, b) { a + b }
pub fn runaway() { loop {} }
pub fn membomb() { let a = Vec::new(); loop { a.push(String::from("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")); } }
"#;
    pub struct E { vm: Vm }
    pub fn new() -> E {
        let mut context = Context::with_default_modules().unwrap();
        context.install(rune_modules::json::module(true).unwrap()).unwrap();
        let runtime = Arc::new(context.runtime().unwrap());
        let mut sources = Sources::new(); sources.insert(Source::memory(SRC).unwrap()).unwrap();
        let unit: Unit = rune::prepare(&mut sources).with_context(&context).build().unwrap();
        E { vm: Vm::new(runtime, Arc::new(unit)) }
    }
    impl Engine for E {
        fn handle(&mut self, event: &str, body: &str) -> Result<String, String> {
            let v = self.vm.call(["handle"], (event.to_owned(), body.to_owned())).map_err(|e| e.to_string())?;
            rune::from_value::<String>(v).map_err(|e| e.to_string())
        }
        fn core(&mut self, event: &str, r: &str, repo: &str, n: i64) -> Result<String, String> {
            let v = self.vm.call(["core"], (event.to_owned(), r.to_owned(), repo.to_owned(), n)).map_err(|e| e.to_string())?;
            rune::from_value::<String>(v).map_err(|e| e.to_string())
        }
    }
    impl Num for E {
        fn num(&mut self, name: &str, a: &[f64]) -> Result<f64, String> {
            let v = match a.len() { 1 => self.vm.call([name], (a[0] as i64,)), _ => self.vm.call([name], (a[0] as i64, a[1] as i64)) }.map_err(|e| e.to_string())?;
            rune::from_value::<i64>(v).map(|i| i as f64).map_err(|e| e.to_string())
        }
    }
    pub fn runaway() -> String {
        let mut e = new(); let t = Instant::now();
        let r = budget::with(5_000_000, || e.vm.call(["runaway"], ())).call();
        format!("stopped after {:?}: {:?}", t.elapsed(), r.err().map(|e| e.to_string()))
    }
    pub fn membomb() -> String {
        let mut e = new(); let t = Instant::now();
        let r = rune::alloc::limit::with(64 << 20, || budget::with(500_000_000, || e.vm.call(["membomb"], ())).call()).call();
        format!("stopped after {:?}: {:?}", t.elapsed(), r.err().map(|e| e.to_string()))
    }
}

#[cfg(feature = "star")]
mod star {
    use super::*;
    use starlark::environment::{GlobalsBuilder, LibraryExtension, Module};
    use starlark::eval::Evaluator;
    use starlark::syntax::{AstModule, Dialect};
    use starlark::values::Value;
    const SRC: &str = r#"
def ok_event(e):
    return e == "push" or e == "create" or e == "delete"
def handle(event, body_json):
    b = json.decode(body_json)
    if not ok_event(event) or b["ref"].startswith("refs/vulcan/"):
        return ""
    return json.encode({"repo": b["repository"]["full_name"], "ref": b["ref"], "n": len(b["commits"])})
def core(event, ref, repo, n):
    if not ok_event(event) or ref.startswith("refs/vulcan/"):
        return ""
    return repo + "|" + ref + "|" + str(n)
def fib(n):
    if n < 2:
        return n
    return fib(n-1) + fib(n-2)
def loop_sum(n):
    s = 0
    for i in range(n):
        s += (i*2) % 7
    return s
def list_sum(n):
    a = list(range(n))
    s = 0
    for x in a:
        if x % 2 == 0:
            s += x*x
    return s
def add(a, b):
    return a + b
def runaway():
    for i in range(1000000000):
        pass
def membomb():
    a = []
    for i in range(100000000):
        a.append("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" + str(i))
"#;
    pub struct E { ast: AstModule, globals: starlark::environment::Globals }
    pub fn new() -> E {
        let globals = GlobalsBuilder::extended_by(&[LibraryExtension::Json]).build();
        let ast = AstModule::parse("pipeline.star", SRC.to_owned(), &Dialect::Standard).unwrap();
        E { ast, globals }
    }
    enum Arg<'a> { S(&'a str), I(i32) }
    impl Num for E {
        fn num(&mut self, name: &str, a: &[f64]) -> Result<f64, String> {
            let args: Vec<Arg> = a.iter().map(|x| Arg::I(*x as i32)).collect();
            self.call(name, &args, None).and_then(|s| s.parse::<f64>().map_err(|e| e.to_string()))
        }
    }
    impl E {
        // Fresh heap per call (no state leaks between events): re-evaluate the module, then call the function.
        fn call(&self, name: &str, args: &[Arg], limits: Option<(u64, usize)>) -> Result<String, String> {
            let ast = self.ast.clone();
            Module::with_temp_heap(|module| {
                let mut eval = Evaluator::new(&module);
                if let Some((ticks, heap_max)) = limits { eval.set_max_tick_count(ticks).map_err(|e| e.to_string())?; eval.set_max_heap_size(heap_max).map_err(|e| e.to_string())?; }
                eval.eval_module(ast, &self.globals).map_err(|e| e.to_string())?;
                let f = module.get(name).ok_or("no such function")?;
                let heap = module.heap();
                let values: Vec<Value> = args.iter().map(|a| match a { Arg::S(s) => heap.alloc(*s), Arg::I(i) => heap.alloc(*i) }).collect();
                let r = eval.eval_function(f, &values, &[]).map_err(|e| e.to_string())?;
                Ok(r.to_str())
            })
        }
    }
    impl Engine for E {
        fn handle(&mut self, event: &str, body: &str) -> Result<String, String> { self.call("handle", &[Arg::S(event), Arg::S(body)], None) }
        fn core(&mut self, event: &str, r: &str, repo: &str, n: i64) -> Result<String, String> { self.call("core", &[Arg::S(event), Arg::S(r), Arg::S(repo), Arg::I(n as i32)], None) }
    }
    /// Reuses one module and heap for many calls (the realistic hot-path shape).
    pub fn call_reuse() -> String {
        let e = new();
        Module::with_temp_heap(|module| {
            let mut eval = Evaluator::new(&module);
            eval.eval_module(e.ast.clone(), &e.globals).unwrap();
            let f = module.get("add").unwrap(); let heap = module.heap();
            let t = Instant::now();
            for i in 0..200_000 { let r = eval.eval_function(f, &[heap.alloc(i as i32), heap.alloc(1)], &[]).unwrap(); assert_eq!(r.to_str(), (i + 1).to_string()); }
            let per_call = t.elapsed().as_secs_f64() * 1e6 / 200_000.0;
            let f = module.get("fib").unwrap(); let t = Instant::now(); let _ = eval.eval_function(f, &[heap.alloc(30)], &[]).unwrap();
            format!("starlark reused heap: {per_call:.2} µs/call; fib(30) {:.1} ms", t.elapsed().as_secs_f64() * 1000.0)
        })
    }
    /// Realistic shape: evaluate the module once, then call `handle` per event on the same heap.
    /// Also a frozen-module variant: freeze after load, then per event create a fresh small Module heap and call the frozen function.
    pub fn handle_reuse() -> String {
        let e = new(); let push = body_push(); let vulcan = body_vulcan(); let big = body_push_n(100);
        let mut out = String::new();
        // (a) one evaluator/heap for all events (memory grows until GC; starlark GCs the module heap during eval)
        Module::with_temp_heap(|module| {
            let mut eval = Evaluator::new(&module);
            eval.eval_module(e.ast.clone(), &e.globals).unwrap();
            let f = module.get("handle").unwrap(); let heap = module.heap();
            macro_rules! go { ($body:expr) => {{ let r = eval.eval_function(f, &[heap.alloc(PUSH_EVENT), heap.alloc($body.as_str())], &[]).unwrap(); r.to_str() }} }
            assert_eq!(serde_json::from_str::<serde_json::Value>(&go!(push)).unwrap(), expected());
            for (label, body, iters) in [("push 1.4KB", &push, 20_000usize), ("vulcan drop", &vulcan, 20_000), ("push 100 commits (~37KB)", &big, 2_000)] {
                for _ in 0..200 { go!(body); }
                let mut s = Vec::with_capacity(iters);
                for _ in 0..iters { let t = Instant::now(); go!(body); s.push(t.elapsed().as_nanos() as f64 / 1000.0); }
                s.sort_by(|a, b| a.partial_cmp(b).unwrap());
                out += &format!("  shared heap  {label:<26} mean {:>8.2} µs p50 {:>8.2} p99 {:>8.2}\n", s.iter().sum::<f64>() / s.len() as f64, s[s.len()/2], s[s.len()*99/100]);
            }
            out += &format!("  shared heap after {} calls: allocated {} bytes, peak RSS {} KB\n", 42_200, heap.allocated_bytes(), rss_kb());
        });
        // (b) frozen module once; per event: fresh Module heap + Evaluator with limits, call frozen fn (no cross-event state, cheap)
        let frozen = Module::with_temp_heap(|module| { { let mut eval = Evaluator::new(&module); eval.eval_module(e.ast.clone(), &e.globals).unwrap(); } module.freeze().unwrap() });
        let f = frozen.get("handle").unwrap(); let huge = body_push_n(1000);
        for (label, body, iters) in [("push 1.4KB", &push, 20_000usize), ("vulcan drop", &vulcan, 20_000), ("push 100 commits (~37KB)", &big, 2_000), ("push 1000 commits (~370KB)", &huge, 200)] {
            let go = || Module::with_temp_heap(|m| { let out: String; { let mut eval = Evaluator::new(&m); eval.set_max_tick_count(10_000_000).unwrap(); eval.set_max_heap_size(64 << 20).unwrap();
                let h = m.heap(); let fv = h.access_owned_frozen_value(&f); let r = eval.eval_function(fv, &[h.alloc(PUSH_EVENT), h.alloc(body.as_str())], &[]).unwrap(); out = r.to_str(); } out });
            if label == "push 1.4KB" { assert_eq!(serde_json::from_str::<serde_json::Value>(&go()).unwrap(), expected()); }
            for _ in 0..200 { go(); }
            let mut s = Vec::with_capacity(iters);
            for _ in 0..iters { let t = Instant::now(); go(); s.push(t.elapsed().as_nanos() as f64 / 1000.0); }
            s.sort_by(|a, b| a.partial_cmp(b).unwrap());
            out += &format!("  frozen+fresh {label:<26} mean {:>8.2} µs p50 {:>8.2} p99 {:>8.2}\n", s.iter().sum::<f64>() / s.len() as f64, s[s.len()/2], s[s.len()*99/100]);
        }
        out
    }
    pub fn runaway() -> String { let e = new(); let t = Instant::now(); let r = e.call("runaway", &[], Some((50_000_000, 64 << 20))); format!("stopped after {:?}: {:?}", t.elapsed(), r.err().map(|s| s.lines().next().unwrap_or("").to_string())) }
    pub fn membomb() -> String { let e = new(); let t = Instant::now(); let r = e.call("membomb", &[], Some((u64::MAX / 2, 64 << 20))); format!("stopped after {:?}: {:?}", t.elapsed(), r.err().map(|s| s.lines().next().unwrap_or("").to_string())) }
}

#[cfg(feature = "rhai")]
mod rhaieng {
    use super::*;
    use rhai::{AST, Dynamic, Engine as Rhai, Scope};
    const SRC: &str = r#"
fn ok_event(e) { e == "push" || e == "create" || e == "delete" }
fn handle(event, body_json) {
    let b = parse_json(body_json);
    if !ok_event(event) || b["ref"].starts_with("refs/vulcan/") { return ""; }
    to_json(#{repo: b.repository.full_name, ref: b["ref"], n: b.commits.len()})
}
fn core(event, git_ref, repo, n) {
    if !ok_event(event) || git_ref.starts_with("refs/vulcan/") { return ""; }
    repo + "|" + git_ref + "|" + n
}
fn fib(n) { if n < 2 { n } else { fib(n - 1) + fib(n - 2) } }
fn loop_sum(n) { let s = 0; for i in 0..n { s += (i * 2) % 7; } s }
fn list_sum(n) { let a = []; for i in 0..n { a.push(i); } let s = 0; for x in a { if x % 2 == 0 { s += x * x; } } s }
fn add(a, b) { a + b }
fn runaway() { loop {} }
fn membomb() { let a = []; loop { a.push("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"); } }
"#;
    pub struct E { pub engine: Rhai, ast: AST }
    pub fn new() -> E {
        let mut engine = Rhai::new();
        // JSON through serde_json on the host side (rhai's `serde` feature maps Value <-> Dynamic).
        engine.register_fn("parse_json", |s: &str| -> Result<Dynamic, Box<rhai::EvalAltResult>> {
            let v: serde_json::Value = serde_json::from_str(s).map_err(|e| e.to_string())?; rhai::serde::to_dynamic(v)
        });
        engine.register_fn("to_json", |d: Dynamic| -> Result<String, Box<rhai::EvalAltResult>> {
            let v: serde_json::Value = rhai::serde::from_dynamic(&d)?; Ok(v.to_string())
        });
        let ast = engine.compile(SRC).unwrap();
        E { engine, ast }
    }
    impl Engine for E {
        fn handle(&mut self, event: &str, body: &str) -> Result<String, String> {
            let mut scope = Scope::new();
            self.engine.call_fn::<String>(&mut scope, &self.ast, "handle", (event.to_owned(), body.to_owned())).map_err(|e| e.to_string())
        }
        fn core(&mut self, event: &str, r: &str, repo: &str, n: i64) -> Result<String, String> {
            let mut scope = Scope::new();
            self.engine.call_fn::<String>(&mut scope, &self.ast, "core", (event.to_owned(), r.to_owned(), repo.to_owned(), n)).map_err(|e| e.to_string())
        }
    }
    impl Num for E {
        fn num(&mut self, name: &str, a: &[f64]) -> Result<f64, String> {
            let mut scope = Scope::new();
            let v = match a.len() { 1 => self.engine.call_fn::<i64>(&mut scope, &self.ast, name, (a[0] as i64,)), _ => self.engine.call_fn::<i64>(&mut scope, &self.ast, name, (a[0] as i64, a[1] as i64)) };
            v.map(|i| i as f64).map_err(|e| e.to_string())
        }
    }
    pub fn runaway(ms: u64) -> String {
        let mut e = new(); let deadline = Instant::now() + Duration::from_millis(ms);
        e.engine.on_progress(move |_ops| if Instant::now() > deadline { Some("deadline".into()) } else { None });
        let t = Instant::now(); let r = e.engine.call_fn::<()>(&mut Scope::new(), &e.ast, "runaway", ());
        format!("stopped after {:?}: {:?}", t.elapsed(), r.err().map(|e| e.to_string()))
    }
    pub fn membomb() -> String {
        let mut e = new(); e.engine.set_max_array_size(100_000); e.engine.set_max_map_size(100_000); e.engine.set_max_string_size(1 << 20);
        let deadline = Instant::now() + Duration::from_secs(10);
        e.engine.on_progress(move |_ops| if Instant::now() > deadline { Some("deadline".into()) } else { None });
        let t = Instant::now(); let r = e.engine.call_fn::<()>(&mut Scope::new(), &e.ast, "membomb", ());
        format!("stopped after {:?}: {:?} (size limits, not a byte cap); peak RSS {} KB", t.elapsed(), r.err().map(|e| e.to_string()), rss_kb())
    }
}

#[cfg(feature = "steel")]
mod steeleng {
    use super::*;
    use steel::steel_vm::engine::Engine as Steel;
    use steel::rvals::SteelVal;
    use std::sync::{atomic::{AtomicBool, Ordering}, Arc};
    const SRC: &str = r#"
(require-builtin steel/json)
(define (ok-event? e) (or (equal? e "push") (equal? e "create") (equal? e "delete")))
(define (handle event body-json)
  (let ((b (string->jsexpr body-json)))
    (if (or (not (ok-event? event)) (starts-with? (hash-ref b 'ref) "refs/vulcan/"))
        ""
        (value->jsexpr-string (hash 'repo (hash-ref (hash-ref b 'repository) 'full_name) 'ref (hash-ref b 'ref) 'n (length (hash-ref b 'commits)))))))
(define (core event ref repo n)
  (if (or (not (ok-event? event)) (starts-with? ref "refs/vulcan/"))
      ""
      (string-append repo "|" ref "|" (number->string n))))
(define (fib n) (if (< n 2) n (+ (fib (- n 1)) (fib (- n 2)))))
(define (loop_sum n) (let loop ((i 0) (s 0)) (if (= i n) s (loop (+ i 1) (+ s (modulo (* i 2) 7))))))
(define (list_sum n) (foldl + 0 (map (lambda (x) (* x x)) (filter even? (range 0 n)))))
(define (add a b) (+ a b))
(define (runaway) (let loop () (loop)))
(define (membomb) (let loop ((acc '())) (loop (cons (make-string 100000 #\x) acc))))
"#;
    pub struct E { pub vm: Steel }
    pub fn new() -> E { let mut vm = Steel::new(); vm.run(SRC.to_string()).unwrap(); E { vm } }
    fn text(v: SteelVal) -> Result<String, String> { match v { SteelVal::StringV(s) => Ok(s.to_string()), other => Err(format!("{other:?}")) } }
    impl Engine for E {
        fn handle(&mut self, event: &str, body: &str) -> Result<String, String> {
            text(self.vm.call_function_by_name_with_args("handle", vec![SteelVal::StringV(event.into()), SteelVal::StringV(body.into())]).map_err(|e| e.to_string())?)
        }
        fn core(&mut self, event: &str, r: &str, repo: &str, n: i64) -> Result<String, String> {
            text(self.vm.call_function_by_name_with_args("core", vec![SteelVal::StringV(event.into()), SteelVal::StringV(r.into()), SteelVal::StringV(repo.into()), SteelVal::IntV(n as isize)]).map_err(|e| e.to_string())?)
        }
    }
    impl Num for E {
        fn num(&mut self, name: &str, a: &[f64]) -> Result<f64, String> {
            let args: Vec<SteelVal> = a.iter().map(|x| SteelVal::IntV(*x as isize)).collect();
            match self.vm.call_function_by_name_with_args(name, args).map_err(|e| e.to_string())? { SteelVal::IntV(i) => Ok(i as f64), SteelVal::NumV(f) => Ok(f), v => Err(format!("{v:?}")) }
        }
    }
    pub fn runaway(ms: u64) -> String {
        let mut e = new(); let flag = Arc::new(AtomicBool::new(false)); e.vm.with_interrupted(flag.clone());
        let f2 = flag.clone(); std::thread::spawn(move || { std::thread::sleep(Duration::from_millis(ms)); f2.store(true, Ordering::SeqCst); });
        let t = Instant::now(); let r = e.vm.call_function_by_name_with_args("runaway", vec![]);
        format!("stopped after {:?}: {:?}", t.elapsed(), r.err().map(|e| e.to_string().lines().next().unwrap_or("").to_string()))
    }
    pub fn membomb() -> String {
        let mut e = new(); let t = Instant::now(); let r = e.vm.call_function_by_name_with_args("membomb", vec![]);
        format!("ended after {:?}: {:?} (no memory limit API)", t.elapsed(), r.err().map(|e| e.to_string()))
    }
}

#[cfg(feature = "wren")]
mod wreneng {
    use super::*;
    use ruwren::{FunctionSignature, VMConfig};
    const SRC_PLACEHOLDER: () = ();
    const SRC: &str = r#"
class Pipe {
  static ok(e) { e == "push" || e == "create" || e == "delete" }
  static core(event, ref, repo, n) {
    if (!ok(event) || ref.startsWith("refs/vulcan/")) return ""
    return "%(repo)|%(ref)|%(n)"
  }
  static fib(n) {
    if (n < 2) return n
    return fib(n - 1) + fib(n - 2)
  }
  static loop_sum(n) {
    var s = 0
    for (i in 0...n) {
      s = s + (i * 2) % 7
    }
    return s
  }
  static list_sum(n) {
    var a = []
    for (i in 0...n) {
      a.add(i)
    }
    var s = 0
    for (x in a) {
      if (x % 2 == 0) s = s + x * x
    }
    return s
  }
  static add(a, b) { a + b }
  static runaway() {
    while (true) {
    }
  }
  static membomb() {
    var a = []
    while (true) { a.add("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx") }
  }
}
"#;
    pub struct E { vm: ruwren::VMWrapper }
    pub fn new() -> E { let vm = VMConfig::new().build(); vm.interpret("main", SRC).unwrap(); E { vm } }
    impl Engine for E {
        fn has_json(&self) -> bool { false }
        fn handle(&mut self, _: &str, _: &str) -> Result<String, String> { Err("no JSON".into()) }
        fn core(&mut self, event: &str, r: &str, repo: &str, n: i64) -> Result<String, String> {
            self.vm.execute(|vm| { vm.ensure_slots(5); vm.get_variable("main", "Pipe", 0); vm.set_slot_string(1, event); vm.set_slot_string(2, r); vm.set_slot_string(3, repo); vm.set_slot_double(4, n as f64); });
            self.vm.call(FunctionSignature::new_function("core", 4)).map_err(|e| format!("{e:?}"))?;
            Ok(self.vm.execute(|vm| vm.get_slot_string(0)).unwrap_or_default())
        }
    }
    impl Num for E {
        fn num(&mut self, name: &str, a: &[f64]) -> Result<f64, String> {
            self.vm.execute(|vm| { vm.ensure_slots(3); vm.get_variable("main", "Pipe", 0); for (i, x) in a.iter().enumerate() { vm.set_slot_double(i + 1, *x); } });
            self.vm.call(FunctionSignature::new_function(name, a.len())).map_err(|e| format!("{e:?}"))?;
            Ok(self.vm.execute(|vm| vm.get_slot_double(0)).ok_or("no number")?)
        }
    }
    pub fn runaway() -> String {
        let e = new(); e.vm.execute(|vm| { vm.ensure_slots(1); vm.get_variable("main", "Pipe", 0); });
        let t = Instant::now(); let r = e.vm.call(FunctionSignature::new_function("runaway", 0));
        format!("ended after {:?}: {:?}", t.elapsed(), r.err().map(|e| format!("{e:?}")))
    }
    pub fn membomb() -> String {
        let e = new(); e.vm.execute(|vm| { vm.ensure_slots(1); vm.get_variable("main", "Pipe", 0); });
        let t = Instant::now(); let r = e.vm.call(FunctionSignature::new_function("membomb", 0));
        format!("ended after {:?}: {:?}", t.elapsed(), r.err().map(|e| format!("{e:?}")))
    }
}

fn stats(name: &str, iters: usize, mut f: impl FnMut()) {
    for _ in 0..iters.min(200) { f(); }
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters { let t = Instant::now(); f(); samples.push(t.elapsed().as_nanos() as f64 / 1000.0); }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mean = samples.iter().sum::<f64>() / samples.len() as f64;
    println!("  {name:<28} mean {mean:>9.2} µs  p50 {:>9.2}  p99 {:>9.2}  (n={iters})", samples[samples.len() / 2], samples[samples.len() * 99 / 100]);
}
fn rss_kb() -> u64 { std::fs::read_to_string("/proc/self/status").unwrap().lines().find(|l| l.starts_with("VmHWM")).and_then(|l| l.split_whitespace().nth(1)).and_then(|v| v.parse().ok()).unwrap_or(0) }

fn perf<E: Engine>(name: &str, make: impl Fn() -> E) {
    let push = body_push(); let vulcan = body_vulcan();
    let mut e = make();
    if e.has_json() {
        let out = e.handle(PUSH_EVENT, &push).expect("handle push");
        let got: serde_json::Value = serde_json::from_str(&out).unwrap_or(serde_json::Value::String(out.clone()));
        assert_eq!(got, expected(), "{name}: wrong output {out}");
        assert_eq!(e.handle(PUSH_EVENT, &vulcan).unwrap(), "", "{name}: vulcan ref must be dropped");
    }
    assert_eq!(e.core(PUSH_EVENT, "refs/vulcan/x", "eric/wiki", 3).unwrap(), "", "{name}: core drop");
    assert_eq!(e.core(PUSH_EVENT, "refs/heads/main", "eric/wiki", 3).unwrap(), "eric/wiki|refs/heads/main|3");
    println!("{name}: correct on both workloads (payload {} bytes)", push.len());
    let rss0 = rss_kb();
    if e.has_json() {
        stats("cold: new engine + 1 event", 300, || { let mut e = make(); let _ = e.handle(PUSH_EVENT, &push).unwrap(); });
        stats("warm: JSON accept+reshape", 20_000, || { let _ = e.handle(PUSH_EVENT, &push).unwrap(); });
        stats("warm: JSON drop (vulcan ref)", 20_000, || { let _ = e.handle(PUSH_EVENT, &vulcan).unwrap(); });
    } else {
        stats("cold: new engine + 1 core", 300, || { let mut e = make(); let _ = e.core(PUSH_EVENT, "refs/heads/main", "eric/wiki", 3).unwrap(); });
        println!("  (no JSON support in the language: JSON rows skipped)");
    }
    stats("warm: core, no JSON", 50_000, || { let _ = e.core(PUSH_EVENT, "refs/heads/main", "eric/wiki", 3).unwrap(); });
    println!("  peak RSS {} KB (before {} KB)", rss_kb(), rss0);
}


fn scale<E: Engine>(name: &str, make: impl Fn() -> E) {
    let mut e = make();
    if !e.has_json() { println!("{name}: no JSON, skipped"); return; }
    print!("{name:<16}");
    for n in [3usize, 100, 1000, 5000] {
        let body = body_push_n(n);
        let iters = if n >= 1000 { 20 } else { 400 };
        let _ = e.handle(PUSH_EVENT, &body).unwrap();
        let mut samples = Vec::new();
        for _ in 0..iters { let t = Instant::now(); let out = e.handle(PUSH_EVENT, &body).unwrap(); samples.push(t.elapsed().as_micros() as f64); assert!(!out.is_empty()); }
        samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
        print!(" | {:>6} KB {:>9.0} µs", body.len() / 1024, samples[samples.len() / 2]);
    }
    println!();
}
fn mem<E: Engine>(name: &str, count: usize, make: impl Fn() -> E) {
    let push = body_push();
    let before = rss_kb();
    let mut v: Vec<E> = Vec::new();
    let t = Instant::now();
    for _ in 0..count { let mut e = make(); if e.has_json() { let _ = e.handle(PUSH_EVENT, &push).unwrap(); } else { let _ = e.core(PUSH_EVENT, "refs/heads/main", "eric/wiki", 3).unwrap(); } v.push(e); }
    let after = rss_kb();
    println!("{name:<16} {count} warm instances: +{} KB total, ~{} KB each, created in {:?}", after - before, (after - before) / count as u64, t.elapsed());
}

fn compute<E: Engine + Num>(name: &str, make: impl Fn() -> E) {
    let mut e = make();
    let expect_fib = 832040.0; let n_loop = 10_000_000.0; let n_list = 200_000.0;
    let expect_loop: f64 = (0..10_000_000u64).map(|i| ((i * 2) % 7) as f64).sum();
    let expect_list: f64 = (0..200_000u64).filter(|x| x % 2 == 0).map(|x| (x * x) as f64).sum();
    print!("{name:<16}");
    let mut run = |label: &str, f: &mut dyn FnMut() -> Result<f64, String>, expect: f64| {
        let t = Instant::now();
        match f() {
            Ok(v) if (v - expect).abs() < 1.0 => print!(" | {label} {:>8.1} ms", t.elapsed().as_secs_f64() * 1000.0),
            Ok(v) => print!(" | {label} WRONG({v})"),
            Err(m) => print!(" | {label} {m}"),
        }
    };
    run("fib(30)", &mut || e.num("fib", &[30.0]), expect_fib);
    run("loop 10M", &mut || e.num("loop_sum", &[n_loop]), expect_loop);
    run("list 200k", &mut || e.num("list_sum", &[n_list]), expect_list);
    // host->script call overhead: 200k calls to add(a, b)
    let t = Instant::now(); let mut ok = true;
    for i in 0..200_000 { match e.num("add", &[i as f64, 1.0]) { Ok(v) if v == i as f64 + 1.0 => {}, _ => { ok = false; break; } } }
    if ok { let el = t.elapsed(); print!(" | call {:>6.2} µs/call", el.as_secs_f64() * 1e6 / 200_000.0); } else { print!(" | call n/a"); }
    println!();
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (engine, mode) = (args[1].as_str(), args.get(2).map(String::as_str).unwrap_or("perf"));
    match (engine, mode) {
        #[cfg(feature = "qjs")] ("qjs", "scale") => scale("quickjs", qjs::new),
        #[cfg(feature = "qjs")] ("qjs", "mem") => mem("quickjs", 300, qjs::new),
        #[cfg(feature = "qjs")] ("qjs", "compute") => compute("quickjs", qjs::new),
        #[cfg(feature = "qjs")] ("qjs", "perf") => perf("quickjs", qjs::new),
        #[cfg(feature = "qjs")] ("qjs", "fresh") => print!("{}", qjs::fresh_ctx()),
        #[cfg(feature = "qjs")] ("qjs", "runaway") => println!("quickjs runaway: {}", qjs::runaway(200)),
        #[cfg(feature = "qjs")] ("qjs", "membomb") => println!("quickjs membomb: {}", qjs::membomb()),
        #[cfg(feature = "boa")] ("boa", "scale") => scale("boa", boa::new),
        #[cfg(feature = "boa")] ("boa", "mem") => mem("boa", 300, boa::new),
        #[cfg(feature = "boa")] ("boa", "compute") => compute("boa", boa::new),
        #[cfg(feature = "boa")] ("boa", "perf") => perf("boa", boa::new),
        #[cfg(feature = "boa")] ("boa", "runaway") => println!("boa runaway: {}", boa::runaway(200)),
        #[cfg(feature = "boa")] ("boa", "membomb") => println!("boa membomb: {}", boa::membomb()),
        #[cfg(feature = "lua")] ("lua", "scale") => scale("lua 5.4", lua::new),
        #[cfg(feature = "lua")] ("lua", "mem") => mem("lua 5.4", 300, lua::new),
        #[cfg(feature = "lua")] ("lua", "compute") => compute("lua 5.4", lua::new),
        #[cfg(feature = "lua")] ("lua", "perf") => perf("lua 5.4", lua::new),
        #[cfg(feature = "lua")] ("lua", "runaway") => println!("lua runaway: {}", lua::runaway(200)),
        #[cfg(feature = "lua")] ("lua", "membomb") => println!("lua membomb: {}", lua::membomb()),
        #[cfg(feature = "cel")] ("cel", "scale") => scale("cel", celeng::new),
        #[cfg(feature = "cel")] ("cel", "mem") => mem("cel", 300, celeng::new),
        #[cfg(feature = "cel")] ("cel", "compute") => compute("cel", celeng::new),
        #[cfg(feature = "cel")] ("cel", "perf") => perf("cel", celeng::new),
        #[cfg(feature = "rune")] ("rune", "scale") => scale("rune", runeeng::new),
        #[cfg(feature = "rune")] ("rune", "mem") => mem("rune", 100, runeeng::new),
        #[cfg(feature = "rune")] ("rune", "compute") => compute("rune", runeeng::new),
        #[cfg(feature = "rune")] ("rune", "perf") => perf("rune", runeeng::new),
        #[cfg(feature = "rune")] ("rune", "runaway") => println!("rune runaway: {}", runeeng::runaway()),
        #[cfg(feature = "rune")] ("rune", "membomb") => println!("rune membomb: {}", runeeng::membomb()),
        #[cfg(feature = "star")] ("star", "scale") => scale("starlark", star::new),
        #[cfg(feature = "star")] ("star", "mem") => mem("starlark", 300, star::new),
        #[cfg(feature = "star")] ("star", "compute") => compute("starlark", star::new),
        #[cfg(feature = "star")] ("star", "perf") => perf("starlark", star::new),
        #[cfg(feature = "star")] ("star", "call") => println!("{}", star::call_reuse()),
        #[cfg(feature = "star")] ("star", "reuse") => print!("{}", star::handle_reuse()),
        #[cfg(feature = "star")] ("star", "runaway") => println!("starlark runaway: {}", star::runaway()),
        #[cfg(feature = "star")] ("star", "membomb") => println!("starlark membomb: {}", star::membomb()),
        #[cfg(feature = "rhai")] ("rhai", "scale") => scale("rhai", rhaieng::new),
        #[cfg(feature = "rhai")] ("rhai", "mem") => mem("rhai", 300, rhaieng::new),
        #[cfg(feature = "rhai")] ("rhai", "compute") => compute("rhai", rhaieng::new),
        #[cfg(feature = "rhai")] ("rhai", "perf") => perf("rhai", rhaieng::new),
        #[cfg(feature = "rhai")] ("rhai", "runaway") => println!("rhai runaway: {}", rhaieng::runaway(200)),
        #[cfg(feature = "rhai")] ("rhai", "membomb") => println!("rhai membomb: {}", rhaieng::membomb()),
        #[cfg(feature = "steel")] ("steel", "scale") => scale("steel", steeleng::new),
        #[cfg(feature = "steel")] ("steel", "mem") => mem("steel", 12, steeleng::new),
        #[cfg(feature = "steel")] ("steel", "compute") => compute("steel", steeleng::new),
        #[cfg(feature = "steel")] ("steel", "perf") => perf("steel (scheme)", steeleng::new),
        #[cfg(feature = "steel")] ("steel", "runaway") => println!("steel runaway: {}", steeleng::runaway(200)),
        #[cfg(feature = "steel")] ("steel", "membomb") => println!("steel membomb: {}", steeleng::membomb()),
        #[cfg(feature = "wren")] ("wren", "scale") => scale("wren", wreneng::new),
        #[cfg(feature = "wren")] ("wren", "mem") => mem("wren", 300, wreneng::new),
        #[cfg(feature = "wren")] ("wren", "compute") => compute("wren", wreneng::new),
        #[cfg(feature = "wren")] ("wren", "perf") => perf("wren", wreneng::new),
        #[cfg(feature = "wren")] ("wren", "runaway") => println!("wren runaway: {}", wreneng::runaway()),
        #[cfg(feature = "wren")] ("wren", "membomb") => println!("wren membomb: {}", wreneng::membomb()),
        _ => eprintln!("unknown engine/mode"),
    }
}
