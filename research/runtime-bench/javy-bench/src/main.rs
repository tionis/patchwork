//! JS-in-Wasm: a Javy-compiled QuickJS filter run under wasmtime, one fresh instance per event
//! (WASI command pattern: payload on stdin, result on stdout).
use std::time::{Duration, Instant};
use wasmtime::{Config, Engine, Linker, Module, ResourceLimiter, Store, StoreLimits, StoreLimitsBuilder, Strategy, InstanceAllocationStrategy, PoolingAllocationConfig};
use wasmtime_wasi::p1::WasiP1Ctx;
use wasmtime_wasi::p2::pipe::{MemoryInputPipe, MemoryOutputPipe};
use wasmtime_wasi::WasiCtxBuilder;

struct Host { wasi: WasiP1Ctx, limits: StoreLimits }

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
fn input(event: &str, body: &str) -> Vec<u8> {
    format!("{{\"event\":{},\"body\":{}}}", serde_json::to_string(event).unwrap(), body).into_bytes()
}

struct Runner { engine: Engine, module: Module, linker: Linker<Host>, epoch: bool, fuel: bool }

impl Runner {
    fn new(wasm: &[u8], pooling: bool, epoch: bool, fuel: bool) -> Self {
        let mut cfg = Config::new();
        cfg.strategy(Strategy::Cranelift);
        if epoch { cfg.epoch_interruption(true); }
        if fuel { cfg.consume_fuel(true); }
        if pooling {
            let mut p = PoolingAllocationConfig::default();
            p.total_memories(64).total_core_instances(64).total_tables(64).max_memory_size(256 << 20);
            cfg.allocation_strategy(InstanceAllocationStrategy::Pooling(p));
        }
        let engine = Engine::new(&cfg).unwrap();
        let t = Instant::now();
        let module = Module::new(&engine, wasm).unwrap();
        eprintln!("  compiled {} KB module in {:?} (pooling={pooling}, epoch={epoch}, fuel={fuel})", wasm.len() / 1024, t.elapsed());
        let mut linker = Linker::new(&engine);
        wasmtime_wasi::p1::add_to_linker_sync(&mut linker, |h: &mut Host| &mut h.wasi).unwrap();
        Runner { engine, module, linker, epoch, fuel }
    }
    /// One event: fresh store + WASI ctx + instance, run `_start`, collect stdout.
    fn run(&self, stdin: &[u8]) -> Result<String, String> {
        let out = MemoryOutputPipe::new(1 << 20);
        let wasi = WasiCtxBuilder::new().stdin(MemoryInputPipe::new(stdin.to_vec())).stdout(out.clone()).build_p1();
        let limits = StoreLimitsBuilder::new().memory_size(128 << 20).build();
        let mut store = Store::new(&self.engine, Host { wasi, limits });
        store.limiter(|h| &mut h.limits);
        if self.epoch { store.set_epoch_deadline(1); }
        if self.fuel { store.set_fuel(2_000_000_000).unwrap(); }
        let inst = self.linker.instantiate(&mut store, &self.module).map_err(|e| e.to_string())?;
        let start = inst.get_typed_func::<(), ()>(&mut store, "_start").map_err(|e| e.to_string())?;
        start.call(&mut store, ()).map_err(|e| e.to_string().lines().next().unwrap_or("").to_string())?;
        drop(store);
        Ok(String::from_utf8_lossy(&out.contents()).into_owned())
    }
}

fn stats(label: &str, iters: usize, mut f: impl FnMut()) {
    for _ in 0..iters.min(50) { f(); }
    let mut s = Vec::with_capacity(iters);
    for _ in 0..iters { let t = Instant::now(); f(); s.push(t.elapsed().as_nanos() as f64 / 1000.0); }
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    println!("  {label:<44} mean {:>9.1} µs  p50 {:>9.1}  p99 {:>9.1}  (n={iters})", s.iter().sum::<f64>() / s.len() as f64, s[s.len() / 2], s[s.len() * 99 / 100]);
}
fn rss_kb() -> u64 { std::fs::read_to_string("/proc/self/status").unwrap().lines().find(|l| l.starts_with("VmHWM")).and_then(|l| l.split_whitespace().nth(1)).and_then(|v| v.parse().ok()).unwrap_or(0) }

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| ".".into());
    let wasm = std::fs::read(format!("{dir}/filter-static.wasm")).expect("filter-static.wasm");
    let push = body_push_n(3); let big = body_push_n(100); let huge = body_push_n(1000);
    let vulcan = serde_json::json!({"ref":"refs/vulcan/notifications","repository":{"full_name":"eric/wiki"},"commits":[]}).to_string();

    for (pooling, epoch, fuel) in [(false, false, false), (true, false, false), (true, true, false), (true, false, true)] {
        let r = Runner::new(&wasm, pooling, epoch, fuel);
        let out = r.run(&input("push", &push)).unwrap();
        assert_eq!(serde_json::from_str::<serde_json::Value>(&out).unwrap(), serde_json::json!({"repo":"eric/wiki","ref":"refs/heads/main","n":3}), "wrong output: {out}");
        assert_eq!(r.run(&input("push", &vulcan)).unwrap(), "");
        let rss0 = rss_kb();
        stats("fresh instance + push 1.4KB", 2000, || { r.run(&input("push", &push)).unwrap(); });
        stats("fresh instance + vulcan drop", 2000, || { r.run(&input("push", &vulcan)).unwrap(); });
        stats("fresh instance + push 100 commits (~37KB)", 500, || { r.run(&input("push", &big)).unwrap(); });
        stats("fresh instance + push 1000 commits (~370KB)", 100, || { r.run(&input("push", &huge)).unwrap(); });
        println!("  peak RSS {} KB (before {} KB)", rss_kb(), rss0);
    }
    // Cost breakdown: instantiate only (no _start), pooling allocator.
    let r = Runner::new(&wasm, true, false, false);
    stats("instantiate only (store+wasi+instance, no run)", 2000, || {
        let out = MemoryOutputPipe::new(1024);
        let wasi = WasiCtxBuilder::new().stdin(MemoryInputPipe::new(b"{}".to_vec())).stdout(out).build_p1();
        let limits = StoreLimitsBuilder::new().memory_size(128 << 20).build();
        let mut store = Store::new(&r.engine, Host { wasi, limits });
        store.limiter(|h| &mut h.limits);
        let _ = r.linker.instantiate(&mut store, &r.module).unwrap();
    });
    // Serialized (precompiled) module load time, i.e. what a cache hit costs instead of the ~1 s Cranelift compile.
    let ser = r.module.serialize().unwrap();
    let t = Instant::now(); let m2 = unsafe { Module::deserialize(&r.engine, &ser) }.unwrap(); println!("  deserialize precompiled module ({} KB): {:?}", ser.len() / 1024, t.elapsed()); drop(m2);
    // Runaway: a JS infinite loop stopped by the epoch deadline from another thread.
    if let Ok(w) = std::fs::read(format!("{dir}/runaway.wasm")) {
        let rr = Runner::new(&w, true, true, false);
        let eng = rr.engine.clone();
        std::thread::spawn(move || loop { std::thread::sleep(Duration::from_millis(200)); eng.increment_epoch(); });
        let t = Instant::now(); let res = rr.run(b"{}");
        println!("runaway JS-in-wasm via epoch 200 ms: stopped after {:?}: {:?}", t.elapsed(), res.err());
    }
    // Memory bomb with NO epoch: only the 128 MB store memory limit can stop it.
    if let Ok(w) = std::fs::read(format!("{dir}/membomb.wasm")) {
        let rr = Runner::new(&w, true, false, false);
        let rss0 = rss_kb();
        let t = Instant::now(); let res = rr.run(b"{}");
        println!("membomb JS-in-wasm, 128 MB store limit, no epoch: stopped after {:?}: {:?}; RSS {} -> {} KB", t.elapsed(), res.err(), rss0, rss_kb());
    }
}

#[allow(dead_code)]
fn _assert_limiter(_: &mut dyn ResourceLimiter) {}
