use std::time::{Duration, Instant};
use wasmtime::{Config, Engine, Instance, Module, Store, TypedFunc};
const WAT: &str = r#"
(module
  (memory (export "mem") 16)
  (func $fib (export "fib") (param i32) (result i32)
    (if (result i32) (i32.lt_s (local.get 0) (i32.const 2))
      (then (local.get 0))
      (else (i32.add (call $fib (i32.sub (local.get 0) (i32.const 1))) (call $fib (i32.sub (local.get 0) (i32.const 2)))))))
  (func (export "loop_sum") (param $n i64) (result i64)
    (local $s i64) (local $i i64)
    (block $done (loop $l
      (br_if $done (i64.ge_s (local.get $i) (local.get $n)))
      (local.set $s (i64.add (local.get $s) (i64.rem_s (i64.mul (local.get $i) (i64.const 2)) (i64.const 7))))
      (local.set $i (i64.add (local.get $i) (i64.const 1)))
      (br $l)))
    (local.get $s))
  (func (export "list_sum") (param $n i32) (result i64)
    (local $i i32) (local $s i64) (local $x i64)
    (block $d1 (loop $l1
      (br_if $d1 (i32.ge_s (local.get $i) (local.get $n)))
      (i32.store (i32.mul (local.get $i) (i32.const 4)) (local.get $i))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $l1)))
    (local.set $i (i32.const 0))
    (block $d2 (loop $l2
      (br_if $d2 (i32.ge_s (local.get $i) (local.get $n)))
      (local.set $x (i64.extend_i32_s (i32.load (i32.mul (local.get $i) (i32.const 4)))))
      (if (i64.eqz (i64.rem_s (local.get $x) (i64.const 2)))
        (then (local.set $s (i64.add (local.get $s) (i64.mul (local.get $x) (local.get $x))))))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $l2)))
    (local.get $s))
  (func (export "add") (param i64 i64) (result i64) (i64.add (local.get 0) (local.get 1)))
  (func (export "runaway") (loop $l (br $l)))
)"#;

fn bench(label: &str, config: Config, setup: impl Fn(&mut Store<()>)) {
    let engine = Engine::new(&config).unwrap();
    let wasm = wat::parse_str(WAT).unwrap();
    let tc = Instant::now(); let module = Module::new(&engine, &wasm).unwrap(); let compile = tc.elapsed();
    let mut store = Store::new(&engine, ()); setup(&mut store);
    let inst = Instance::new(&mut store, &module, &[]).unwrap();
    let fib: TypedFunc<i32, i32> = inst.get_typed_func(&mut store, "fib").unwrap();
    let lp: TypedFunc<i64, i64> = inst.get_typed_func(&mut store, "loop_sum").unwrap();
    let ls: TypedFunc<i32, i64> = inst.get_typed_func(&mut store, "list_sum").unwrap();
    let add: TypedFunc<(i64, i64), i64> = inst.get_typed_func(&mut store, "add").unwrap();
    print!("{label:<22}");
    let t = Instant::now(); let r = fib.call(&mut store, 30).unwrap(); assert_eq!(r, 832040); print!(" | fib(30) {:>7.1} ms", t.elapsed().as_secs_f64() * 1000.0);
    let t = Instant::now(); let r = lp.call(&mut store, 10_000_000).unwrap(); assert_eq!(r, 29999997); print!(" | loop 10M {:>7.1} ms", t.elapsed().as_secs_f64() * 1000.0);
    let t = Instant::now(); let r = ls.call(&mut store, 200_000).unwrap(); assert_eq!(r, 1333313333400000); print!(" | list 200k {:>6.1} ms", t.elapsed().as_secs_f64() * 1000.0);
    let t = Instant::now(); for i in 0..200_000i64 { assert_eq!(add.call(&mut store, (i, 1)).unwrap(), i + 1); }
    println!(" | call {:.2} µs/call  (compile {:?})", t.elapsed().as_secs_f64() * 1e6 / 200_000.0, compile);
    // instantiate-per-event cost (fresh sandbox per event)
    let t = Instant::now(); for _ in 0..2000 { let mut s = Store::new(&engine, ()); setup(&mut s); let i = Instance::new(&mut s, &module, &[]).unwrap(); let f: TypedFunc<(i64, i64), i64> = i.get_typed_func(&mut s, "add").unwrap(); f.call(&mut s, (1, 2)).unwrap(); }
    println!("{:<22}   fresh store+instance+1 call: {:.1} µs", "", t.elapsed().as_secs_f64() * 1e6 / 2000.0);
}

fn main() {
    bench("wasmtime (no limits)", Config::new(), |_| {});
    let mut c = Config::new(); c.epoch_interruption(true);
    bench("wasmtime + epoch", c, |s| s.set_epoch_deadline(u64::MAX / 2));
    let mut c = Config::new(); c.consume_fuel(true);
    bench("wasmtime + fuel", c, |s| s.set_fuel(u64::MAX / 2).unwrap());
    // Can we stop a runaway?
    let mut c = Config::new(); c.epoch_interruption(true);
    let engine = Engine::new(&c).unwrap(); let module = Module::new(&engine, &wat::parse_str(WAT).unwrap()).unwrap();
    let mut store = Store::new(&engine, ()); store.set_epoch_deadline(1);
    let e2 = engine.clone(); std::thread::spawn(move || { std::thread::sleep(Duration::from_millis(200)); e2.increment_epoch(); });
    let inst = Instance::new(&mut store, &module, &[]).unwrap(); let f: TypedFunc<(), ()> = inst.get_typed_func(&mut store, "runaway").unwrap();
    let t = Instant::now(); let r = f.call(&mut store, ()); println!("runaway via epoch deadline 200 ms: stopped after {:?}: {:?}", t.elapsed(), r.err().map(|e| e.to_string().lines().next().unwrap_or("").to_string()));
    let mut c = Config::new(); c.consume_fuel(true);
    let engine = Engine::new(&c).unwrap(); let module = Module::new(&engine, &wat::parse_str(WAT).unwrap()).unwrap();
    let mut store = Store::new(&engine, ()); store.set_fuel(100_000_000).unwrap();
    let inst = Instance::new(&mut store, &module, &[]).unwrap(); let f: TypedFunc<(), ()> = inst.get_typed_func(&mut store, "runaway").unwrap();
    let t = Instant::now(); let r = f.call(&mut store, ()); println!("runaway via fuel 100M: stopped after {:?}: {:?}", t.elapsed(), r.err().map(|e| e.to_string().lines().next().unwrap_or("").to_string()));
}
