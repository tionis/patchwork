# Runtime benchmarks

Throwaway benchmark crates from the September 2026 evaluation of filter and script runtimes. Results and conclusions are in [the retrospective](../../docs/retrospective.md#filter-and-script-runtimes). Each directory is a standalone Cargo project. They are not part of the Patchwork build and are not maintained.

| Crate | What it measures |
| --- | --- |
| `cel-spike` | CEL (`cel` crate) for accept, validate and transform expressions over a Forgejo push event, plus cost blow-ups |
| `script-bench` | QuickJS, Boa, Lua 5.4, CEL, Rune, Starlark, Steel, Wren and Rhai, each behind a cargo feature: warm per-event filter, compute workloads, runaway and memory limits |
| `jsonnet-bench` | Jsonnet, kept separate because of a dependency conflict with Boa |
| `luajit-bench` | LuaJIT through `mlua`, including whether the instruction hook stops a JIT-compiled loop |
| `wasm-bench` | wasmtime on hand-written WAT, plain, with epoch interruption and with fuel |
| `v8-bench` | V8 through `rusty_v8`, including `terminate_execution` |
| `javy-bench` | QuickJS compiled to WebAssembly with Javy. Needs the `javy` CLI (not committed) to build `js/*.js` into `.wasm` modules |

Run a crate with `cargo run --release` in its directory. Most crates take a mode as their first argument; `main` in each `src/main.rs` lists the modes. For `script-bench`, add `--features <name>` (the names are in its `Cargo.toml`) and set `LIMITS=1` to run the runaway tests.
