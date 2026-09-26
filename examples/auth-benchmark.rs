//! Reproducible local verifier measurements; no server or persistent data.
use biscuit_auth::{
    Biscuit, BlockBuilder, KeyPair,
    builder::{fact, int, string},
};
use patchwork::auth::token::VerifiedToken;
use std::time::{Instant, SystemTime};
fn main() {
    let samples: usize = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "100".into())
        .parse()
        .expect("sample count");
    assert!((10..=10000).contains(&samples));
    let cpu = std::fs::read_to_string("/proc/cpuinfo")
        .unwrap_or_default()
        .lines()
        .find(|line| line.starts_with("model name"))
        .unwrap_or("unknown CPU")
        .to_owned();
    println!(
        "{}",
        serde_json::json!({"cpu":cpu,"arch":std::env::consts::ARCH,"os":std::env::consts::OS,"profile":if cfg!(debug_assertions){"debug"}else{"release"},"samples":samples,"limits":{"bytes":32768,"blocks":8,"facts":1000,"iterations":100,"execution_ms":50}})
    );
    let root = KeyPair::new();
    for blocks in [1, 8, 32] {
        for facts in [10, 100, 1000] {
            let mut builder = Biscuit::builder()
                .fact(fact("principal", &[string("alice")]))
                .unwrap()
                .fact(fact("credential", &[string("benchmark")]))
                .unwrap()
                .fact(fact("issued_instance", &[string("instance")]))
                .unwrap();
            for n in (0..facts).step_by(blocks) {
                builder = builder.fact(fact("bench", &[int(n as i64)])).unwrap();
            }
            let mut token = builder
                .code("check if bench($n), $n >= 0;")
                .unwrap()
                .build(&root)
                .unwrap();
            for b in 1..blocks {
                let mut block = BlockBuilder::new();
                for n in (b..facts).step_by(blocks) {
                    block = block.fact(fact("bench", &[int(n as i64)])).unwrap();
                }
                let block = block.code("check if bench($n), $n >= 0;").unwrap();
                token = token.append(block).unwrap();
            }
            let encoded = token.to_base64().unwrap();
            let mut elapsed = Vec::with_capacity(samples);
            let mut accepted = 0;
            let wall = Instant::now();
            for _ in 0..samples {
                let start = Instant::now();
                let result = VerifiedToken::parse(&encoded, root.public()).and_then(|t| {
                    t.check(
                        "record.read",
                        "stream",
                        "str_fixture",
                        "events/a",
                        "instance",
                        SystemTime::now(),
                    )
                });
                elapsed.push(start.elapsed().as_micros() as u64);
                accepted += usize::from(result.is_ok());
            }
            let duration = wall.elapsed().as_secs_f64();
            elapsed.sort_unstable();
            let quantile = |p: usize| elapsed[((samples * p).div_ceil(100) - 1).min(samples - 1)];
            let rss = std::fs::read_to_string("/proc/self/status")
                .unwrap_or_default()
                .lines()
                .find(|l| l.starts_with("VmHWM:"))
                .unwrap_or("unavailable")
                .to_owned();
            println!(
                "{}",
                serde_json::json!({"blocks":blocks,"extra_facts":facts,"encoded_bytes":encoded.len(),"accepted":accepted,"rejected":samples-accepted,"p50_us":quantile(50),"p95_us":quantile(95),"p99_us":quantile(99),"requests_per_second":samples as f64/duration,"process_cumulative_peak_rss":rss})
            );
        }
    }
}
