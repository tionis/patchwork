// Same workload as script-bench: Forgejo-like push JSON in, filter + reshape, JSON out.
function readAll() {
  const chunks = []; let total = 0;
  while (true) {
    const buf = new Uint8Array(4096);
    const n = Javy.IO.readSync(0, buf);
    if (n === 0) break;
    total += n; chunks.push(buf.subarray(0, n));
  }
  const out = new Uint8Array(total); let off = 0;
  for (const c of chunks) { out.set(c, off); off += c.length; }
  return new TextDecoder().decode(out);
}
function handle(event, b) {
  if (!["push","create","delete"].includes(event) || b.ref.startsWith("refs/vulcan/")) return "";
  return JSON.stringify({repo: b.repository.full_name, ref: b.ref, n: b.commits.length});
}
const input = JSON.parse(readAll());
const result = handle(input.event, input.body);
Javy.IO.writeSync(1, new TextEncoder().encode(result));
