# Patchwork

Patchwork is a Rust, single-node backend for ordered streams, immutable objects, and revisioned references. The service is at bootstrap stage: its server currently exposes health endpoints, while retained stream storage is available only through an internal API. The broader design is specified, not yet implemented.

Start with the [design wiki](docs/index.md), [implementation status](docs/implementation-status.md), [roadmap](docs/roadmap.md), and [developer guide](docs/development.md).

From the repository root:

```sh
cargo build --locked --all-targets
cargo test --locked --all-targets
vulcan --vault docs --output json doctor --fail-on-issues
```

The Rust crate, migrations, and tests live at the repository root. The wiki is initialized with Vulcan; its vault instructions and bundled agent skills are in `docs/AGENTS.md` and `docs/.agents/skills/`.
