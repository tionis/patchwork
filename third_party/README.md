# Third-Party Extension Sources

This directory vendors SQLite extension source trees as git subtrees.

Included trees:

- `cr-sqlite` from `https://github.com/vlcn-io/cr-sqlite`
- `cr-sqlite/core/rs/sqlite-rs-embedded` from `https://github.com/vlcn-io/sqlite-rs-embedded`
- `sqlite-vec` from `https://github.com/asg017/sqlite-vec`
- `sqlean` from `https://github.com/nalgeon/sqlean`

These are source-only imports. Compiled artifacts are built into `build/extensions/` and are not committed.

Sqlean notes:

- `third_party/sqlean/src/crypto/xxhash.impl.h`
- `third_party/sqlean/src/test_windirent.h`

are cached build inputs normally fetched by sqlean's `download-external` target.
They are kept in-tree so `make build-extensions` can run without network access.

## Update Commands

From the repository root:

```bash
git subtree pull --prefix=third_party/cr-sqlite https://github.com/vlcn-io/cr-sqlite.git main --squash
git subtree pull --prefix=third_party/cr-sqlite/core/rs/sqlite-rs-embedded https://github.com/vlcn-io/sqlite-rs-embedded.git main --squash
git subtree pull --prefix=third_party/sqlite-vec https://github.com/asg017/sqlite-vec.git main --squash
git subtree pull --prefix=third_party/sqlean https://github.com/nalgeon/sqlean.git main --squash
```

Prefer release tags or pinned refs for production updates.
