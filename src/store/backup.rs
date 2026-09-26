//! Online DB-only backup and verified, exclusive-directory restore.
use super::Store;
use crate::{Error, Result};
use rusqlite::{
    Connection, OpenFlags,
    backup::{Backup, StepResult},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
    time::{Duration, Instant},
};
const DATABASE: &str = "database.sqlite3";
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format: String,
    pub created_at: String,
    pub instance_id: String,
    pub origin: String,
    pub database: String,
    pub sha256: String,
    pub bytes: String,
    pub schema_version: u32,
    pub counts: BTreeMap<String, String>,
}
fn directory(path: &Path) -> Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    Ok(())
}
fn new_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}
fn checksum(path: &Path) -> Result<(String, u64)> {
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut size = 0u64;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
        size = size.checked_add(n as u64).ok_or(Error::Exhausted)?;
    }
    Ok((format!("{:x}", hash.finalize()), size))
}
fn validate(connection: &Connection) -> Result<()> {
    Store::check_format(connection)?;
    let integrity: String = connection.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
    if integrity != "ok" {
        return Err(Error::DatabaseFormat);
    }
    if connection
        .prepare("PRAGMA foreign_key_check")?
        .query([])?
        .next()?
        .is_some()
    {
        return Err(Error::DatabaseFormat);
    }
    for query in [
        "SELECT EXISTS(SELECT 1 FROM streams s WHERE tail-head!=(SELECT count(*) FROM records WHERE stream_id=s.id))",
        "SELECT EXISTS(SELECT 1 FROM records r JOIN streams s ON s.id=r.stream_id WHERE position<s.head OR position>=s.tail)",
        "SELECT EXISTS(SELECT 1 FROM streams s WHERE tail-head!=(SELECT coalesce(sum(record_count),0) FROM segments WHERE stream_id=s.id))",
        "SELECT EXISTS(SELECT 1 FROM streams s WHERE (SELECT coalesce(sum(payload_bytes),0) FROM segments WHERE stream_id=s.id)!=(SELECT coalesce(sum(length(payload)),0) FROM records WHERE stream_id=s.id))",
        "SELECT EXISTS(SELECT 1 FROM kv_attachments a JOIN streams s ON s.id=a.stream_id WHERE a.applied_position!=s.tail)",
        "SELECT EXISTS(SELECT 1 FROM kv_items k JOIN kv_attachments a ON a.id=k.attachment_id WHERE k.revision>=a.applied_position)",
    ] {
        if connection.query_row(query, [], |r| r.get::<_, bool>(0))? {
            return Err(Error::DatabaseFormat);
        }
    }
    // Require this binary's full schema, including data with no current rows.
    connection.prepare("SELECT revision,secret FROM hooks WHERE 0")?;
    connection.prepare("SELECT ceiling,kind,revoked FROM credentials WHERE 0")?;
    Ok(())
}
fn counts(connection: &Connection) -> Result<BTreeMap<String, String>> {
    let mut result = BTreeMap::new();
    for table in [
        "streams",
        "records",
        "segments",
        "principals",
        "credentials",
        "receipts",
        "kv_attachments",
        "kv_items",
        "hooks",
    ] {
        let count: i64 =
            connection.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))?;
        result.insert(table.into(), count.to_string());
    }
    Ok(result)
}
fn identity(connection: &Connection) -> Result<(String, String)> {
    Ok(connection.query_row(
        "SELECT id,origin FROM instance WHERE singleton=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?)
}
impl Store {
    /// Uses an independent CLI connection; other server connections keep writing.
    /// Partial output is intentionally retained without a complete manifest.
    pub fn backup(&self, output: &Path) -> Result<Manifest> {
        if !self.connection.is_autocommit() {
            return Err(Error::Busy);
        }
        self.identity()?;
        directory(output)?;
        let path = output.join(DATABASE);
        new_file(&path)?.sync_all()?;
        let mut destination = Connection::open(&path)?;
        destination.pragma_update(None, "synchronous", "FULL")?;
        let snapshot = self.connection.unchecked_transaction()?;
        snapshot.query_row("SELECT count(*) FROM sqlite_schema", [], |r| {
            r.get::<_, i64>(0)
        })?;
        {
            let backup = Backup::new(&snapshot, &mut destination)?;
            let deadline = Instant::now() + Duration::from_secs(300);
            loop {
                if Instant::now() >= deadline {
                    return Err(Error::Busy);
                }
                match backup.step(128)? {
                    StepResult::Done => break,
                    StepResult::More => std::thread::yield_now(),
                    StepResult::Busy | StepResult::Locked => {
                        std::thread::sleep(Duration::from_millis(10))
                    }
                    _ => return Err(Error::Busy),
                }
            }
        }
        snapshot.commit()?;
        // Produce a standalone database; no untracked WAL is part of the artifact.
        destination.pragma_update(None, "journal_mode", "DELETE")?;
        validate(&destination)?;
        let (instance_id, origin) = identity(&destination)?;
        let counts = counts(&destination)?;
        destination.close().map_err(|(_, e)| Error::Storage(e))?;
        File::open(&path)?.sync_all()?;
        let (sha256, bytes) = checksum(&path)?;
        let manifest = Manifest {
            format: "patchwork/db-backup/v1".into(),
            created_at: super::ingress::timestamp(super::identity::now()?)?,
            instance_id,
            origin,
            database: DATABASE.into(),
            sha256,
            bytes: bytes.to_string(),
            schema_version: 1,
            counts,
        };
        let mut file = new_file(&output.join("manifest.json"))?;
        file.write_all(
            &serde_json::to_vec_pretty(&manifest).map_err(|_| Error::Invalid("backup manifest"))?,
        )?;
        file.sync_all()?;
        File::open(output)?.sync_all()?;
        Ok(manifest)
    }
    /// Preserves identity and origin exactly; both must be explicitly confirmed.
    /// Existing destinations are refused, and startup rejects partial restores.
    pub fn restore(
        backup: &Path,
        destination: &Path,
        expected_instance: &str,
        expected_origin: &str,
    ) -> Result<Manifest> {
        let mut text = Vec::new();
        File::open(backup.join("manifest.json"))?
            .take(65537)
            .read_to_end(&mut text)?;
        if text.len() > 65536 {
            return Err(Error::Invalid("backup manifest"));
        }
        let manifest: Manifest =
            serde_json::from_slice(&text).map_err(|_| Error::Invalid("backup manifest"))?;
        if manifest.format != "patchwork/db-backup/v1"
            || manifest.database != DATABASE
            || manifest.schema_version != 1
            || manifest.instance_id != expected_instance
            || manifest.origin != expected_origin
        {
            return Err(Error::Invalid("backup identity or format"));
        }
        directory(destination)?;
        let marker = destination.join(".restore-incomplete");
        new_file(&marker)?.sync_all()?;
        File::open(destination)?.sync_all()?;
        let temporary = destination.join(".restore.sqlite3");
        let mut target = new_file(&temporary)?;
        std::io::copy(&mut File::open(backup.join(DATABASE))?, &mut target)?;
        target.sync_all()?;
        drop(target);
        let (digest, bytes) = checksum(&temporary)?;
        if digest != manifest.sha256 || bytes.to_string() != manifest.bytes {
            return Err(Error::Invalid("backup checksum"));
        }
        let connection = Connection::open_with_flags(&temporary, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        validate(&connection)?;
        if identity(&connection)? != (manifest.instance_id.clone(), manifest.origin.clone())
            || counts(&connection)? != manifest.counts
        {
            return Err(Error::Invalid("backup manifest contents"));
        }
        connection.close().map_err(|(_, e)| Error::Storage(e))?;
        std::fs::rename(&temporary, destination.join("patchwork-v1.sqlite3"))?;
        File::open(destination)?.sync_all()?;
        std::fs::remove_file(marker)?;
        File::open(destination)?.sync_all()?;
        if let Some(parent) = destination.parent().filter(|p| !p.as_os_str().is_empty()) {
            File::open(parent)?.sync_all()?;
        }
        Ok(manifest)
    }
}
