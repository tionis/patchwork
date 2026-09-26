use super::{AdminCommand, Command, ConnectionArgs, PrincipalCommand, StreamCommand, TokenCommand};
use crate::{
    Error, Result,
    auth::{Grant, ssh},
    model::{Position, Revision, StreamId, StreamName},
    store::{MAX_RECORD_BYTES, Store},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    path::Path,
    process::{Command as Process, Stdio},
    time::Duration,
};
fn origin(value: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(value).map_err(|_| Error::Invalid("URL"))?;
    if !(url.scheme() == "https"
        || (url.scheme() == "http"
            && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"))))
        || url.host_str().is_none()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(Error::Invalid(
            "expected an HTTPS origin or loopback HTTP origin",
        ));
    }
    Ok(url)
}
fn client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(Error::HealthRequest)
}
fn bounded_file(path: &Path, limit: usize) -> Result<String> {
    let mut value = String::new();
    std::fs::File::open(path)?
        .take((limit + 1) as u64)
        .read_to_string(&mut value)?;
    if value.len() > limit {
        return Err(Error::TooLarge);
    }
    Ok(value)
}
fn save_secret(path: &Path, token: &str) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(token.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}
fn value_string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or(Error::Invalid("server response"))
}
async fn checked(response: reqwest::Response) -> Result<reqwest::Response> {
    if !response.status().is_success() {
        return Err(Error::Unhealthy(response.status()));
    }
    Ok(response)
}
async fn request(
    args: &ConnectionArgs,
    method: reqwest::Method,
    path: &str,
    body: Option<Value>,
) -> Result<reqwest::Response> {
    let base = origin(&args.url)?;
    let token = bounded_file(&args.token_file, crate::auth::token::MAX_TOKEN_BYTES + 1)?;
    let mut request = client()?
        .request(
            method,
            base.join(&format!("v1/{path}"))
                .map_err(|_| Error::Invalid("path"))?,
        )
        .bearer_auth(token.trim());
    if let Some(body) = body {
        request = request.json(&body);
    }
    checked(request.send().await.map_err(Error::HealthRequest)?).await
}
async fn print_json(response: reqwest::Response) -> Result<()> {
    let value: Value = response.json().await.map_err(Error::HealthRequest)?;
    println!("{value}");
    Ok(())
}
pub async fn run(command: Command) -> Result<()> {
    match command {
        Command::Admin {
            command: AdminCommand::Backup { data_dir, output },
        } => {
            let manifest = Store::open(&data_dir)?.backup(&output)?;
            println!(
                "{}",
                serde_json::to_string(&manifest).map_err(|_| Error::Invalid("backup manifest"))?
            );
        }
        Command::Admin {
            command:
                AdminCommand::Restore {
                    backup,
                    data_dir,
                    expected_instance,
                    expected_origin,
                },
        } => {
            let manifest =
                Store::restore(&backup, &data_dir, &expected_instance, &expected_origin)?;
            println!(
                "{}",
                json!({"outcome":"restored","instance_id":manifest.instance_id,"origin":manifest.origin})
            );
        }
        Command::Hook {
            connection,
            command,
        } => hook_command(&connection, command).await?,
        Command::Kv {
            connection,
            stream_id,
            command,
        } => kv_command(&connection, &stream_id, command).await?,
        Command::Admin {
            command:
                AdminCommand::Recover {
                    data_dir,
                    ssh_public_key,
                },
        } => {
            let key = bounded_file(&ssh_public_key, 16384)?;
            let result = Store::open(&data_dir)?.recover_administrator(&key)?;
            println!("{result}");
        }
        Command::Health { url } => {
            super::check_health(&url).await?;
            println!("healthy");
        }
        Command::Admin {
            command:
                AdminCommand::Principals {
                    connection,
                    command,
                },
        } => match command {
            PrincipalCommand::List { after, limit } => {
                let path = admin_page("admin/principals", after.as_deref(), limit)?;
                print_json(request(&connection, reqwest::Method::GET, &path, None).await?).await?
            }
            PrincipalCommand::Create { file } => {
                print_json(
                    request(
                        &connection,
                        reqwest::Method::POST,
                        "admin/principals",
                        Some(read_json(&file)?),
                    )
                    .await?,
                )
                .await?
            }
            PrincipalCommand::Update { id, file, revision } => {
                uuid::Uuid::parse_str(&id).map_err(|_| Error::Invalid("principal ID"))?;
                revision.parse::<Revision>()?;
                control(
                    &connection,
                    &format!("admin/principals/{id}"),
                    Some(&file),
                    Some(format!("\"principal:{id}:{revision}\"")),
                )
                .await?;
            }
        },
        Command::Admin {
            command:
                AdminCommand::Policy {
                    connection,
                    file,
                    revision,
                },
        } => {
            control(
                &connection,
                "admin/policy",
                file.as_deref(),
                revision.map(|r| format!("\"policy:{r}\"")),
            )
            .await?
        }
        Command::Admin {
            command:
                AdminCommand::CreationRules {
                    connection,
                    file,
                    revision,
                },
        } => {
            control(
                &connection,
                "admin/creation-rules",
                file.as_deref(),
                revision.map(|r| format!("\"creation-rules:{r}\"")),
            )
            .await?
        }
        Command::Admin {
            command:
                AdminCommand::Bootstrap {
                    data_dir,
                    ssh_public_key,
                    origin,
                },
        } => {
            if !data_dir.exists() {
                let mut builder = std::fs::DirBuilder::new();
                builder.recursive(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    builder.mode(0o700);
                }
                builder.create(&data_dir)?;
            }
            Store::open(&data_dir)?.bootstrap(&bounded_file(&ssh_public_key, 1024)?, &origin)?;
            println!("{{\"outcome\":\"bootstrapped\"}}");
        }
        Command::Login {
            url,
            ssh_key,
            ssh_public_key,
            output,
        } => {
            if output.exists() {
                return Err(Error::Invalid("output credential file already exists"));
            }
            let base = origin(&url)?;
            let public = bounded_file(&ssh_public_key, 1024)?;
            let c = client()?;
            let challenge: Value = checked(
                c.post(base.join("v1/auth/challenges").unwrap())
                    .json(&json!({"ssh_public_key":public}))
                    .send()
                    .await
                    .map_err(Error::HealthRequest)?,
            )
            .await?
            .json()
            .await
            .map_err(Error::HealthRequest)?;
            let payload = STANDARD
                .decode(value_string(&challenge, "payload_base64")?)
                .map_err(|_| Error::Invalid("challenge"))?;
            let binding: Value =
                serde_json::from_slice(&payload).map_err(|_| Error::Invalid("challenge"))?;
            if value_string(&challenge, "namespace")? != ssh::NAMESPACE
                || value_string(&binding, "origin")? != base.origin().ascii_serialization()
                || value_string(&binding, "public_key")?
                    != ssh::public_key(&public)?
                        .to_openssh()
                        .map_err(|_| Error::Invalid("public key"))?
            {
                return Err(Error::Invalid("challenge binding"));
            }
            let mut process = Process::new("ssh-keygen")
                .args(["-Y", "sign", "-f"])
                .arg(ssh_key)
                .args(["-n", ssh::NAMESPACE])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()?;
            process
                .stdin
                .take()
                .ok_or(Error::Invalid("signer stdin"))?
                .write_all(&payload)?;
            let signed = process.wait_with_output()?;
            if !signed.status.success() {
                return Err(Error::Unauthorized);
            }
            let signature =
                String::from_utf8(signed.stdout).map_err(|_| Error::Invalid("signature"))?;
            let receipt:Value=checked(c.post(base.join("v1/auth/exchange").unwrap()).json(&json!({"challenge_id":value_string(&challenge,"challenge_id")?,"signature":signature})).send().await.map_err(Error::HealthRequest)?).await?.json().await.map_err(Error::HealthRequest)?;
            save_secret(&output, value_string(&receipt, "token")?)?;
            println!(
                "{}",
                json!({"credential_id":receipt["credential_id"],"expires_at":receipt["expires_at"]})
            );
        }
        Command::Stream {
            connection,
            command,
        } => match command {
            StreamCommand::Create {
                name,
                config_file,
                metadata_file,
            } => {
                name.parse::<StreamName>()?;
                let mut body = json!({"name":name});
                if let Some(file) = config_file {
                    body["config"] = read_json(&file)?;
                }
                if let Some(file) = metadata_file {
                    body["metadata"] = read_json(&file)?;
                }
                print_json(
                    request(&connection, reqwest::Method::POST, "streams", Some(body)).await?,
                )
                .await?;
            }
            StreamCommand::List {
                prefix,
                cursor,
                limit,
            } => {
                let mut url = origin(&connection.url)?.join("v1/streams").unwrap();
                url.query_pairs_mut()
                    .append_pair("prefix", &prefix)
                    .append_pair("limit", &limit.to_string());
                if let Some(cursor) = cursor {
                    url.query_pairs_mut().append_pair("cursor", &cursor);
                }
                let token = bounded_file(
                    &connection.token_file,
                    crate::auth::token::MAX_TOKEN_BYTES + 1,
                )?;
                print_json(
                    checked(
                        client()?
                            .get(url)
                            .bearer_auth(token.trim())
                            .send()
                            .await
                            .map_err(Error::HealthRequest)?,
                    )
                    .await?,
                )
                .await?;
            }
            StreamCommand::Config { id, file, revision } => {
                id.parse::<StreamId>()?;
                control(
                    &connection,
                    &format!("streams/{id}/config"),
                    file.as_deref(),
                    revision.map(|r| format!("\"{id}:config:{r}\"")),
                )
                .await?;
            }
            StreamCommand::Metadata { id, file, revision } => {
                id.parse::<StreamId>()?;
                control(
                    &connection,
                    &format!("streams/{id}/metadata"),
                    file.as_deref(),
                    revision.map(|r| format!("\"{id}:metadata:{r}\"")),
                )
                .await?;
            }
            StreamCommand::Show { id } => {
                id.parse::<StreamId>()?;
                print_json(
                    request(
                        &connection,
                        reqwest::Method::GET,
                        &format!("streams/{id}"),
                        None,
                    )
                    .await?,
                )
                .await?;
            }
            StreamCommand::Resolve { name } => {
                name.parse::<StreamName>()?;
                print_json(
                    request(
                        &connection,
                        reqwest::Method::GET,
                        &format!("streams/resolve?name={name}"),
                        None,
                    )
                    .await?,
                )
                .await?;
            }
            StreamCommand::Delete {
                id,
                config_revision,
            } => {
                id.parse::<StreamId>()?;
                config_revision.parse::<Revision>()?;
                let token = bounded_file(
                    &connection.token_file,
                    crate::auth::token::MAX_TOKEN_BYTES + 1,
                )?;
                checked(
                    client()?
                        .delete(
                            origin(&connection.url)?
                                .join(&format!("v1/streams/{id}"))
                                .unwrap(),
                        )
                        .bearer_auth(token.trim())
                        .header("If-Match", format!("\"{id}:config:{config_revision}\""))
                        .send()
                        .await
                        .map_err(Error::HealthRequest)?,
                )
                .await?;
                println!("{{\"outcome\":\"deleted\"}}");
            }
        },
        Command::Append {
            connection,
            stream_id,
            idempotency_key,
            content_type,
        } => {
            stream_id.parse::<StreamId>()?;
            append_bytes(
                &connection,
                &format!("streams/{stream_id}/records"),
                idempotency_key.as_deref(),
                &content_type,
            )
            .await?;
        }
        Command::AppendNamed {
            connection,
            name,
            idempotency_key,
            content_type,
        } => {
            name.parse::<StreamName>()?;
            append_bytes(
                &connection,
                &format!("streams/append?name={name}"),
                idempotency_key.as_deref(),
                &content_type,
            )
            .await?;
        }
        Command::Follow {
            connection,
            stream_id,
            from,
            last_event_id,
        } => {
            stream_id.parse::<StreamId>()?;
            let path = if let Some(from) = from {
                from.parse::<Position>()?;
                format!("streams/{stream_id}/follow?from={from}")
            } else if last_event_id.is_some() {
                format!("streams/{stream_id}/follow")
            } else {
                format!("streams/{stream_id}/follow?from=0")
            };
            subscription(&connection, &path, None, last_event_id.as_deref()).await?;
        }
        Command::Live {
            connection,
            stream_id,
        } => {
            stream_id.parse::<StreamId>()?;
            subscription(
                &connection,
                &format!("streams/{stream_id}/live"),
                None,
                None,
            )
            .await?;
        }
        Command::Watch {
            connection,
            prefix,
            stream_ids,
        } => {
            let body = if let Some(prefix) = prefix {
                json!({"prefix":prefix})
            } else {
                for id in &stream_ids {
                    id.parse::<StreamId>()?;
                }
                json!({"stream_ids":stream_ids})
            };
            subscription(&connection, "watch", Some(body), None).await?;
        }
        Command::Read {
            connection,
            stream_id,
            from,
            limit,
            max_bytes,
        } => {
            stream_id.parse::<StreamId>()?;
            from.parse::<Position>()?;
            print_json(
                request(
                    &connection,
                    reqwest::Method::GET,
                    &format!("streams/{stream_id}/records?from={from}&limit={limit}&max_bytes={max_bytes}"),
                    None,
                )
                .await?,
            )
            .await?;
        }
        Command::Get {
            connection,
            stream_id,
            position,
        } => {
            stream_id.parse::<StreamId>()?;
            position.parse::<Position>()?;
            let bytes = request(
                &connection,
                reqwest::Method::GET,
                &format!("streams/{stream_id}/records/{position}"),
                None,
            )
            .await?
            .bytes()
            .await
            .map_err(Error::HealthRequest)?;
            std::io::stdout().write_all(&bytes)?;
        }
        Command::Token {
            connection,
            command,
        } => match command {
            TokenCommand::List { after, limit } => {
                let path = admin_page("auth/credentials", after.as_deref(), limit)?;
                print_json(request(&connection, reqwest::Method::GET, &path, None).await?).await?
            }
            TokenCommand::Whoami => {
                print_json(request(&connection, reqwest::Method::GET, "auth/whoami", None).await?)
                    .await?
            }
            TokenCommand::Inspect => {
                let text = bounded_file(
                    &connection.token_file,
                    crate::auth::token::MAX_TOKEN_BYTES + 1,
                )?;
                let token = biscuit_auth::UnverifiedBiscuit::from_base64(text.trim())
                    .map_err(|_| Error::Unauthorized)?;
                println!(
                    "{}",
                    json!({"signature_verified":false,"blocks":token.block_count(),"has_third_party_blocks":token.external_public_keys().iter().any(Option::is_some)})
                );
            }
            TokenCommand::Attenuate {
                read_only,
                stream,
                prefix,
                expires_at,
                output,
            } => {
                let text = bounded_file(
                    &connection.token_file,
                    crate::auth::token::MAX_TOKEN_BYTES + 1,
                )?;
                let result = crate::auth::token::attenuate(
                    text.trim(),
                    read_only,
                    stream.as_deref(),
                    prefix.as_deref(),
                    expires_at.as_deref(),
                )?;
                save_secret(&output, &result)?;
                println!("{}", json!({"outcome":"attenuated"}));
            }
            TokenCommand::Mint {
                scope_file,
                lifetime_seconds,
                output,
            } => {
                if output.exists() {
                    return Err(Error::Invalid("output credential file already exists"));
                }
                let grants: Vec<Grant> = serde_json::from_str(&bounded_file(&scope_file, 65536)?)
                    .map_err(|_| Error::Invalid("scope file"))?;
                crate::auth::validate_grants(&grants)?;
                let receipt: Value = request(
                    &connection,
                    reqwest::Method::POST,
                    "credentials",
                    Some(json!({"grants":grants,"lifetime_seconds":lifetime_seconds})),
                )
                .await?
                .json()
                .await
                .map_err(Error::HealthRequest)?;
                save_secret(&output, value_string(&receipt, "token")?)?;
                println!(
                    "{}",
                    json!({"credential_id":receipt["credential_id"],"expires_at":receipt["expires_at"]})
                );
            }
            TokenCommand::Revoke { id } => {
                uuid::Uuid::parse_str(&id).map_err(|_| Error::Invalid("credential ID"))?;
                request(
                    &connection,
                    reqwest::Method::DELETE,
                    &format!("credentials/{id}"),
                    None,
                )
                .await?;
                println!("{{\"outcome\":\"revoked\"}}");
            }
        },
    }
    Ok(())
}

fn read_json(path: &Path) -> Result<Value> {
    serde_json::from_str(&bounded_file(path, 1024 * 1024)?).map_err(|_| Error::Invalid("JSON file"))
}
async fn control(
    connection: &ConnectionArgs,
    path: &str,
    file: Option<&Path>,
    etag: Option<String>,
) -> Result<()> {
    if let Some(file) = file {
        let tag = etag.ok_or(Error::Invalid("revision required"))?;
        let token = bounded_file(
            &connection.token_file,
            crate::auth::token::MAX_TOKEN_BYTES + 1,
        )?;
        let response = checked(
            client()?
                .put(
                    origin(&connection.url)?
                        .join(&format!("v1/{path}"))
                        .unwrap(),
                )
                .bearer_auth(token.trim())
                .header("If-Match", tag)
                .json(&read_json(file)?)
                .send()
                .await
                .map_err(Error::HealthRequest)?,
        )
        .await?;
        let etag = response
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        println!("{}", json!({"outcome":"updated","etag":etag}));
    } else {
        let response = request(connection, reqwest::Method::GET, path, None).await?;
        let etag = response
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let value: Value = response.json().await.map_err(Error::HealthRequest)?;
        println!("{}", json!({"etag":etag,"value":value}));
    }
    Ok(())
}
async fn append_bytes(
    connection: &ConnectionArgs,
    path: &str,
    key: Option<&str>,
    content_type: &str,
) -> Result<()> {
    crate::pipeline::validate_content_type(content_type)?;
    let mut bytes = Vec::new();
    std::io::stdin()
        .take((MAX_RECORD_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(Error::TooLarge);
    }
    let token = bounded_file(
        &connection.token_file,
        crate::auth::token::MAX_TOKEN_BYTES + 1,
    )?;
    let mut request = client()?
        .post(
            origin(&connection.url)?
                .join(&format!("v1/{path}"))
                .unwrap(),
        )
        .bearer_auth(token.trim())
        .header("Content-Type", content_type)
        .body(bytes);
    if let Some(key) = key {
        request = request.header("Idempotency-Key", key);
    }
    print_json(checked(request.send().await.map_err(Error::HealthRequest)?).await?).await
}
async fn subscription(
    connection: &ConnectionArgs,
    path: &str,
    body: Option<Value>,
    last_event_id: Option<&str>,
) -> Result<()> {
    let token = bounded_file(
        &connection.token_file,
        crate::auth::token::MAX_TOKEN_BYTES + 1,
    )?;
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .read_timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(Error::HealthRequest)?;
    let mut request = client
        .request(
            if body.is_some() {
                reqwest::Method::POST
            } else {
                reqwest::Method::GET
            },
            origin(&connection.url)?
                .join(&format!("v1/{path}"))
                .unwrap(),
        )
        .bearer_auth(token.trim());
    if let Some(body) = body {
        request = request.json(&body);
    }
    if let Some(id) = last_event_id {
        request = request.header("Last-Event-ID", id);
    }
    let mut response = checked(request.send().await.map_err(Error::HealthRequest)?).await?;
    let mut frame = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(Error::HealthRequest)? {
        std::io::stdout().write_all(&chunk)?;
        std::io::stdout().flush()?;
        frame.extend_from_slice(&chunk);
        while let Some(end) = frame.windows(2).position(|w| w == b"\n\n") {
            let value = std::str::from_utf8(&frame[..end]).map_err(|_| Error::Invalid("SSE"))?;
            if value.lines().any(|l| {
                [
                    "event: unauthorized",
                    "event: lagged",
                    "event: history_lost",
                    "event: unavailable",
                    "event: resync_required",
                    "event: deleted",
                ]
                .contains(&l)
            }) {
                return Err(Error::Invalid(
                    "subscription closed; inspect last SSE event",
                ));
            }
            frame.drain(..end + 2);
        }
        if frame.len() > 2 * 1024 * 1024 {
            return Err(Error::TooLarge);
        }
    }
    Ok(())
}

fn admin_page(path: &str, after: Option<&str>, limit: usize) -> Result<String> {
    if !(1..=1000).contains(&limit) {
        return Err(Error::Invalid("page limit"));
    }
    if let Some(after) = after {
        uuid::Uuid::parse_str(after).map_err(|_| Error::Invalid("page cursor"))?;
    }
    Ok(format!(
        "{path}?after={}&limit={limit}",
        after.unwrap_or("")
    ))
}

async fn kv_command(
    connection: &ConnectionArgs,
    sid: &str,
    command: super::KvCommand,
) -> Result<()> {
    use super::KvCommand;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    sid.parse::<StreamId>()?;
    let base = origin(&connection.url)?;
    let token = bounded_file(
        &connection.token_file,
        crate::auth::token::MAX_TOKEN_BYTES + 1,
    )?;
    let c = client()?;
    let root = format!("v1/streams/{sid}");
    let url = |path: &str| base.join(path).map_err(|_| Error::Invalid("KV path"));
    let response = match command {
        KvCommand::Enable { config_revision } => {
            config_revision.parse::<Revision>()?;
            c.post(url(&format!("{root}/attachments"))?)
                .bearer_auth(token.trim())
                .header("if-match", format!("\"{sid}:config:{config_revision}\""))
                .json(&json!({"type":crate::store::kv::TYPE}))
                .send()
                .await
                .map_err(Error::HealthRequest)?
        }
        KvCommand::Attachments => c
            .get(url(&format!("{root}/attachments"))?)
            .bearer_auth(token.trim())
            .send()
            .await
            .map_err(Error::HealthRequest)?,
        KvCommand::Get { attachment, key } => {
            validate_attachment(&attachment)?;
            crate::store::kv::validate_key(&key)?;
            let response = checked(
                c.get(url(&format!(
                    "{root}/kv/{attachment}/items/{}",
                    URL_SAFE_NO_PAD.encode(key.as_bytes())
                ))?)
                .bearer_auth(token.trim())
                .send()
                .await
                .map_err(Error::HealthRequest)?,
            )
            .await?;
            std::io::stdout().write_all(&response.bytes().await.map_err(Error::HealthRequest)?)?;
            return Ok(());
        }
        KvCommand::List {
            attachment,
            prefix,
            cursor,
            limit,
        } => {
            validate_attachment(&attachment)?;
            let mut query = url(&format!("{root}/kv/{attachment}/items"))?;
            query
                .query_pairs_mut()
                .append_pair("prefix", &prefix)
                .append_pair("limit", &limit.to_string());
            if let Some(cursor) = cursor {
                query.query_pairs_mut().append_pair("cursor", &cursor);
            }
            c.get(query)
                .bearer_auth(token.trim())
                .send()
                .await
                .map_err(Error::HealthRequest)?
        }
        command => {
            let (attachment, key, if_match, if_absent, idempotency, content_type, put) =
                match command {
                    KvCommand::Put {
                        attachment,
                        key,
                        if_match,
                        if_absent,
                        idempotency_key,
                        content_type,
                    } => (
                        attachment,
                        key,
                        if_match,
                        if_absent,
                        idempotency_key,
                        content_type,
                        true,
                    ),
                    KvCommand::Delete {
                        attachment,
                        key,
                        if_match,
                        idempotency_key,
                    } => (
                        attachment,
                        key,
                        if_match,
                        false,
                        idempotency_key,
                        String::new(),
                        false,
                    ),
                    _ => unreachable!(),
                };
            validate_attachment(&attachment)?;
            crate::store::kv::validate_key(&key)?;
            let mut request = c
                .request(
                    if put {
                        reqwest::Method::PUT
                    } else {
                        reqwest::Method::DELETE
                    },
                    url(&format!(
                        "{root}/kv/{attachment}/items/{}",
                        URL_SAFE_NO_PAD.encode(key.as_bytes())
                    ))?,
                )
                .bearer_auth(token.trim());
            if let Some(revision) = if_match {
                revision.parse::<Position>()?;
                request = request.header("if-match", format!("\"kv:{attachment}:{revision}\""));
            }
            if if_absent {
                request = request.header("if-none-match", "*");
            }
            if let Some(key) = idempotency {
                request = request.header("idempotency-key", key);
            }
            if put {
                let mut bytes = Vec::new();
                std::io::stdin()
                    .take((crate::store::kv::MAX_VALUE_BYTES + 1) as u64)
                    .read_to_end(&mut bytes)?;
                if bytes.len() > crate::store::kv::MAX_VALUE_BYTES {
                    return Err(Error::TooLarge);
                }
                request = request.header("content-type", content_type).body(bytes);
            }
            request.send().await.map_err(Error::HealthRequest)?
        }
    };
    let response = checked(response).await?;
    if response.status() == reqwest::StatusCode::NO_CONTENT {
        println!(
            "{}",
            json!({"status":204,"position":response.headers().get("patchwork-position").and_then(|v|v.to_str().ok()),"applied_position":response.headers().get("patchwork-applied-position").and_then(|v|v.to_str().ok()),"deduplicated":response.headers().get("patchwork-deduplicated").and_then(|v|v.to_str().ok())})
        );
        Ok(())
    } else {
        print_json(response).await
    }
}
fn validate_attachment(id: &str) -> Result<()> {
    uuid::Uuid::parse_str(
        id.strip_prefix("att_")
            .ok_or(Error::Invalid("attachment ID"))?,
    )
    .map_err(|_| Error::Invalid("attachment ID"))?;
    Ok(())
}

async fn hook_command(connection: &ConnectionArgs, command: super::HookCommand) -> Result<()> {
    use super::HookCommand;
    match command {
        HookCommand::Create { file } => {
            print_json(
                request(
                    connection,
                    reqwest::Method::POST,
                    "hooks",
                    Some(read_json(&file)?),
                )
                .await?,
            )
            .await
        }
        HookCommand::List { after, limit } => {
            let mut path = origin(&connection.url)?
                .join("hooks")
                .map_err(|_| Error::Invalid("hook path"))?;
            path.query_pairs_mut()
                .append_pair("after", &after)
                .append_pair("limit", &limit.to_string());
            print_json(
                request(
                    connection,
                    reqwest::Method::GET,
                    &format!("hooks?{}", path.query().unwrap_or("")),
                    None,
                )
                .await?,
            )
            .await
        }
        command => {
            let (id, file, revision, delete) = match command {
                HookCommand::Get { id } => (id, None, None, false),
                HookCommand::Update { id, file, revision } => {
                    (id, Some(file), Some(revision), false)
                }
                HookCommand::Delete { id, revision } => (id, None, Some(revision), true),
                _ => unreachable!(),
            };
            uuid::Uuid::parse_str(id.strip_prefix("hook_").ok_or(Error::Invalid("hook ID"))?)
                .map_err(|_| Error::Invalid("hook ID"))?;
            if let Some(revision) = &revision {
                revision.parse::<Revision>()?;
            }
            let etag = revision.map(|r| format!("\"hook:{id}:{r}\""));
            if !delete {
                return control(connection, &format!("hooks/{id}"), file.as_deref(), etag).await;
            }
            let token = bounded_file(
                &connection.token_file,
                crate::auth::token::MAX_TOKEN_BYTES + 1,
            )?;
            checked(
                client()?
                    .delete(
                        origin(&connection.url)?
                            .join(&format!("v1/hooks/{id}"))
                            .map_err(|_| Error::Invalid("hook URL"))?,
                    )
                    .bearer_auth(token.trim())
                    .header("if-match", etag.ok_or(Error::Invalid("revision"))?)
                    .send()
                    .await
                    .map_err(Error::HealthRequest)?,
            )
            .await?;
            println!("{{\"outcome\":\"deleted\"}}");
            Ok(())
        }
    }
}
