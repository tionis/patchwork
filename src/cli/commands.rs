use super::{AdminCommand, Command, ConnectionArgs, StreamCommand, TokenCommand};
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
    if url.scheme() != "http"
        || !matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"))
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(Error::Invalid(
            "prototype client requires a loopback HTTP origin",
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
        .request(method, base.join(path).map_err(|_| Error::Invalid("path"))?)
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
        Command::Health { url } => {
            super::check_health(&url).await?;
            println!("healthy");
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
                c.post(base.join("auth/challenges").unwrap())
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
            let receipt:Value=checked(c.post(base.join("auth/exchange").unwrap()).json(&json!({"challenge_id":value_string(&challenge,"challenge_id")?,"signature":signature})).send().await.map_err(Error::HealthRequest)?).await?.json().await.map_err(Error::HealthRequest)?;
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
            StreamCommand::Create { name } => {
                name.parse::<StreamName>()?;
                print_json(
                    request(
                        &connection,
                        reqwest::Method::POST,
                        "streams",
                        Some(json!({"name":name})),
                    )
                    .await?,
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
                                .join(&format!("streams/{id}"))
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
        } => {
            stream_id.parse::<StreamId>()?;
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
            print_json(
                checked(
                    client()?
                        .post(
                            origin(&connection.url)?
                                .join(&format!("streams/{stream_id}/records"))
                                .unwrap(),
                        )
                        .bearer_auth(token.trim())
                        .header("Content-Type", "application/octet-stream")
                        .body(bytes)
                        .send()
                        .await
                        .map_err(Error::HealthRequest)?,
                )
                .await?,
            )
            .await?;
        }
        Command::Read {
            connection,
            stream_id,
            from,
            limit,
        } => {
            stream_id.parse::<StreamId>()?;
            from.parse::<Position>()?;
            print_json(
                request(
                    &connection,
                    reqwest::Method::GET,
                    &format!("streams/{stream_id}/records?from={from}&limit={limit}"),
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
