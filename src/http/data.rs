//! Authenticated prototype routes. A bounded blocking boundary keeps SQLite and
//! cryptographic work off Tokio workers; no unbounded writer task queue.
mod admission;
mod hooks;
mod kv;
mod subscriptions;
use crate::{
    Error, Result,
    auth::{Action, Grant},
    model::{Metadata, Position, Revision, Stream, StreamConfig, StreamId, StreamName},
    store::Store,
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use tokio::sync::Semaphore;

#[derive(Clone)]
pub struct DataService {
    store: Arc<Mutex<Store>>,
    admission: Arc<Semaphore>,
    requests: Arc<Semaphore>,
    login_admission: Arc<Mutex<admission::LoginAdmission>>,
    stopping: Arc<std::sync::atomic::AtomicBool>,
    hub: Arc<Mutex<subscriptions::Hub>>,
    subscriptions: Arc<Semaphore>,
}
impl DataService {
    pub fn new(store: Store) -> Self {
        let service = Self {
            store: Arc::new(Mutex::new(store)),
            admission: Arc::new(Semaphore::new(32)),
            requests: Arc::new(Semaphore::new(64)),
            login_admission: Arc::new(Mutex::new(admission::LoginAdmission::new())),
            stopping: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            hub: Arc::new(Mutex::new(subscriptions::Hub::new())),
            subscriptions: Arc::new(Semaphore::new(128)),
        };
        let weak = Arc::downgrade(&service.store);
        let admission = Arc::downgrade(&service.admission);
        tokio::spawn(async move {
            let mut after = String::new();
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                let (Some(store), Some(admission)) = (weak.upgrade(), admission.upgrade()) else {
                    break;
                };
                let Ok(permit) = admission.try_acquire_owned() else {
                    continue;
                };
                let cursor = after.clone();
                if let Ok(Ok(next)) = tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    store
                        .lock()
                        .map_err(|_| Error::Busy)?
                        .maintenance_page(&cursor)
                })
                .await
                {
                    after = next;
                }
            }
        });
        service
    }
    pub fn shutdown(&self) {
        self.stopping
            .store(true, std::sync::atomic::Ordering::Release);
    }
    async fn run<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&mut Store) -> Result<T> + Send + 'static,
    ) -> std::result::Result<T, ApiError> {
        if self.stopping.load(std::sync::atomic::Ordering::Acquire) {
            return Err(ApiError(Error::Busy));
        }
        let permit = self
            .admission
            .clone()
            .try_acquire_owned()
            .map_err(|_| ApiError(Error::Busy))?;
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut store = store.lock().map_err(|_| Error::Busy)?;
            operation(&mut store)
        })
        .await
        .map_err(|_| ApiError(Error::Busy))?
        .map_err(ApiError)
    }
}
pub fn router(service: DataService) -> Router {
    Router::new()
        .route("/hooks", get(hooks::list).post(hooks::create))
        .route(
            "/hooks/{id}",
            get(hooks::get)
                .put(hooks::put)
                .delete(hooks::delete)
                .post(hooks::ingest),
        )
        .route("/auth/challenges", post(challenge))
        .route("/auth/exchange", post(exchange))
        .route("/credentials", post(mint).get(credentials_get))
        .route("/auth/credentials", post(mint).get(credentials_get))
        .route("/auth/whoami", get(whoami))
        .route("/auth/credentials/{id}", axum::routing::delete(revoke))
        .route(
            "/admin/principals",
            get(principals_get).post(principals_post),
        )
        .route("/admin/principals/{id}", axum::routing::put(principals_put))
        .route("/admin/policy", get(policy_get).put(policy_put))
        .route("/credentials/{id}", axum::routing::delete(revoke))
        .route("/streams", post(create).get(streams_list))
        .route(
            "/streams/{id}/attachments",
            get(kv::attachments).post(kv::install),
        )
        .route("/streams/{id}/kv/{aid}/items", get(kv::list))
        .route(
            "/streams/{id}/kv/{aid}/items/{key}",
            get(kv::get).put(kv::put).delete(kv::delete),
        )
        .route("/streams/{id}/follow", get(subscriptions::follow))
        .route("/streams/{id}/live", get(subscriptions::live))
        .route("/watch", post(subscriptions::watch))
        .route("/streams/resolve", get(resolve))
        .route("/streams/append", post(subscriptions::append_named))
        .route(
            "/admin/creation-rules",
            get(creation_rules_get).put(creation_rules_put),
        )
        .route("/streams/{id}", get(inspect).delete(delete))
        .route("/streams/{id}/config", get(config_get).put(config_put))
        .route(
            "/streams/{id}/metadata",
            get(metadata_get).put(metadata_put),
        )
        .route("/streams/{id}/records", get(read).post(append))
        .route("/streams/{id}/records/{position}", get(raw))
        .layer(DefaultBodyLimit::max(crate::store::MAX_RECORD_BYTES))
        .layer(axum::middleware::from_fn(lift_url_token))
        .layer(axum::middleware::from_fn_with_state(
            service.clone(),
            admit_request,
        ))
        .layer(axum::middleware::map_response(normalize_response))
        .with_state(service)
}
/// Lifts a `?token=` query parameter into an `Authorization` header so every
/// handler sees one credential path. The marker makes the credential layer
/// accept it only for `api_url` credentials, which minting confines to narrow
/// stream-data authority. The query string is rewritten without the token, so
/// nothing downstream (handlers, tracing) can see it; a token in both places
/// is refused; responses forbid referrers (and are already `no-store`).
async fn lift_url_token(
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let query = request.uri().query().map(str::to_owned);
    if let Some(query) = query.as_deref() {
        let mut kept = Vec::new();
        let mut token = None;
        for pair in query.split('&') {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            if key == "token" {
                if token.replace(percent_decode(value)).is_some() {
                    return ApiError(Error::Unauthorized).into_response();
                }
            } else {
                kept.push(pair);
            }
        }
        if let Some(decoded) = token {
            let header_value = decoded
                .filter(|t| !t.is_empty() && t.len() <= crate::auth::token::MAX_TOKEN_BYTES)
                .and_then(|t| {
                    header::HeaderValue::from_str(&format!(
                        "Bearer {}{t}",
                        crate::auth::token::URL_MARKER
                    ))
                    .ok()
                });
            let Some(mut header_value) = header_value else {
                return ApiError(Error::Unauthorized).into_response();
            };
            if request.headers().contains_key(header::AUTHORIZATION) {
                return ApiError(Error::Unauthorized).into_response();
            }
            header_value.set_sensitive(true);
            request
                .headers_mut()
                .insert(header::AUTHORIZATION, header_value);
            let path = request.uri().path().to_owned();
            let rebuilt = if kept.is_empty() {
                path
            } else {
                format!("{path}?{}", kept.join("&"))
            };
            let mut parts = request.uri().clone().into_parts();
            let Ok(path_and_query) = rebuilt.parse() else {
                return ApiError(Error::Unauthorized).into_response();
            };
            parts.path_and_query = Some(path_and_query);
            let Ok(uri) = axum::http::Uri::from_parts(parts) else {
                return ApiError(Error::Unauthorized).into_response();
            };
            *request.uri_mut() = uri;
        }
    }
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::REFERRER_POLICY,
        header::HeaderValue::from_static("no-referrer"),
    );
    response
}
/// Decodes `%XX` escapes; any malformed escape or non-UTF-8 result is `None`.
fn percent_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = value.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}
// Admit before body extraction so slow uploads cannot allocate unbounded
// buffers. The deadline covers upload and handler work, not SSE lifetimes.
async fn admit_request(
    State(service): State<DataService>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if request.uri().path().ends_with("/auth/challenges")
        || request.uri().path().ends_with("/auth/exchange")
    {
        let peer = request
            .extensions()
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|info| info.0.ip())
            .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED.into());
        let allowed = service
            .login_admission
            .lock()
            .is_ok_and(|mut limiter| limiter.admit(peer, std::time::Instant::now()));
        if !allowed {
            return (StatusCode::TOO_MANY_REQUESTS, [(header::RETRY_AFTER, "60")]).into_response();
        }
    }
    let Ok(_permit) = service.requests.try_acquire() else {
        return ApiError(Error::Busy).into_response();
    };
    match tokio::time::timeout(std::time::Duration::from_secs(10), next.run(request)).await {
        Ok(response) => response,
        Err(_) => StatusCode::REQUEST_TIMEOUT.into_response(),
    }
}

pub struct ApiError(Error);
impl From<Error> for ApiError {
    fn from(e: Error) -> Self {
        Self(e)
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = match self.0 {
            Error::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Error::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            Error::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Error::Conflict | Error::ConfigChanged | Error::PositionAhead | Error::StreamMode => {
                (StatusCode::CONFLICT, "conflict")
            }
            Error::RevisionMismatch => (StatusCode::PRECONDITION_FAILED, "revision_mismatch"),
            Error::Rejected => (StatusCode::UNPROCESSABLE_ENTITY, "rejected"),
            Error::HistoryLost => (StatusCode::GONE, "history_lost"),
            Error::TooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "too_large"),
            Error::Invalid("If-Match required") => {
                (StatusCode::PRECONDITION_REQUIRED, "precondition_required")
            }
            Error::Invalid(_) => (StatusCode::BAD_REQUEST, "invalid_request"),
            _ => (StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        };
        let mut response=(status,Json(json!({"type":"about:blank","title":code,"status":status.as_u16(),"code":code,"request_id":uuid::Uuid::new_v4().to_string()}))).into_response();
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/problem+json"),
        );
        response
    }
}
fn bearer(headers: &HeaderMap) -> Result<String> {
    if headers.get_all(header::AUTHORIZATION).iter().count() != 1 {
        return Err(Error::Unauthorized);
    }
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(Error::Unauthorized)?;
    if value.len() > crate::auth::token::MAX_TOKEN_BYTES || value.is_empty() {
        return Err(Error::Unauthorized);
    }
    Ok(value.to_owned())
}
fn expected(headers: &HeaderMap, id: &StreamId, kind: &str) -> Result<Revision> {
    let value = headers
        .get(header::IF_MATCH)
        .ok_or(Error::Invalid("If-Match required"))?
        .to_str()
        .map_err(|_| Error::Invalid("If-Match"))?;
    let prefix = format!("\"{}:{kind}:", id.as_str());
    value
        .strip_prefix(&prefix)
        .and_then(|v| v.strip_suffix('"'))
        .ok_or(Error::RevisionMismatch)?
        .parse()
}
fn etag(id: &StreamId, kind: &str, revision: Revision) -> String {
    format!("\"{}:{kind}:{revision}\"", id.as_str())
}
fn descriptor(s: Stream) -> Value {
    let mut value = json!({"id":s.id.as_str(),"name":s.name.as_str(),"mode":if s.retained{"retained"}else{"none"},"config_revision":s.config_revision.to_string(),"metadata_revision":s.metadata_revision.to_string()});
    if s.retained {
        value["head"] = json!(s.head.to_string());
        value["tail"] = json!(s.tail.to_string());
    }
    value
}
fn stream(store: &Store, token: &str, id: &str) -> Result<Stream> {
    store.authenticate(token)?;
    store.stream(&id.parse()?)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChallengeInput {
    #[serde(rename = "public_key", alias = "ssh_public_key")]
    ssh_public_key: String,
}
async fn challenge(
    State(s): State<DataService>,
    Json(input): Json<ChallengeInput>,
) -> std::result::Result<impl IntoResponse, ApiError> {
    Ok(Json(
        s.run(move |s| s.challenge(&input.ssh_public_key)).await?,
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExchangeInput {
    challenge_id: String,
    signature: String,
}
async fn exchange(
    State(s): State<DataService>,
    Json(input): Json<ExchangeInput>,
) -> std::result::Result<impl IntoResponse, ApiError> {
    Ok(Json(
        s.run(move |s| s.exchange(&input.challenge_id, &input.signature))
            .await?,
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MintInput {
    grants: Vec<Grant>,
    lifetime_seconds: i64,
    #[serde(default)]
    url_transport: bool,
}
async fn mint(
    State(s): State<DataService>,
    headers: HeaderMap,
    Json(input): Json<MintInput>,
) -> std::result::Result<impl IntoResponse, ApiError> {
    let token = bearer(&headers)?;
    Ok((
        StatusCode::CREATED,
        Json(
            s.run(move |s| {
                s.mint_with(
                    &token,
                    &input.grants,
                    input.lifetime_seconds,
                    input.url_transport,
                )
            })
            .await?,
        ),
    ))
}
async fn revoke(
    State(s): State<DataService>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> std::result::Result<impl IntoResponse, ApiError> {
    let token = bearer(&headers)?;
    s.run(move |s| s.revoke(&token, &id)).await?;
    Ok(StatusCode::NO_CONTENT)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateInput {
    name: String,
    #[serde(default)]
    config: Option<StreamConfig>,
    #[serde(default = "empty_metadata")]
    metadata: Value,
}
fn empty_metadata() -> Value {
    json!({})
}
async fn create(
    State(s): State<DataService>,
    headers: HeaderMap,
    Json(input): Json<CreateInput>,
) -> std::result::Result<impl IntoResponse, ApiError> {
    let token = bearer(&headers)?;
    let name: StreamName = input.name.parse()?;
    let metadata: Metadata = input.metadata.to_string().parse()?;
    let stream = s
        .run(move |s| s.create_authorized(&token, &name, input.config.as_ref(), &metadata))
        .await?;
    s.hint(stream.id.as_str(), stream.name.as_str(), "created");
    Ok((StatusCode::CREATED, Json(descriptor(stream))))
}
#[derive(Deserialize)]
struct ResolveInput {
    name: String,
}
async fn resolve(
    State(s): State<DataService>,
    headers: HeaderMap,
    Query(input): Query<ResolveInput>,
) -> std::result::Result<impl IntoResponse, ApiError> {
    let token = bearer(&headers)?;
    let name: StreamName = input.name.parse()?;
    Ok(Json(
        s.run(move |s| {
            s.authenticate(&token)?;
            let st = s.lookup_stream(&name)?;
            s.authorized(&token, Action::StreamInspect, Some(&st.id), &st.name, |s| {
                s.stream(&st.id)
            })
            .map(descriptor)
        })
        .await?,
    ))
}
async fn inspect(
    State(s): State<DataService>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> std::result::Result<impl IntoResponse, ApiError> {
    let token = bearer(&headers)?;
    Ok(Json(
        s.run(move |s| {
            let st = stream(s, &token, &id)?;
            s.authorized(&token, Action::StreamInspect, Some(&st.id), &st.name, |s| {
                s.stream(&st.id)
            })
            .map(descriptor)
        })
        .await?,
    ))
}
async fn delete(
    State(s): State<DataService>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> std::result::Result<impl IntoResponse, ApiError> {
    let token = bearer(&headers)?;
    let id: StreamId = id.parse()?;
    let revision = expected(&headers, &id, "config")?;
    let st = s
        .run(move |s| {
            let st = stream(s, &token, id.as_str())?;
            s.authorized(&token, Action::StreamDelete, Some(&id), &st.name, |s| {
                s.delete_stream(&id, revision)
            })?;
            Ok(st)
        })
        .await?;
    s.hint(st.id.as_str(), st.name.as_str(), "deleted");
    Ok(StatusCode::NO_CONTENT)
}
async fn config_get(
    State(s): State<DataService>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> std::result::Result<impl IntoResponse, ApiError> {
    let token = bearer(&headers)?;
    let (tag, value) = s
        .run(move |s| {
            let st = stream(s, &token, &id)?;
            s.authorized(&token, Action::ConfigRead, Some(&st.id), &st.name, |s| {
                let v = s.config(&st.id)?;
                Ok((etag(&st.id, "config", v.revision), v.value))
            })
        })
        .await?;
    Ok(([(header::ETAG, tag)], Json(value)))
}
async fn config_put(
    State(s): State<DataService>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(config): Json<StreamConfig>,
) -> std::result::Result<impl IntoResponse, ApiError> {
    let token = bearer(&headers)?;
    let id: StreamId = id.parse()?;
    let rev = expected(&headers, &id, "config")?;
    let (st, tag) = s
        .run(move |s| {
            let st = stream(s, &token, id.as_str())?;
            let rev = s.authorized(&token, Action::ConfigWrite, Some(&id), &st.name, |s| {
                s.replace_config(&id, rev, &config)
            })?;
            Ok((st, etag(&id, "config", rev)))
        })
        .await?;
    s.hint(st.id.as_str(), st.name.as_str(), "config");
    Ok(([(header::ETAG, tag)], StatusCode::NO_CONTENT))
}
async fn metadata_get(
    State(s): State<DataService>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> std::result::Result<impl IntoResponse, ApiError> {
    let token = bearer(&headers)?;
    let (tag, value) = s
        .run(move |s| {
            let st = stream(s, &token, &id)?;
            s.authorized(&token, Action::MetadataRead, Some(&st.id), &st.name, |s| {
                let v = s.metadata(&st.id)?;
                let value: Value =
                    serde_json::from_str(v.value.as_str()).map_err(|_| Error::DatabaseFormat)?;
                Ok((etag(&st.id, "metadata", v.revision), value))
            })
        })
        .await?;
    Ok((
        [(header::ETAG, tag)],
        Json(json!({"value":value,"object_refs":[]})),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MetadataInput {
    value: Value,
    #[serde(default)]
    object_refs: Vec<String>,
}
async fn metadata_put(
    State(s): State<DataService>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<MetadataInput>,
) -> std::result::Result<impl IntoResponse, ApiError> {
    if !input.object_refs.is_empty() {
        return Err(Error::Invalid("object links unavailable").into());
    }
    let token = bearer(&headers)?;
    let id: StreamId = id.parse()?;
    let rev = expected(&headers, &id, "metadata")?;
    let metadata: Metadata = input.value.to_string().parse()?;
    let (st, tag) = s
        .run(move |s| {
            let st = stream(s, &token, id.as_str())?;
            let rev = s.authorized(&token, Action::MetadataWrite, Some(&id), &st.name, |s| {
                s.replace_metadata(&id, rev, &metadata)
            })?;
            Ok((st, etag(&id, "metadata", rev)))
        })
        .await?;
    s.hint(st.id.as_str(), st.name.as_str(), "metadata");
    Ok(([(header::ETAG, tag)], StatusCode::NO_CONTENT))
}
async fn append(
    State(s): State<DataService>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> std::result::Result<Response, ApiError> {
    subscriptions::publish(s, id, headers, body).await
}
#[derive(Deserialize)]
struct ReadInput {
    from: String,
    #[serde(default = "page_limit")]
    limit: usize,
    #[serde(default = "byte_limit")]
    max_bytes: usize,
}
fn page_limit() -> usize {
    100
}
fn byte_limit() -> usize {
    4 * 1024 * 1024
}
async fn read(
    State(s): State<DataService>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Query(input): Query<ReadInput>,
) -> std::result::Result<impl IntoResponse, ApiError> {
    let token = bearer(&headers)?;
    let from: Position = input.from.parse()?;
    let page = s.run(move |s| {
        let st = stream(s, &token, &id)?;
        let page = s.authorized(&token, Action::RecordRead, Some(&st.id), &st.name,
            |s| s.read(&st.id, from, input.limit, input.max_bytes))?;
        let records = page.records.into_iter().map(record_json).collect::<Result<Vec<_>>>()?;
        Ok(json!({"stream_id":id,"head":page.head.to_string(),"tail":page.tail.to_string(),"next_position":page.next_position.to_string(),"records":records}))
    }).await?;
    Ok(Json(page))
}
fn record_json(record: crate::model::Record) -> Result<Value> {
    Ok(
        json!({"position":record.position.to_string(),"data_base64":STANDARD.encode(record.payload),"object_refs":[],"content_type":record.content_type,"accepted_at":crate::wire::timestamp_ms(record.accepted_at_ms)?}),
    )
}
async fn raw(
    State(s): State<DataService>,
    Path((id, position)): Path<(String, String)>,
    headers: HeaderMap,
) -> std::result::Result<impl IntoResponse, ApiError> {
    let token = bearer(&headers)?;
    let position: Position = position.parse()?;
    let record = s
        .run(move |s| {
            let st = stream(s, &token, &id)?;
            let page = s.authorized(&token, Action::RecordRead, Some(&st.id), &st.name, |s| {
                s.read(&st.id, position, 1, crate::store::MAX_RECORD_BYTES)
            })?;
            page.records.into_iter().next().ok_or(Error::NotFound)
        })
        .await?;
    Ok((
        [(header::CONTENT_TYPE, record.content_type)],
        record.payload,
    ))
}

async fn normalize_response(response: Response) -> Response {
    let mut response = if (response.status().is_client_error()
        || response.status().is_server_error())
        && response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            != Some("application/problem+json")
    {
        let status = response.status();
        let code = match status {
            StatusCode::PAYLOAD_TOO_LARGE => "too_large",
            StatusCode::UNPROCESSABLE_ENTITY => "invalid_request",
            StatusCode::TOO_MANY_REQUESTS => "rate_limited",
            StatusCode::REQUEST_TIMEOUT => "request_timeout",
            _ => "request_failed",
        };
        let mut result=(status,Json(json!({"type":"about:blank","title":code,"status":status.as_u16(),"code":code,"request_id":uuid::Uuid::new_v4().to_string()}))).into_response();
        result.headers_mut().insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/problem+json"),
        );
        if let Some(retry) = response.headers().get(header::RETRY_AFTER) {
            result
                .headers_mut()
                .insert(header::RETRY_AFTER, retry.clone());
        }
        result
    } else {
        response
    };
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}

#[derive(Deserialize)]
struct AdminPage {
    #[serde(default)]
    after: String,
    #[serde(default = "page_limit")]
    limit: usize,
}
async fn whoami(
    State(s): State<DataService>,
    headers: HeaderMap,
) -> std::result::Result<impl IntoResponse, ApiError> {
    let token = bearer(&headers)?;
    Ok(Json(s.run(move |s| s.whoami(&token)).await?))
}
async fn principals_get(
    State(s): State<DataService>,
    headers: HeaderMap,
    Query(page): Query<AdminPage>,
) -> std::result::Result<impl IntoResponse, ApiError> {
    let token = bearer(&headers)?;
    let items = s
        .run(move |s| s.principals(&token, &page.after, page.limit))
        .await?;
    let next = if items.len() == page.limit {
        items.last().map(|p| p.id.clone())
    } else {
        None
    };
    Ok(Json(json!({"items":items,"next_cursor":next})))
}
async fn principals_post(
    State(s): State<DataService>,
    headers: HeaderMap,
    Json(input): Json<crate::store::PrincipalInput>,
) -> std::result::Result<impl IntoResponse, ApiError> {
    let token = bearer(&headers)?;
    let p = s
        .run(move |s| s.put_principal(&token, None, None, &input))
        .await?;
    Ok((
        StatusCode::CREATED,
        [(
            header::ETAG,
            format!("\"principal:{}:{}\"", p.id, p.revision),
        )],
        Json(p),
    ))
}
fn control_revision(headers: &HeaderMap, kind: &str) -> Result<Revision> {
    let value = headers
        .get(header::IF_MATCH)
        .ok_or(Error::Invalid("If-Match required"))?
        .to_str()
        .map_err(|_| Error::Invalid("If-Match"))?;
    value
        .strip_prefix(&format!("\"{kind}:"))
        .and_then(|v| v.strip_suffix('"'))
        .ok_or(Error::RevisionMismatch)?
        .parse()
}
async fn principals_put(
    State(s): State<DataService>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<crate::store::PrincipalInput>,
) -> std::result::Result<impl IntoResponse, ApiError> {
    let token = bearer(&headers)?;
    let expected = control_revision(&headers, &format!("principal:{id}"))?;
    let p = s
        .run(move |s| s.put_principal(&token, Some(&id), Some(expected), &input))
        .await?;
    Ok((
        [(
            header::ETAG,
            format!("\"principal:{}:{}\"", p.id, p.revision),
        )],
        Json(p),
    ))
}
async fn policy_get(
    State(s): State<DataService>,
    headers: HeaderMap,
) -> std::result::Result<impl IntoResponse, ApiError> {
    let token = bearer(&headers)?;
    let (rev, value) = s.run(move |s| s.policy(&token)).await?;
    Ok(([(header::ETAG, format!("\"policy:{rev}\""))], Json(value)))
}
async fn policy_put(
    State(s): State<DataService>,
    headers: HeaderMap,
    Json(input): Json<crate::store::AuthPolicy>,
) -> std::result::Result<impl IntoResponse, ApiError> {
    let token = bearer(&headers)?;
    let rev = control_revision(&headers, "policy")?;
    let rev = s
        .run(move |s| s.replace_policy(&token, rev, &input))
        .await?;
    Ok((
        [(header::ETAG, format!("\"policy:{rev}\""))],
        StatusCode::NO_CONTENT,
    ))
}
async fn credentials_get(
    State(s): State<DataService>,
    headers: HeaderMap,
    Query(page): Query<AdminPage>,
) -> std::result::Result<impl IntoResponse, ApiError> {
    let token = bearer(&headers)?;
    let items = s
        .run(move |s| s.credentials(&token, &page.after, page.limit))
        .await?;
    let next = if items.len() == page.limit {
        items.last().and_then(|v| v.get("id")).cloned()
    } else {
        None
    };
    Ok(Json(json!({"items":items,"next_cursor":next})))
}

#[derive(Deserialize)]
struct StreamListQuery {
    #[serde(default)]
    prefix: String,
    cursor: Option<String>,
    #[serde(default = "page_limit")]
    limit: usize,
}
#[derive(serde::Serialize, Deserialize)]
struct StreamCursor {
    principal: String,
    prefix: String,
    after: String,
}
async fn streams_list(
    State(s): State<DataService>,
    headers: HeaderMap,
    Query(query): Query<StreamListQuery>,
) -> std::result::Result<impl IntoResponse, ApiError> {
    let token = bearer(&headers)?;
    let cursor = query
        .cursor
        .map(|c| {
            if c.len() > 4096 {
                return Err(Error::Invalid("cursor"));
            }
            let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(c)
                .map_err(|_| Error::Invalid("cursor"))?;
            serde_json::from_slice::<StreamCursor>(&bytes).map_err(|_| Error::Invalid("cursor"))
        })
        .transpose()?;
    let (items, next) = s
        .run(move |s| {
            let principal = s.principal_id(&token)?;
            let after = if let Some(cursor) = cursor {
                if cursor.principal != principal || cursor.prefix != query.prefix {
                    return Err(Error::Invalid("cursor binding"));
                }
                cursor.after
            } else {
                String::new()
            };
            let (items, next) = s.list_streams(&token, &query.prefix, &after, query.limit)?;
            let next = next.map(|after| {
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
                    serde_json::to_vec(&StreamCursor {
                        principal,
                        prefix: query.prefix,
                        after,
                    })
                    .expect("cursor serialization"),
                )
            });
            Ok((items, next))
        })
        .await?;
    Ok(Json(
        json!({"items":items.into_iter().map(descriptor).collect::<Vec<_>>(),"next_cursor":next}),
    ))
}

async fn creation_rules_get(
    State(s): State<DataService>,
    headers: HeaderMap,
) -> std::result::Result<impl IntoResponse, ApiError> {
    let token = bearer(&headers)?;
    let (r, v) = s.run(move |s| s.creation_rules(&token)).await?;
    Ok(([(header::ETAG, format!("\"creation-rules:{r}\""))], Json(v)))
}
async fn creation_rules_put(
    State(s): State<DataService>,
    headers: HeaderMap,
    Json(input): Json<crate::store::CreationRules>,
) -> std::result::Result<impl IntoResponse, ApiError> {
    let token = bearer(&headers)?;
    let r = control_revision(&headers, "creation-rules")?;
    let r = s
        .run(move |s| s.replace_creation_rules(&token, r, &input))
        .await?;
    Ok((
        [(header::ETAG, format!("\"creation-rules:{r}\""))],
        StatusCode::NO_CONTENT,
    ))
}
