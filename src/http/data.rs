//! Authenticated prototype routes. A bounded blocking boundary keeps SQLite and
//! cryptographic work off Tokio workers; no unbounded writer task queue.
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
}
impl DataService {
    pub fn new(store: Store) -> Self {
        Self {
            store: Arc::new(Mutex::new(store)),
            admission: Arc::new(Semaphore::new(32)),
        }
    }
    async fn run<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&mut Store) -> Result<T> + Send + 'static,
    ) -> std::result::Result<T, ApiError> {
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
        .route("/auth/challenges", post(challenge))
        .route("/auth/exchange", post(exchange))
        .route("/credentials", post(mint))
        .route("/credentials/{id}", axum::routing::delete(revoke))
        .route("/streams", post(create))
        .route("/streams/resolve", get(resolve))
        .route("/streams/{id}", get(inspect).delete(delete))
        .route("/streams/{id}/config", get(config_get).put(config_put))
        .route(
            "/streams/{id}/metadata",
            get(metadata_get).put(metadata_put),
        )
        .route("/streams/{id}/records", get(read).post(append))
        .route("/streams/{id}/records/{position}", get(raw))
        .layer(DefaultBodyLimit::max(crate::store::MAX_RECORD_BYTES))
        .layer(axum::middleware::map_response(normalize_response))
        .with_state(service)
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
            Error::Conflict | Error::PositionAhead | Error::StreamMode => {
                (StatusCode::CONFLICT, "conflict")
            }
            Error::RevisionMismatch => (StatusCode::PRECONDITION_FAILED, "revision_mismatch"),
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
    json!({"id":s.id.as_str(),"name":s.name.as_str(),"head":s.head.to_string(),"tail":s.tail.to_string(),"config_revision":s.config_revision.to_string(),"metadata_revision":s.metadata_revision.to_string()})
}
fn stream(store: &Store, token: &str, id: &str) -> Result<Stream> {
    store.authenticate(token)?;
    store.stream(&id.parse()?)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChallengeInput {
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
            s.run(move |s| s.mint(&token, &input.grants, input.lifetime_seconds))
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
    config: StreamConfig,
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
    Ok((
        StatusCode::CREATED,
        Json(
            s.run(move |s| {
                s.authorized(&token, Action::StreamCreate, None, &name, |s| {
                    s.create_stream_with(&name, &input.config, &metadata)
                })
                .map(descriptor)
            })
            .await?,
        ),
    ))
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
    s.run(move |s| {
        let st = stream(s, &token, id.as_str())?;
        s.authorized(&token, Action::StreamDelete, Some(&id), &st.name, |s| {
            s.delete_stream(&id, revision)
        })
    })
    .await?;
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
    let tag = s
        .run(move |s| {
            let st = stream(s, &token, id.as_str())?;
            s.authorized(&token, Action::ConfigWrite, Some(&id), &st.name, |s| {
                s.replace_config(&id, rev, &config)
                    .map(|r| etag(&id, "config", r))
            })
        })
        .await?;
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
    let tag = s
        .run(move |s| {
            let st = stream(s, &token, id.as_str())?;
            s.authorized(&token, Action::MetadataWrite, Some(&id), &st.name, |s| {
                s.replace_metadata(&id, rev, &metadata)
                    .map(|r| etag(&id, "metadata", r))
            })
        })
        .await?;
    Ok(([(header::ETAG, tag)], StatusCode::NO_CONTENT))
}
async fn append(
    State(s): State<DataService>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> std::result::Result<impl IntoResponse, ApiError> {
    if headers.contains_key("idempotency-key") {
        return Err(Error::Invalid("idempotency unavailable").into());
    }
    let token = bearer(&headers)?;
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .map(|v| v.to_str())
        .transpose()
        .map_err(|_| Error::Invalid("content type"))?
        .unwrap_or("application/octet-stream")
        .to_owned();
    Ok((StatusCode::CREATED,Json(s.run(move|s|{let st=stream(s,&token,&id)?;let p=s.authorized(&token,Action::RecordAppend,Some(&st.id),&st.name,|s|s.append(&st.id,&body,&content_type))?;Ok(json!({"outcome":"appended","stream_id":id,"position":p.to_string(),"next_position":p.next()?.to_string()}))}).await?)))
}
#[derive(Deserialize)]
struct ReadInput {
    #[serde(default = "zero")]
    from: String,
    #[serde(default = "page_limit")]
    limit: usize,
    #[serde(default = "byte_limit")]
    max_bytes: usize,
}
fn zero() -> String {
    "0".into()
}
fn page_limit() -> usize {
    100
}
fn byte_limit() -> usize {
    1024 * 1024
}
async fn read(
    State(s): State<DataService>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Query(input): Query<ReadInput>,
) -> std::result::Result<impl IntoResponse, ApiError> {
    let token = bearer(&headers)?;
    let from: Position = input.from.parse()?;
    Ok(Json(s.run(move|s|{let st=stream(s,&token,&id)?;let page=s.authorized(&token,Action::RecordRead,Some(&st.id),&st.name,|s|s.read(&st.id,from,input.limit,input.max_bytes))?;Ok(json!({"head":page.head.to_string(),"tail":page.tail.to_string(),"next_position":page.next_position.to_string(),"records":page.records.into_iter().map(|r|json!({"position":r.position.to_string(),"payload_base64":STANDARD.encode(r.payload),"content_type":r.content_type,"accepted_at_ms":r.accepted_at_ms})).collect::<Vec<_>>()}))}).await?))
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
            _ => "request_failed",
        };
        let mut result=(status,Json(json!({"type":"about:blank","title":code,"status":status.as_u16(),"code":code,"request_id":uuid::Uuid::new_v4().to_string()}))).into_response();
        result.headers_mut().insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/problem+json"),
        );
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
