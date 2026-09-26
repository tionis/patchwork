use super::*;
use crate::store::kv::{Condition, Event};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Install {
    #[serde(rename = "type")]
    kind: String,
}
pub(super) async fn install(
    State(service): State<DataService>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<Install>,
) -> std::result::Result<Response, ApiError> {
    if input.kind != crate::store::kv::TYPE {
        return Err(Error::Invalid("attachment type").into());
    }
    let token = bearer(&headers)?;
    let id: StreamId = id.parse()?;
    let revision = expected(&headers, &id, "config")?;
    let (attachment, name) = service
        .run(move |s| {
            let a = s.enable_kv(&token, &id, revision)?;
            Ok((a, s.stream(&id)?.name))
        })
        .await?;
    service.hint(&attachment.stream_id, name.as_str(), "config");
    Ok((
        StatusCode::CREATED,
        [(
            header::ETAG,
            format!(
                "\"{}:config:{}\"",
                attachment.stream_id, attachment.config_revision
            ),
        )],
        Json(attachment),
    )
        .into_response())
}
pub(super) async fn attachments(
    State(service): State<DataService>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> std::result::Result<Response, ApiError> {
    let token = bearer(&headers)?;
    let id = id.parse()?;
    Ok(
        Json(json!({"items":service.run(move|s|s.kv_attachments(&token,&id)).await?}))
            .into_response(),
    )
}
fn decode_key(encoded: &str) -> Result<String> {
    if encoded.len() > 1366 {
        return Err(Error::Invalid("KV key encoding"));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| Error::Invalid("KV key encoding"))?;
    if URL_SAFE_NO_PAD.encode(&bytes) != encoded {
        return Err(Error::Invalid("KV key encoding"));
    }
    let key = String::from_utf8(bytes).map_err(|_| Error::Invalid("KV key UTF-8"))?;
    crate::store::kv::validate_key(&key)?;
    Ok(key)
}
fn tag(aid: &str, revision: &str) -> String {
    format!("\"kv:{aid}:{revision}\"")
}
fn condition(headers: &HeaderMap, aid: &str, put: bool) -> Result<Option<Condition>> {
    if headers.get_all(header::IF_MATCH).iter().count() > 1
        || headers.get_all(header::IF_NONE_MATCH).iter().count() > 1
        || (headers.contains_key(header::IF_MATCH) && headers.contains_key(header::IF_NONE_MATCH))
    {
        return Err(Error::Invalid("KV condition"));
    }
    if let Some(value) = headers.get(header::IF_NONE_MATCH) {
        if !put || value != "*" {
            return Err(Error::Invalid("If-None-Match"));
        }
        return Ok(Some(Condition::Absent));
    }
    if let Some(value) = headers.get(header::IF_MATCH) {
        let prefix = format!("\"kv:{aid}:");
        let revision = value
            .to_str()
            .ok()
            .and_then(|v| v.strip_prefix(&prefix))
            .and_then(|v| v.strip_suffix('"'))
            .ok_or(Error::RevisionMismatch)?;
        revision.parse::<Position>()?;
        return Ok(Some(Condition::Revision {
            revision: revision.into(),
        }));
    }
    Ok(None)
}
pub(super) async fn get(
    State(service): State<DataService>,
    Path((id, aid, key)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> std::result::Result<Response, ApiError> {
    let token = bearer(&headers)?;
    let id = id.parse()?;
    let key = decode_key(&key)?;
    let a = aid.clone();
    let value = service
        .run(move |s| s.kv_get(&token, &id, &a, &key))
        .await?;
    Ok((
        [
            (header::CONTENT_TYPE, value.content_type),
            (header::ETAG, tag(&aid, &value.revision)),
            (
                header::HeaderName::from_static("patchwork-applied-position"),
                value.applied_position,
            ),
        ],
        value.bytes,
    )
        .into_response())
}
#[derive(Deserialize)]
pub(super) struct PageQuery {
    #[serde(default)]
    prefix: String,
    cursor: Option<String>,
    #[serde(default = "page_limit")]
    limit: usize,
}
pub(super) async fn list(
    State(service): State<DataService>,
    Path((id, aid)): Path<(String, String)>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> std::result::Result<Response, ApiError> {
    let token = bearer(&headers)?;
    let id = id.parse()?;
    let after = query.cursor.map(|s| decode_key(&s)).transpose()?;
    let mut page = service
        .run(move |s| {
            s.kv_list(
                &token,
                &id,
                &aid,
                &query.prefix,
                after.as_deref(),
                query.limit,
            )
        })
        .await?;
    page.next_cursor = page
        .next_cursor
        .map(|s| URL_SAFE_NO_PAD.encode(s.as_bytes()));
    Ok(Json(page).into_response())
}
pub(super) async fn put(
    State(service): State<DataService>,
    Path((id, aid, key)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> std::result::Result<Response, ApiError> {
    let key = decode_key(&key)?;
    let condition = condition(&headers, &aid, true)?;
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .map(|v| v.to_str())
        .transpose()
        .map_err(|_| Error::Invalid("content type"))?
        .unwrap_or("application/octet-stream");
    let event = Event::put(key, &body, content_type.into(), condition)?;
    mutate(service, id, aid, headers, event).await
}
pub(super) async fn delete(
    State(service): State<DataService>,
    Path((id, aid, key)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> std::result::Result<Response, ApiError> {
    let event = Event::delete(decode_key(&key)?, condition(&headers, &aid, false)?)?;
    mutate(service, id, aid, headers, event).await
}
async fn mutate(
    service: DataService,
    id: String,
    aid: String,
    headers: HeaderMap,
    event: Event,
) -> std::result::Result<Response, ApiError> {
    let token = bearer(&headers)?;
    let sid = id.parse()?;
    let key = headers
        .get("idempotency-key")
        .map(|v| v.to_str().map(str::to_owned))
        .transpose()
        .map_err(|_| Error::Invalid("idempotency key"))?;
    let a = aid.clone();
    let (receipt, name) = service
        .run(move |s| {
            let receipt = s.kv_mutate(&token, &sid, &a, &event, key.as_deref())?;
            Ok((receipt, s.stream(&sid)?.name))
        })
        .await?;
    if receipt.position.is_some() && receipt.deduplicated != Some(true) {
        service.hint(&id, name.as_str(), "records");
    }
    let status = StatusCode::from_u16(receipt.status).map_err(|_| Error::DatabaseFormat)?;
    let mut headers = HeaderMap::new();
    let mut insert = |name: &'static str, value: String| -> Result<()> {
        headers.insert(
            header::HeaderName::from_static(name),
            value.parse().map_err(|_| Error::DatabaseFormat)?,
        );
        Ok(())
    };
    insert(
        "patchwork-applied-position",
        receipt.applied_position.clone(),
    )?;
    if let Some(revision) = &receipt.revision {
        insert("etag", tag(&aid, revision))?;
    }
    if let Some(position) = &receipt.position {
        insert("patchwork-position", position.clone())?;
    }
    if let Some(deduplicated) = receipt.deduplicated {
        insert("patchwork-deduplicated", deduplicated.to_string())?;
    }
    if let Some(expires) = &receipt.idempotency_expires_at {
        insert("patchwork-idempotency-expires-at", expires.clone())?;
    }
    if status == StatusCode::NO_CONTENT {
        Ok((status, headers).into_response())
    } else {
        Ok((status, headers, Json(receipt)).into_response())
    }
}
