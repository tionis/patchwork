use super::*;
use crate::store::hooks::Input;
pub(super) async fn list(
    State(service): State<DataService>,
    headers: HeaderMap,
    Query(page): Query<AdminPage>,
) -> std::result::Result<Response, ApiError> {
    let token = bearer(&headers)?;
    let (items, next) = service
        .run(move |s| s.hooks(&token, &page.after, page.limit))
        .await?;
    Ok(Json(json!({"items":items,"next_cursor":next})).into_response())
}
pub(super) async fn create(
    State(service): State<DataService>,
    headers: HeaderMap,
    Json(input): Json<Input>,
) -> std::result::Result<Response, ApiError> {
    let token = bearer(&headers)?;
    let value = service
        .run(move |s| s.put_hook(&token, None, None, &input))
        .await?;
    Ok((
        StatusCode::CREATED,
        [(
            header::ETAG,
            format!("\"hook:{}:{}\"", value.id, value.revision),
        )],
        Json(value),
    )
        .into_response())
}
pub(super) async fn get(
    State(service): State<DataService>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> std::result::Result<Response, ApiError> {
    let token = bearer(&headers)?;
    let value = service.run(move |s| s.hook(&token, &id)).await?;
    Ok((
        [(
            header::ETAG,
            format!("\"hook:{}:{}\"", value.id, value.revision),
        )],
        Json(value),
    )
        .into_response())
}
pub(super) async fn put(
    State(service): State<DataService>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<Input>,
) -> std::result::Result<Response, ApiError> {
    let token = bearer(&headers)?;
    let revision = control_revision(&headers, &format!("hook:{id}"))?;
    let value = service
        .run(move |s| s.put_hook(&token, Some(&id), Some(revision), &input))
        .await?;
    Ok((
        [(
            header::ETAG,
            format!("\"hook:{}:{}\"", value.id, value.revision),
        )],
        Json(value),
    )
        .into_response())
}
pub(super) async fn delete(
    State(service): State<DataService>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> std::result::Result<Response, ApiError> {
    let token = bearer(&headers)?;
    let revision = control_revision(&headers, &format!("hook:{id}"))?;
    service
        .run(move |s| s.delete_hook(&token, &id, revision))
        .await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
fn provider_header(headers: &HeaderMap, name: &'static str) -> Result<String> {
    if headers.get_all(name).iter().count() != 1 {
        return Err(Error::Unauthorized);
    }
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .ok_or(Error::Unauthorized)
}
pub(super) async fn ingest(
    State(service): State<DataService>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> std::result::Result<Response, ApiError> {
    let signature = provider_header(&headers, "x-hub-signature-256")?;
    let event = provider_header(&headers, "x-github-event")?;
    let delivery = provider_header(&headers, "x-github-delivery")?;
    let result = service
        .run(move |s| s.ingest_hook(&id, &event, &delivery, &signature, &body))
        .await?;
    if let Some(payload) = result.live {
        service.publish_hook_live(&result.stream_id, &result.name, payload)?;
    } else if result.receipt.outcome == "appended" && result.receipt.deduplicated != Some(true) {
        service.hint(&result.stream_id, &result.name, "records");
    }
    if result.status == 204 {
        Ok(StatusCode::NO_CONTENT.into_response())
    } else {
        Ok((StatusCode::OK, "ok\n").into_response())
    }
}
