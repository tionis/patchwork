use super::*;
use axum::response::sse::{Event, KeepAlive, Sse};
use std::{collections::HashMap, convert::Infallible, time::Duration};
use tokio::sync::{OwnedSemaphorePermit, broadcast};
#[derive(Clone)]
pub(super) struct Hint {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub revision: u64,
}
#[derive(Clone)]
struct LiveRecord {
    sequence: u64,
    payload: Arc<Vec<u8>>,
    content_type: String,
}
pub(super) struct Hub {
    epoch: String,
    revision: u64,
    hints: broadcast::Sender<Hint>,
    live: HashMap<String, (u64, broadcast::Sender<LiveRecord>)>,
}
impl Hub {
    pub fn new() -> Self {
        Self {
            epoch: uuid::Uuid::new_v4().to_string(),
            revision: 0,
            hints: broadcast::channel(256).0,
            live: HashMap::new(),
        }
    }
    fn hint(&mut self, id: String, name: String, kind: &str) {
        self.revision = self.revision.saturating_add(1);
        let _ = self.hints.send(Hint {
            id,
            name,
            kind: kind.into(),
            revision: self.revision,
        });
    }
}
fn event(kind: &str, value: Value) -> Event {
    Event::default().event(kind).data(value.to_string())
}
fn failure(error: ApiError) -> Event {
    let code = match error.0 {
        Error::HistoryLost => "history_lost",
        Error::NotFound => "deleted",
        Error::Unauthorized | Error::Forbidden => "unauthorized",
        _ => "unavailable",
    };
    event(code, json!({"code":code}))
}
fn sse(
    stream: impl futures_util::Stream<Item = std::result::Result<Event, Infallible>> + Send + 'static,
) -> Response {
    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
        .into_response()
}
impl DataService {
    pub(super) fn hint(&self, id: &str, name: &str, kind: &str) {
        if let Ok(mut hub) = self.hub.lock() {
            hub.hint(id.into(), name.into(), kind);
        }
    }
}
#[derive(Deserialize)]
pub(super) struct FollowQuery {
    from: Option<String>,
}
struct Follow {
    service: DataService,
    token: String,
    id: String,
    cursor: Position,
    ready: Option<Event>,
    closed: bool,
    _permit: OwnedSemaphorePermit,
}
pub(super) async fn follow(
    State(s): State<DataService>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Query(query): Query<FollowQuery>,
) -> std::result::Result<Response, ApiError> {
    let token = bearer(&headers)?;
    let stream_id: StreamId = id.parse()?;
    let resume = headers
        .get("last-event-id")
        .map(|v| v.to_str().map(str::to_owned))
        .transpose()
        .map_err(|_| Error::Invalid("Last-Event-ID"))?;
    let resume = resume
        .map(|r| {
            r.strip_prefix(&format!("{id}:"))
                .ok_or(Error::Invalid("Last-Event-ID"))
                .and_then(|v| v.parse::<Position>())
        })
        .transpose()?;
    let from = query
        .from
        .as_deref()
        .map(str::parse::<Position>)
        .transpose()?;
    if from.is_some() && resume.is_some() && from != resume {
        return Err(Error::Invalid("conflicting resume cursor").into());
    }
    let cursor = from.or(resume).ok_or(Error::Invalid("from required"))?;
    let permit = s
        .subscriptions
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError(Error::Busy))?;
    let bearer = token.clone();
    let page = s
        .run(move |s| {
            s.authenticate(&bearer)?;
            let st = s.stream(&stream_id)?;
            s.authorized(&bearer, Action::RecordRead, Some(&st.id), &st.name, |s| {
                s.read(&st.id, cursor, 1, 1)
            })
        })
        .await?;
    let ready = event(
        "ready",
        json!({"stream_id":id,"head":page.head.to_string(),"tail":page.tail.to_string()}),
    );
    Ok(sse(futures_util::stream::unfold(
        Follow {
            service: s,
            token,
            id,
            cursor,
            ready: Some(ready),
            closed: false,
            _permit: permit,
        },
        |mut state| async move {
            if state.closed {
                return None;
            }
            if let Some(ready) = state.ready.take() {
                return Some((Ok(ready), state));
            }
            loop {
                let token = state.token.clone();
                let id = state.id.clone();
                let cursor = state.cursor;
                let result = state
                    .service
                    .run(move |s| {
                        let st = stream(s, &token, &id)?;
                        s.authorized(&token, Action::RecordRead, Some(&st.id), &st.name, |s| {
                            s.read(&st.id, cursor, 1, crate::store::MAX_RECORD_BYTES)
                        })
                    })
                    .await;
                match result {
                    Err(e) => {
                        state.closed = true;
                        return Some((Ok(failure(e)), state));
                    }
                    Ok(page) => {
                        if let Some(record) = page.records.into_iter().next() {
                            state.cursor = page.next_position;
                            let value = match record_json(record) {
                                Ok(value) => value,
                                Err(error) => {
                                    state.closed = true;
                                    return Some((Ok(failure(ApiError(error))), state));
                                }
                            };
                            let ev =
                                event("record", value).id(format!("{}:{}", state.id, state.cursor));
                            return Some((Ok(ev), state));
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        },
    )))
}
struct Live {
    service: DataService,
    token: String,
    id: String,
    receiver: broadcast::Receiver<LiveRecord>,
    ready: Option<Event>,
    closed: bool,
    _permit: OwnedSemaphorePermit,
}
pub(super) async fn live(
    State(s): State<DataService>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> std::result::Result<Response, ApiError> {
    let token = bearer(&headers)?;
    let permit = s
        .subscriptions
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError(Error::Busy))?;
    let bearer = token.clone();
    let sid = id.clone();
    s.run(move |s| {
        let st = stream(s, &bearer, &sid)?;
        s.authorized(
            &bearer,
            Action::RecordSubscribe,
            Some(&st.id),
            &st.name,
            |s| {
                if s.config(&st.id)?.value.retention != crate::model::Retention::None {
                    return Err(Error::StreamMode);
                }
                Ok(())
            },
        )
    })
    .await?;
    let (epoch, sequence, receiver) = {
        let mut hub = s.hub.lock().map_err(|_| ApiError(Error::Busy))?;
        let epoch = hub.epoch.clone();
        let entry = hub
            .live
            .entry(id.clone())
            .or_insert_with(|| (0, broadcast::channel(8).0));
        (epoch, entry.0, entry.1.subscribe())
    };
    let ready = event(
        "ready",
        json!({"stream_id":id,"epoch":epoch,"sequence":sequence.to_string()}),
    );
    Ok(sse(futures_util::stream::unfold(
        Live {
            service: s,
            token,
            id,
            receiver,
            ready: Some(ready),
            closed: false,
            _permit: permit,
        },
        |mut state| async move {
            if state.closed {
                return None;
            }
            if let Some(ready) = state.ready.take() {
                return Some((Ok(ready), state));
            }
            loop {
                let item =
                    tokio::time::timeout(Duration::from_secs(1), state.receiver.recv()).await;
                let token = state.token.clone();
                let id = state.id.clone();
                if let Err(e) = state
                    .service
                    .run(move |s| {
                        let st = stream(s, &token, &id)?;
                        s.authorized(
                            &token,
                            Action::RecordSubscribe,
                            Some(&st.id),
                            &st.name,
                            |_| Ok(()),
                        )
                    })
                    .await
                {
                    state.closed = true;
                    return Some((Ok(failure(e)), state));
                }
                match item {
                    Ok(Ok(record)) => {
                        return Some((
                            Ok(event(
                                "record",
                                json!({"sequence":record.sequence.to_string(),"data_base64":STANDARD.encode(record.payload.as_slice()),"object_refs":[],"content_type":record.content_type}),
                            )),
                            state,
                        ));
                    }
                    Ok(Err(_)) => {
                        state.closed = true;
                        return Some((Ok(event("lagged", json!({"code":"lagged"}))), state));
                    }
                    Err(_) => {}
                }
            }
        },
    )))
}
pub(super) async fn publish(
    s: DataService,
    id: String,
    headers: HeaderMap,
    body: Bytes,
) -> std::result::Result<Response, ApiError> {
    let token = bearer(&headers)?;
    let sid: StreamId = id.parse()?;
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .map(|v| v.to_str())
        .transpose()
        .map_err(|_| Error::Invalid("content type"))?
        .unwrap_or("application/octet-stream")
        .to_owned();
    if headers.contains_key("patchwork-object-refs") {
        return Err(Error::Invalid("object links unavailable").into());
    }
    let key = headers
        .get("idempotency-key")
        .map(|v| v.to_str().map(str::to_owned))
        .transpose()
        .map_err(|_| Error::Invalid("idempotency key"))?;
    let ct = content_type.clone();
    let (name, receipt, live) = s
        .run(move |s| {
            s.authenticate(&token)?;
            let stream = s.stream(&sid)?;
            let mode = s.config(&sid)?.value.retention;
            if mode == crate::model::Retention::None {
                if key.is_some() {
                    return Err(Error::Invalid("live idempotency unavailable"));
                }
                let candidate = s.prepare_live(&token, &sid, &body, &ct)?;
                Ok((stream.name.as_str().to_owned(), None, candidate))
            } else {
                Ok((
                    stream.name.as_str().to_owned(),
                    Some(s.append_authorized(&token, &sid, &body, &ct, key.as_deref())?),
                    None,
                ))
            }
        })
        .await?;
    if let Some(receipt) = receipt {
        if receipt.outcome == "appended" && receipt.deduplicated != Some(true) {
            s.hint(&id, &name, "records");
        }
        let status = if receipt.deduplicated == Some(true) || receipt.outcome == "dropped" {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        };
        return Ok((status, Json(receipt)).into_response());
    }
    if let Some(payload) = live {
        let (epoch, sequence) = {
            let mut hub = s.hub.lock().map_err(|_| ApiError(Error::Busy))?;
            let epoch = hub.epoch.clone();
            let entry = hub
                .live
                .entry(id.clone())
                .or_insert_with(|| (0, broadcast::channel(8).0));
            entry.0 = entry.0.checked_add(1).ok_or(Error::Exhausted)?;
            let sequence = entry.0;
            let _ = entry.1.send(LiveRecord {
                sequence,
                payload: Arc::new(payload),
                content_type,
            });
            hub.hint(id.clone(), name, "records");
            (epoch, sequence)
        };
        Ok((StatusCode::ACCEPTED,Json(json!({"outcome":"published","stream_id":id,"epoch":epoch,"sequence":sequence.to_string()}))).into_response())
    } else {
        Ok(Json(json!({"outcome":"dropped","stream_id":id})).into_response())
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WatchInput {
    stream_ids: Option<Vec<String>>,
    prefix: Option<String>,
}
struct Watch {
    service: DataService,
    token: String,
    explicit: Vec<(StreamId, StreamName)>,
    prefix: Option<String>,
    receiver: broadcast::Receiver<Hint>,
    ready: Option<Event>,
    closed: bool,
    _permit: OwnedSemaphorePermit,
}
async fn check_watch(
    service: &DataService,
    token: String,
    explicit: Vec<(StreamId, StreamName)>,
    prefix: Option<String>,
) -> std::result::Result<(), ApiError> {
    service
        .run(move |s| {
            if let Some(prefix) = prefix {
                s.prefix_permission(&token, Action::StreamWatch, &prefix)
            } else {
                for (id, name) in explicit {
                    s.watch_permission(&token, &id, &name)?;
                }
                Ok(())
            }
        })
        .await
}
pub(super) async fn watch(
    State(s): State<DataService>,
    headers: HeaderMap,
    Json(input): Json<WatchInput>,
) -> std::result::Result<Response, ApiError> {
    let token = bearer(&headers)?;
    if input.stream_ids.is_some() == input.prefix.is_some()
        || input
            .stream_ids
            .as_ref()
            .is_some_and(|v| v.is_empty() || v.len() > 256)
    {
        return Err(Error::Invalid("watch selector").into());
    }
    let permit = s
        .subscriptions
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError(Error::Busy))?;
    // Subscribe before authorization/state assembly so concurrent changes queue.
    let (revision, receiver) = {
        let hub = s.hub.lock().map_err(|_| ApiError(Error::Busy))?;
        (hub.revision, hub.hints.subscribe())
    };
    let bearer = token.clone();
    let ids = input.stream_ids.unwrap_or_default();
    let explicit = s
        .run(move |s| {
            s.authenticate(&bearer)?;
            ids.iter()
                .map(|id| {
                    let st = s.stream(&id.parse()?)?;
                    Ok((st.id, st.name))
                })
                .collect::<Result<Vec<_>>>()
        })
        .await?;
    check_watch(&s, token.clone(), explicit.clone(), input.prefix.clone()).await?;
    let ready = event(
        "ready",
        json!({"watch_id":uuid::Uuid::new_v4().to_string(),"revision":revision.to_string()}),
    );
    Ok(sse(futures_util::stream::unfold(
        Watch {
            service: s,
            token,
            explicit,
            prefix: input.prefix,
            receiver,
            ready: Some(ready),
            closed: false,
            _permit: permit,
        },
        |mut state| async move {
            if state.closed {
                return None;
            }
            if let Some(ready) = state.ready.take() {
                return Some((Ok(ready), state));
            }
            loop {
                let item =
                    tokio::time::timeout(Duration::from_secs(1), state.receiver.recv()).await;
                if let Err(e) = check_watch(
                    &state.service,
                    state.token.clone(),
                    state.explicit.clone(),
                    state.prefix.clone(),
                )
                .await
                {
                    state.closed = true;
                    return Some((Ok(failure(e)), state));
                }
                match item {
                    Ok(Ok(hint)) => {
                        let selected = if let Some(prefix) = &state.prefix {
                            hint.name.starts_with(prefix)
                        } else {
                            state.explicit.iter().any(|(id, _)| id.as_str() == hint.id)
                        };
                        if !selected {
                            continue;
                        }
                        let kind = if matches!(hint.kind.as_str(), "created" | "deleted") {
                            hint.kind.as_str()
                        } else {
                            "changed"
                        };
                        let mut value =
                            json!({"stream_id":hint.id,"revision":hint.revision.to_string()});
                        if kind == "changed" {
                            value["kinds"] = json!([hint.kind]);
                        }
                        return Some((Ok(event(kind, value)), state));
                    }
                    Ok(Err(_)) => {
                        state.closed = true;
                        return Some((
                            Ok(event("resync_required", json!({"code":"resync_required"}))),
                            state,
                        ));
                    }
                    Err(_) => {}
                }
            }
        },
    )))
}

pub(super) async fn append_named(
    State(s): State<DataService>,
    Query(query): Query<ResolveInput>,
    headers: HeaderMap,
    body: Bytes,
) -> std::result::Result<Response, ApiError> {
    let token = bearer(&headers)?;
    let name: StreamName = query.name.parse()?;
    if headers.contains_key("patchwork-object-refs") {
        return Err(Error::Invalid("object links unavailable").into());
    }
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .map(|v| v.to_str())
        .transpose()
        .map_err(|_| Error::Invalid("content type"))?
        .unwrap_or("application/octet-stream")
        .to_owned();
    let key = headers
        .get("idempotency-key")
        .map(|v| v.to_str().map(str::to_owned))
        .transpose()
        .map_err(|_| Error::Invalid("idempotency key"))?;
    let ct = content_type.clone();
    let n = name.clone();
    let result = s
        .run(move |s| s.append_named(&token, &n, &body, &ct, key.as_deref()))
        .await?;
    match result {
        crate::store::NameAppend::Dropped => {
            Ok(Json(json!({"outcome":"dropped","name":name.as_str()})).into_response())
        }
        crate::store::NameAppend::Retained { receipt, created } => {
            if created {
                s.hint(&receipt.stream_id, name.as_str(), "created");
            }
            if receipt.deduplicated != Some(true) && receipt.outcome == "appended" {
                s.hint(&receipt.stream_id, name.as_str(), "records");
            }
            let status = if receipt.deduplicated == Some(true) || receipt.outcome == "dropped" {
                StatusCode::OK
            } else {
                StatusCode::CREATED
            };
            Ok((status, Json(receipt)).into_response())
        }
        crate::store::NameAppend::Live {
            stream,
            payload,
            created,
        } => {
            if created {
                s.hint(stream.id.as_str(), name.as_str(), "created");
            }
            let (epoch, sequence) = {
                let mut hub = s.hub.lock().map_err(|_| ApiError(Error::Busy))?;
                let epoch = hub.epoch.clone();
                let entry = hub
                    .live
                    .entry(stream.id.as_str().into())
                    .or_insert_with(|| (0, broadcast::channel(8).0));
                entry.0 = entry.0.checked_add(1).ok_or(Error::Exhausted)?;
                let sequence = entry.0;
                let _ = entry.1.send(LiveRecord {
                    sequence,
                    payload: Arc::new(payload),
                    content_type,
                });
                hub.hint(stream.id.as_str().into(), name.as_str().into(), "records");
                (epoch, sequence)
            };
            Ok((StatusCode::ACCEPTED,Json(json!({"outcome":"published","stream_id":stream.id.as_str(),"epoch":epoch,"sequence":sequence.to_string()}))).into_response())
        }
    }
}
