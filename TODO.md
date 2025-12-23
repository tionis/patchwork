# ToDo Next
- Migrate away from the forgejo/http request based token/auth management to a locally managed one. For this I want to rely on SSO via OIDC (with SCIM and backchannel logout) with a local sqlite database.
- The database should have point in time recovery, either via a native litestream integration or as a sidecard process in the container

# Ideas for the future (once a database is in place)
- [ ] use new backend to implement url shortening service under $patchwork\_domain/s/...
- [ ] embed a mqtt server using sqlite db for persistence
  - [ ] add token management platform (using some permission system based on namespaces)
  - [ ] add data from mqtt broker to prometheus data
- [ ] replace ntfy endpoint abstraction with https://containrrr.dev/shoutrrr/v0.8/ to allow users to easily add many different notification services
- [ ] look into adding data storage for small scripts (per-user or per-script databases?)
- [ ] add web endpoints for mqtt broker (subscribe to mqtt patterns using SSE, send messages using a simple POST)
