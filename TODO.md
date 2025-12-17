# ToDo Next
- [ ] Migrate token handling to an encrypted-at-rest model (Option 2) to ensure tokens in the config cannot be used if leaked, while maintaining O(1) lookup performance on the hot path.
  - [ ] Implement a simple, well-documented API endpoint to "mint" (encrypt) tokens using the server's secret.
  - [ ] Update config loading logic to decrypt tokens in `config.yaml` upon fetch/refresh.
  - [ ] Ensure request authentication remains a fast memory lookup against the decrypted tokens.


# Ideas for the future
> Some of the feature below might be better handled by a workflow engine or serverless functions platform
- [ ] migrate away from quasi stateless forgejo backend to a stateful sqlite one, that auto restored litestream backup on startup and stream litestream backups to target location during operation
- [ ] use new backend to implement url shortening service under $patchwork_domain/s/...
- [ ] add oidc integration for auth to manage data, tokens etc
- [ ] embed a mqtt server using sqlite db for persistence
  - [ ] add token management platform (using some permission system based on namespaces)
  - [ ] add data from mqtt broker to prometheus data
- [ ] replace ntfy endpoint abstraction with https://containrrr.dev/shoutrrr/v0.8/ to allow users to easily add many different notification services
- [ ] look into adding data storage for small scripts
- [ ] add web endpoints for mqtt broker (subscribe to mqtt patterns using SSE, send messages using a simple POST)
- [ ] look into optional integration into a mosquitto-logger service (idea would be to integrate it, but make it optional and allow users to start the logger without the rest of the server)
- [ ] think about integrating simple file sharing using s3 backend with pre-signed urls etc (or direct rclone integration instead)