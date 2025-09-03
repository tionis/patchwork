- [ ] migrate away from quasi stateless forgejo backend to a stateful sqlite one, that auto restored litestream backup on startup and stream litestream backups to target location during operation
- [ ] use new backend to implement url shortening service under $patchwork_domain/s/...
- [ ] add oidc integration for auth to manage data, tokens etc
  - [ ] should also include a SCIM server to receive instant group updates
- [ ] embed a mqtt server using sqlite db for persistence
      I found two main mqtt project so far:
        https://github.com/wind-c/comqtt
        https://github.com/mochi-mqtt/server
  - [ ] add token management platform (using some permission system based on namespaces)
  - [ ] add data from mqtt broker to prometheus data
- [ ] replace ntfy endpoint abstraction with https://containrrr.dev/shoutrrr/v0.8/ to allow users to easily add many different notification services
- [ ] look into adding data storage for small scripts
- [ ] add web endpoints for mqtt broker (subscribe to mqtt patterns using SSE, send messages using a simple POST)
- [ ] look into optional integration into a mosquitto-logger service (idea would be to integrate it, but make it optional and allow users to start the logger without the rest of the server)
- [ ] think about integrating simple file sharing using s3 backend with pre-signed urls etc (or direct rclone integration instead)
