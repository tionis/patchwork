# Notification System

Patchwork now includes a built-in notification system that allows scripts to send notifications through various backends like Matrix, Discord, and more.

## Quick Start

1. **Create a config.yaml file** in your `.patchwork` repository:

```yaml
# Simplified config.yaml structure
tokens:
  "your-secret-token":
    POST:
      - "/_/ntfy"  # Allow notification access
      - "/webhook" # Your other endpoints

ntfy:
  type: matrix
  config:
    access_token: "your_matrix_access_token"
    user: "@bot:matrix.org"
    endpoint: "https://matrix.org"  # optional: specify Matrix server endpoint
    room_id: "!roomid:matrix.org"   # optional: default room for notifications
```

2. **Send a notification**:

```bash
# Simple text notification
curl -X POST "https://patchwork.example.com/u/yourusername/_/ntfy" \
  -H "Authorization: Bearer your-secret-token" \
  -d "Hello from patchwork!"

# JSON notification with title
curl -X POST "https://patchwork.example.com/u/yourusername/_/ntfy" \
  -H "Authorization: Bearer your-secret-token" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Script Alert",
    "content": "Something important happened!",
    "type": "markdown"
  }'
```

## Configuration

Create a `config.yaml` file in your `.patchwork` repository:

```yaml
tokens:
  "my-token":
    POST:
      - "/webhook"
      - "/_/ntfy"  # Add notification access

ntfy:
  type: matrix
  config:
    access_token: "your_matrix_token"
    user: "@bot:matrix.org"
```

## Notification Backends

### Matrix

Send notifications to Matrix rooms/channels:

```yaml
ntfy:
  type: matrix
  config:
    access_token: "your_matrix_access_token"
    user: "@bot:matrix.org"
    endpoint: "https://matrix.org"  # Matrix server endpoint
    room_id: "!roomid:matrix.org"   # optional: default room for notifications
```

**Getting a Matrix Access Token:**
1. Log in to your Matrix account (Element, etc.)
2. Go to Settings → Help & About → Advanced → Access Token
3. Copy the access token

**Custom Matrix Servers:**
If you're using a custom Matrix server or a username with a custom domain (like `@notify:example.com`), specify the Matrix server endpoint explicitly:

```yaml
ntfy:
  type: matrix
  config:
    access_token: "your_matrix_access_token"
    user: "@notify:example.com"
    endpoint: "https://matrix.example.com"  # Custom Matrix server
```

**Room Configuration:**
The `room_id` field allows you to specify a default room for notifications. If not specified, notifications will be sent to the user's own DM. You can also override the room per notification using the `room` parameter in the request.

```yaml
ntfy:
  type: matrix
  config:
    access_token: "your_matrix_access_token"
    user: "@bot:matrix.org"
    room_id: "!notificationroom:matrix.org"  # Default room for all notifications
```

Room priority order:
1. `room` parameter in the notification request (highest priority)
2. `room_id` in the configuration
3. User's DM room (fallback)

## API Reference

### Endpoint
```
POST /u/{username}/_/ntfy
GET  /u/{username}/_/ntfy
```

### Authentication
Requires a valid token with `POST` permission for `/_/ntfy`.

### Request Formats

#### JSON POST
```json
{
  "type": "markdown",
  "title": "Alert Title", 
  "content": "Message **content** here",
  "room": "optional-room-id"
}
```

#### Form POST
```bash
curl -X POST "https://patchwork.example.com/u/username/_/ntfy" \
  -H "Authorization: Bearer token" \
  -d "type=plain&title=Alert&content=Message"
```

#### GET with Query Parameters
```bash
curl "https://patchwork.example.com/u/username/_/ntfy?token=your-token&title=Alert&content=Message"
```

#### Plain Text POST
```bash
curl -X POST "https://patchwork.example.com/u/username/_/ntfy" \
  -H "Authorization: Bearer token" \
  -H "Content-Type: text/plain" \
  -d "This is a plain text message"
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `type` | string | Message format: `plain`, `markdown`, `html` (default: `plain`) |
| `title` | string | Message title (optional) |
| `content` | string | Message content (required) |
| `room` | string | Target room/channel (optional, backend-specific) |

Alternative parameter names:
- `content` can also be `body` or `message`

### Response

Success response:
```json
{
  "status": "sent",
  "type": "plain"
}
```

## Use Cases

### Script Monitoring
```bash
#!/bin/bash
# Send notification when backup completes
backup_script.sh
if [ $? -eq 0 ]; then
  curl -X POST "https://patchwork.example.com/u/admin/_/ntfy" \
    -H "Authorization: Bearer $PATCHWORK_TOKEN" \
    -d "type=plain&title=Backup Complete&content=Daily backup finished successfully"
fi
```

### Error Alerts
```bash
#!/bin/bash
# Send notification on service failure
if ! systemctl is-active myservice; then
  curl -X POST "https://patchwork.example.com/u/admin/_/ntfy" \
    -H "Authorization: Bearer $PATCHWORK_TOKEN" \
    -d "type=markdown&title=⚠️ Service Alert&content=**myservice** is down!"
fi
```

### Room-Specific Notifications
```bash
#!/bin/bash
# Send notification to specific Matrix room (overrides config default)
curl -X POST "https://patchwork.example.com/u/admin/_/ntfy" \
  -H "Authorization: Bearer $PATCHWORK_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "markdown",
    "title": "Critical Alert",
    "content": "Database backup **failed**! Check logs immediately.",
    "room": "!alerts:matrix.org"
  }'
```

### CI/CD Integration
```yaml
# GitHub Actions example
- name: Notify on deploy
  run: |
    curl -X POST "https://patchwork.example.com/u/ci/_/ntfy" \
      -H "Authorization: Bearer ${{ secrets.PATCHWORK_TOKEN }}" \
      -H "Content-Type: application/json" \
      -d '{
        "type": "markdown",
        "title": "🚀 Deploy Success",
        "content": "Application deployed to **production**\nCommit: `${{ github.sha }}`"
      }'
```
