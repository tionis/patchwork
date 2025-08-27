# Configuration Guide

## Overview

Patchwork uses a unified `config.yaml` configuration file that includes both authentication and notification settings. This file is placed in the `.patchwork` repository for each user or organization.

## Configuration File Structure

### config.yaml Format

```yaml
# Tokens are directly at the root level
tokens:
  "my_token_name":
    is_admin: false
    POST: 
      - "/projects/*/data"  # Can POST to any project's data endpoint
      - "/_/ntfy"          # Can send notifications
    GET: 
      - "/projects/myproject/*"  # Can GET from all paths under myproject
      - "!/projects/myproject/secret/*" # But nothing in my secret project
    huproxy:
      - "*.example.com:*"  # Can access specific hosts via HuProxy
      - "localhost:*"
  
  "restricted_token":
    is_admin: false
    POST: []  # No POST access
    GET: 
      - "*"  # Can GET from all subpaths in this namespace
  
  "webhook_token":
    is_admin: false
    POST: 
      - "/webhooks/*"  # Can POST to any webhook endpoint
      - "/_/ntfy"      # Can send notifications
    GET: 
      - "/status"  # Can only GET the status endpoint
  
  "admin_token":
    is_admin: true
    POST: ["*"]
    GET: ["*"]

# Optional: Configure notification backend
ntfy:
  type: matrix
  config:
    access_token: "your_matrix_access_token"
    user: "@bot:matrix.org"
    endpoint: "https://matrix.org"  # optional: Matrix server endpoint
    room_id: "!roomid:matrix.org"   # optional: specific room ID
```

### Key Features

1. **Single Configuration File**: Everything is in one `config.yaml` file
2. **Simplified Structure**: Tokens are directly under the root level
3. **Unified Management**: Authentication, permissions, HuProxy access, and notifications in one place
4. **Glob Pattern Support**: Use OpenSSH-style patterns for fine-grained access control

### Permission Patterns

- Empty array (`[]`) denies all access for that method
- `"*"` allows access to all subpaths
- Specific glob patterns like `projects/*/data` allow fine-grained control
- Negation patterns like `!secret/*` can exclude specific paths
- Admin tokens (`is_admin: true`) have access to administrative endpoints

## Repository Setup

1. **Create `.patchwork` repository**: Each user/organization creates a repository named `.patchwork`
2. **Add `config.yaml`**: Place the configuration file in the repository root
3. **Grant access**: Give the special `patchwork` user read access to the `.patchwork` repository
4. **Caching**: The patchwork server pulls and caches these configuration files as needed

Example repository structure:
```
user/.patchwork/
├── config.yaml
└── README.md (optional)
```

## Notification System

### Notification Endpoint

The notification endpoint is available at:
```
POST /u/{username}/_/ntfy
GET  /u/{username}/_/ntfy
```

### Authentication

The endpoint requires authentication using the existing token system. Make sure your tokens have `POST` permission for `/_/ntfy`:

```yaml
tokens:
  "my_token":
    POST:
      - "/_/ntfy"  # Required for notification access
```

### Usage Examples

#### JSON POST Request
```bash
curl -X POST "https://patchwork.example.com/u/username/_/ntfy" \
  -H "Authorization: Bearer your-token" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "markdown",
    "title": "Alert", 
    "content": "Something **important** happened!"
  }'
```

#### Form POST Request
```bash
curl -X POST "https://patchwork.example.com/u/username/_/ntfy" \
  -H "Authorization: Bearer your-token" \
  -d "type=plain&title=Alert&content=Something happened!"
```

#### GET Request with Query Parameters
```bash
curl "https://patchwork.example.com/u/username/_/ntfy?token=your-token&type=plain&title=Alert&content=Something%20happened!"
```

#### Plain Text POST
```bash
curl -X POST "https://patchwork.example.com/u/username/_/ntfy" \
  -H "Authorization: Bearer your-token" \
  -H "Content-Type: text/plain" \
  -d "This is a plain text notification"
```

### Message Types

- `plain` - Plain text message (default)
- `markdown` - Markdown formatted message 
- `html` - HTML formatted message

### Parameters

- `type` - Message type (plain, markdown, html)
- `title` - Message title (optional)
- `content` - Message content (required, can also use `body` or `message`)
- `room` - Target room/channel (optional, backend-specific)

## Notification Backends

### Matrix

Configuration for Matrix notifications:

```yaml
ntfy:
  type: matrix
  config:
    access_token: "your_matrix_access_token"
    user: "@bot:matrix.org"
    endpoint: "https://matrix.org"  # optional
    room_id: "!roomid:matrix.org"   # optional
```

To get a Matrix access token:
1. Log in to your Matrix account
2. Go to Settings → Help & About → Advanced → Access Token
3. Copy the access token

## HuProxy Configuration

For HuProxy access, configure tokens in the `huproxy` field of your token definition:

```yaml
tokens:
  "production_ssh_token":
    huproxy:
      - "*.production.com:*"
  "development_access":
    huproxy:
      - "*.dev.com:*"
      - "localhost:*"
  "backup_script_token":
    huproxy:
      - "backup.example.com:22"
```

Users can then access HuProxy endpoints using these tokens:
```bash
curl -H "Authorization: Bearer production_ssh_token" \
  https://patchwork.example.com/huproxy/alice/production.com/22
```

## Server Environment Variables

Server configuration is provided via environment variables:
- `FORGEJO_URL` - Forgejo/Gitea instance URL (default: https://forge.tionis.dev)
- `FORGEJO_TOKEN` - Forgejo/Gitea API token for accessing repositories
- `ACL_TTL` - Cache TTL for configuration files (default: 5m)
- `SECRET_KEY` - Server secret key for HMAC generation (required for hooks)
- `LOG_LEVEL` - Logging level (DEBUG, INFO, WARN, ERROR)
- `LOG_SOURCE` - Add source information to logs (true/false)

## Benefits of Unified Configuration

- **Simplicity**: One file, one format
- **Clarity**: No confusion about which file to use
- **Clean codebase**: No backward compatibility code to maintain
- **Better errors**: Missing config files properly return errors
- **Centralized management**: All settings in one place
