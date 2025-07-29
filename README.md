# Patchwork

A simple communication backend for scripts and other small applications.
Patchwork enables IFTTT-type applications by providing infinite HTTP endpoints
that serve as a multi-process, multi-consumer (MPMC) queue.

## Features

- **Channel-based Communication**: HTTP endpoints that act as communication channels
- **Multiple Namespaces**: Public (`/p`), hooks (`/h`, `/r`), user (`/u/{username}`) namespaces
- **WebSocket Tunneling**: SSH/TCP tunneling via HuProxy integration
- **Token-based Authentication**: Forgejo-integrated ACL system with caching
- **Administrative API**: Cache invalidation and user management endpoints

## Authentication

Patchwork uses a Forgejo-integrated authentication system. Each user maintains an `auth.yaml` file in their `.patchwork` repository to define access tokens and permissions.

See [AUTHENTICATION.md](AUTHENTICATION.md) for detailed configuration and usage information.

## What does it do?

Patchwork provi### SSH over WebSocket Tunneling (huproxy) Example

The huproxy endpoint provides WebSocket tunneling for SSH and other TCP protocols, based on Google's
HUProxy project. This allows tunneling SSH connections through HTTP/HTTPS when direct SSH access is
restricted by firewalls or network policies.

#### Using with SSH Client

First, ensure you have proper tokens configured in your `.patchwork/auth.yaml` file:

```yaml
tokens:
  "your_secure_token_here":
    huproxy:
      - "*"  # allows all host:port combinations
  "another_token_for_different_client":
    huproxy:
      - "*.example.com:*"
      - "localhost:*"
```

Then configure your SSH client to use the proxy:

```bash
# Using a WebSocket client like huproxyclient (needs to be built separately)
ssh -o 'ProxyCommand=huproxyclient -auth=Bearer:your_secure_token_here wss://patchwork.example.com/huproxy/alice/targethost/22' user@targethost

# Or using curl as a basic test (won't work for full SSH sessions)
curl -H "Authorization: Bearer your_secure_token_here" 
     --http1.1 
     --upgrade websocket 
     https://patchwork.example.com/huproxy/alice/localhost/22
```

#### Token-based Authentication

Authentication is managed through `auth.yaml` files stored in each user's `.patchwork` repository:

```yaml
# .patchwork/auth.yaml
tokens:
  "production_ssh_token_abc123":
    huproxy:
      - "*.production.com:*"
  "development_access_def456":
    huproxy:
      - "*.dev.com:*"
      - "localhost:*"
  "backup_script_token_789xyz":
    huproxy:
      - "backup.example.com:22"
```

**Security Notes:**
- Tokens are validated against the user's `.patchwork/auth.yaml` file
- Each user controls their own token list through their repository
- Tokens should be long, random strings (recommended: 32+ characters)
- The proxy supports any TCP service, not just SSH (databases, VNC, etc.)

**Original Project**: This implementation is based on [Google's HUProxy](https://github.com/google/huproxy)
with added user-specific authentication and integration into the Patchwork ecosystem.TP endpoints that can be used to implement powerful
serverless applications - including desktop notifications, SMS notifications,
job queues, web hosting, and file sharing. These applications are basically
just a few lines of bash that wrap a `curl` command.

The philosophy behind this is that the main logic happens on the local machine
with small scripts. There is a server with an infinite number of virtual channels
that will relay messages between the publisher and the subscriber.

## Quick Start

### Basic Usage

To subscribe to a channel you can simply make a `GET` request:
```bash
curl https://patchwork.example.com/p/a61b1f42
```

The above will block until something is published to the channel `a61b1f42`. 
You can easily publish to a channel using a `POST` request:
```bash
curl https://patchwork.example.com/p/a61b1f42 -d "hello, world"
```

The subscriber will immediately receive that data. If you reverse the order,
then the post will block until it is received.

### Pubsub mode

The default mode is a MPMC queue, where the first to connect are able to
publish/subscribe. But you can also specify publish-subscribe (pubsub) mode.
In pubsub mode, the publisher will become non-blocking and their data will be
transmitted to each connected subscriber:

```bash
curl https://patchwork.example.com/p/a61b1f42?pubsub=true -d "hello, world"
```

### Publish with GET

You can also publish with a `GET` request by using the parameter
`body=X`, making it easier to write href links that can trigger hooks:

```bash
curl https://patchwork.example.com/p/a61b1f42?pubsub=true&body=hello,%20world
```

## Namespaces

The server is organized by namespaces with different access patterns:

- **`/p/**`**: Public namespace - no authentication required.
  Everyone can read and write. Perfect for testing and public communication channels.
- **`/h/**`**: Forward hooks - GET `/h` to obtain a new channel and secret,
  then use the secret to POST data to that channel. Anyone can GET data from the channel.
  Useful for webhooks and notifications where you want to control who can send.
- **`/r/**`**: Reverse hooks - GET `/r` to obtain a new channel and secret,
  then anyone can POST data to that channel. Use the secret to GET data from the channel.
  Useful for collecting data from multiple sources where you want to control who can read.
- **`/u/{username}/**`**: User namespace - controlled by ACL lists
  (not implemented yet). Access is controlled by YAML ACL files stored in
  Forgejo/Gitea repositories that specify which tokens can access which paths.
- **`/huproxy/{user}/{host}/{port}`**: HTTP-to-TCP WebSocket proxy for tunneling SSH and other protocols.
  Based on Google's HUProxy project, this endpoint provides WebSocket tunneling primarily for SSH
  connections. Uses token-based authentication via `Authorization` header. Tokens are managed through
  the `huproxy` field in the user's `auth.yaml` file in their `.patchwork` repository.

### ACL File Format

For user namespaces, access control is managed through YAML files stored in
Forgejo/Gitea repositories. Each user or organization can create a 
`.patchwork` repository containing an `auth.yaml` file:

- **`auth.yaml`**: Defines ACL permissions and HuProxy tokens for different authentication tokens

#### User Namespace ACL (`auth.yaml`)

```yaml
some_token_name:
  POST: "projects/*/data"  # Can POST to any project's data endpoint
  GET: "projects/myproject/**"  # Can GET from all paths under myproject

restricted_token:
  POST: ""  # Empty string means no POST access allowed
  GET: "**"  # Can GET from all subpaths in this namespace

webhook_token:
  POST: "webhooks/*"  # Can POST to any webhook endpoint
  GET: "status"  # Can only GET the status endpoint
```

Each token can have `POST` and `GET` permissions defined with glob patterns:
- An empty string (`""`) denies all access for that method
- `**` allows access to all subpaths
- Specific glob patterns like `projects/*/data` allow fine-grained control
- Tokens are passed via the `token` query parameter: `?token=some_token_name`

#### Repository Setup

1. **Create `.patchwork` repository**: Each user/organization creates a repository named `.patchwork`
2. **Add `auth.yaml`**: Place the ACL and HuProxy configuration in a file named `auth.yaml` in the repository root
3. **Grant access**: Give the special `patchwork` user read access to the `.patchwork` repository
4. **Caching**: The patchwork server pulls and caches these configuration files as needed

Example repository structure:
```
user/.patchwork/
├── auth.yaml
└── README.md (optional)
```

#### HuProxy Configuration

For HuProxy access, configure tokens in the `huproxy` field of your `.patchwork/auth.yaml` file:

```yaml
tokens:
  "some-long-token-for-huproxy-access":
    huproxy:
      - "*"  # allows all host:port combinations
  "restricted-huproxy-token":
    huproxy:
      - "*.example.com:*"
      - "localhost:*"
```

Users can then access HuProxy endpoints using these tokens:
```bash
curl -H "Authorization: Bearer some-long-token-for-huproxy-access" \
  https://patchwork.example.com/huproxy/alice/localhost/22
```

## Modes

Each endpoint supports multiple modes:

- **queue**: Each message is received by exactly one receiver (default)
- **pubsub**: All receivers receive the published message
- **req/res**: Request/response pattern (not implemented yet)

## Examples

### File Sharing

Sending a file:
```bash
curl -X POST --data-binary "@test.txt" https://patchwork.example.com/p/test.txt
```

Receiving a file:
```bash
wget https://patchwork.example.com/p/test.txt
```

### Desktop Notifications (Linux)

```bash
#!/bin/bash
MAGIC="notify"
URL="https://patchwork.example.com/p/notifications"

while [ 1 ]
do
  X="$(curl $URL)"
  if [[ $X =~ ^$MAGIC ]]; then
    Y="$(echo "$X" | sed "s/$MAGIC*//")"
    notify-send "$Y"
  else
    sleep 10
  fi
done
```

### Job Queue

Adding jobs to a queue:
```bash
#!/bin/bash
for filename in *.mp3
do
  curl https://patchwork.example.com/p/jobs -d $filename
done
```

Processing jobs from the queue:
```bash
#!/bin/bash
while true
do
  filename=$(curl -s https://patchwork.example.com/p/jobs)
  if [ "$filename" != "Too Many Requests" ]
  then
    echo "Processing: $filename"
    # Process the file here
    ffmpeg -i "$filename" "$filename.ogg"
  else
    sleep 1
  fi
done
```

### Forward Hook Example

To use forward hooks, first obtain a channel and secret by making a GET request to `/h`:

```bash
# Get a new channel and secret
curl https://patchwork.example.com/h
# Returns: {"channel":"abc123-def456-...","secret":"sha256hash..."}
```

Then use the channel and secret for secure communication:

```bash
# Send notification (requires secret)
curl https://patchwork.example.com/h/abc123-def456-...?secret=sha256hash... -d "Server is down!"

# Anyone can listen for notifications
curl https://patchwork.example.com/h/abc123-def456-...
```

### Reverse Hook Example

Similarly, for reverse hooks, obtain a channel and secret by making a GET request to `/r`:

```bash
# Get a new channel and secret
curl https://patchwork.example.com/r
# Returns: {"channel":"xyz789-abc123-...","secret":"sha256hash..."}
```

Then collect data from multiple sources:

```bash
# Anyone can submit metrics
curl https://patchwork.example.com/r/xyz789-abc123-... -d "cpu:85%"
curl https://patchwork.example.com/r/xyz789-abc123-... -d "memory:67%"

# Reading requires secret
curl https://patchwork.example.com/r/xyz789-abc123-...?secret=sha256hash...
```

**Note**: The secrets are generated using HMAC-SHA256 with a server secret key and the channel name. If no `SECRET_KEY` environment variable is provided, a random key is generated at startup (secrets won't persist across server restarts).

### User Namespace Example

Using ACL-controlled user namespaces with tokens:

```bash
# Send data to a user namespace (requires appropriate token)
curl https://patchwork.example.com/u/alice/projects/web/logs?token=webhook_token -d "Deploy completed"

# Read from user namespace (requires token with GET permission)
curl https://patchwork.example.com/u/alice/projects/web/status?token=some_token_name
```

### HTTP-to-TCP Proxy (huproxy) Example

Using the huproxy endpoint to proxy HTTP requests to TCP services:

```bash
# Using token-based authentication
curl -H "Authorization: Bearer your_huproxy_token" \
  https://patchwork.example.com/huproxy/alice/localhost/22

# Alternative without "Bearer" prefix  
curl -H "Authorization: your_huproxy_token" \
  https://patchwork.example.com/huproxy/alice/database/5432
```

**Note**: Tokens are configured in the `huproxy` field of the `auth.yaml` file in the user's `.patchwork` repository.

## Tools

### Bash Client

You can download a bash-based client [here](assets/patchwork.sh).

#### Usage Examples

```bash
# Send data to a channel
patchwork send mychannel "hello world"
echo "hello" | patchwork send mychannel

# Receive data from a channel
patchwork receive mychannel

# Send in pubsub mode
patchwork send -m pubsub mychannel "broadcast message"

# Use forward hooks
patchwork get-hook h  # Get channel and secret for forward hook
patchwork send -n h -s <secret> <channel> "notification"

# Use reverse hooks
patchwork get-hook r  # Get channel and secret for reverse hook
patchwork send -n r <channel> "cpu:85%"  # No secret needed
patchwork receive -n r -s <secret> <channel>

# Use user namespaces with tokens
patchwork send -n u -t webhook_token alice/projects/logs "deploy completed"
patchwork receive -n u -t some_token alice/projects/status

# Listen for notifications
patchwork listen notifications

# Share files
patchwork share document.pdf
patchwork download document.pdf
```

## Installation

### Docker

```bash
docker run -p 8080:8080 ghcr.io/tionis/patchwork:latest
```

### From Source

```bash
git clone https://github.com/tionis/patchwork.git
cd patchwork
go build -o patchwork .
./patchwork start --port 8080
```

### CLI Options

The `start` command supports the following options:

- `--port`: Port to listen on (default: 8080)

Example:
```bash
./patchwork start --port 3000
```

### Configuration

#### Forgejo/Gitea Backend Setup

To enable user namespaces with ACL control, configure Patchwork to use a Forgejo or Gitea instance:

1. **Set up Forgejo/Gitea instance**: Ensure you have a running Forgejo or Gitea server
2. **Create patchwork user**: Create a dedicated `patchwork` user account on your Forgejo/Gitea instance
3. **Configure Patchwork**: Set environment variables or configuration file to point to your Forgejo/Gitea instance:
   ```bash
   export FORGEJO_URL="https://git.example.com"
   export ACL_TTL="5m"  # Cache ACL files for 5 minutes
   export SECRET_KEY="your-secret-key-for-hook-authentication"  # For hook HMAC generation
   ```

   **Note**: The `SECRET_KEY` is used to generate HMAC-SHA256 secrets for hook channels. If not provided, a random key is generated at startup, but hook secrets won't persist across server restarts.

#### User Setup for ACL

For users who want to use the `/u/{username}/` namespace:

1. **Create `.patchwork` repository** in your Forgejo/Gitea account
2. **Add the `patchwork` user** as a collaborator with read access
3. **Create `auth.yaml`** file with your token permissions
4. **Commit and push** the configuration

The patchwork server will automatically fetch and cache your ACL configuration when needed.

## License

MIT
