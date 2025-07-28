# Patchwork

A simple communication backend for scripts and other small applications.
Patchwork enables IFTTT-type applications by providing infinite HTTP endpoints
that serve as a multi-process, multi-consumer (MPMC) queue.

## What does it do?

Patchwork provides infinite HTTP endpoints that can be used to implement powerful
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

### ACL File Format

For user namespaces, access control is managed through YAML files stored in
Forgejo/Gitea repositories. Each user or organization can create a 
`.patchwork` repository containing an `auth.yaml` file that defines
permissions for different tokens:

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
2. **Add `auth.yaml`**: Place the ACL configuration in a file named `auth.yaml` in the repository root
3. **Grant access**: Give the special `patchwork` user read access to the `.patchwork` repository
4. **Caching**: The patchwork server pulls and caches these ACL files as needed

Example repository structure:
```
user/.patchwork/
├── auth.yaml
└── README.md (optional)
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
