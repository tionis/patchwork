# Authentication System Documentation

## Overview

The patchwork server now includes a comprehensive authentication system that integrates with Forgejo repositories to manage access control lists (ACLs) for both regular patchwork channels and HuProxy tunneling.

## Environment Variables

Add these environment variables to configure the authentication system:

```bash
# Required: Forgejo API token for accessing .patchwork repositories
FORGEJO_TOKEN=your_forgejo_api_token_here

# Optional: Forgejo instance URL (defaults to https://forge.tionis.dev)
FORGEJO_URL=https://forge.tionis.dev

# Optional: ACL cache TTL (defaults to 5 minutes)
ACL_TTL=5m

# Required: Server secret key for channel secrets
SECRET_KEY=your_secret_key_here
```

## Repository Structure

Each user needs a `.patchwork` repository in Forgejo with an `auth.yaml` file:

```
username/.patchwork/
└── auth.yaml
```

## auth.yaml Format

```yaml
# Regular patchwork channel tokens
tokens:
  "user_token_123": 
    is_admin: false
    permissions: ["read", "write"]
    expires_at: 2025-12-31T23:59:59Z
  
  "admin_token_456":
    is_admin: true
    permissions: ["read", "write", "admin"]
    # No expires_at means token never expires

# HuProxy tunneling tokens
huproxy:
  "huproxy_token_789":
    is_admin: false
    permissions: ["tunnel"]
    expires_at: 2026-01-31T23:59:59Z
  
  "huproxy_admin_abc":
    is_admin: true
    permissions: ["tunnel", "admin"]
```

## Token Properties

- **is_admin**: Boolean flag for administrative privileges
- **permissions**: Array of permission strings (currently informational)
- **expires_at**: Optional expiration timestamp in RFC3339 format

## Administrative Endpoints

### Cache Invalidation

Use webhook endpoint to invalidate user cache instantly:

```bash
curl -X POST \
  'https://patchwork.example.com/u/username/_/invalidate_cache' \
  -H 'Authorization: Bearer admin_token_456'
```

This endpoint:
- Requires admin token in Authorization header
- Supports `Bearer <token>`, `token <token>`, or direct token formats
- Clears cached ACL data for the user
- Returns JSON response: `{"status": "cache invalidated"}`

## Usage Examples

### Regular Channel Access

```bash
# Using token in query parameter
curl -H "Authorization: Bearer user_token_123" \
  https://patchwork.example.com/u/alice/my-channel

# Or in header
curl -H "Authorization: token user_token_123" \
  https://patchwork.example.com/u/alice/my-channel
```

### HuProxy Access

```bash
# SSH tunneling with huproxy token
ssh -o 'ProxyCommand=huproxyclient -auth=Bearer:huproxy_token_789 \
  wss://patchwork.example.com/huproxy/alice/targethost/22' user@targethost
```

## Webhook Integration

Set up a repository webhook in Forgejo to automatically invalidate cache when auth.yaml changes:

1. Go to your `.patchwork` repository settings
2. Add webhook with URL: `https://patchwork.example.com/u/yourusername/_/invalidate_cache`
3. Set secret to your admin token
4. Choose "Push events" trigger

## Security Notes

- Tokens are validated against the user's own `.patchwork/auth.yaml` file
- Admin tokens allow access to administrative endpoints
- Cache invalidation requires admin privileges
- Expired tokens are automatically rejected
- Failed API requests fall back to cached data if available

## API Flow

1. Client makes request with token
2. Server checks ACL cache for user
3. If cache miss or expired, fetches from Forgejo API
4. Validates token against ACL data
5. Caches result for future requests
6. Returns authentication decision

## Error Handling

- Missing token: `401 Unauthorized`
- Invalid token: `403 Forbidden`
- API errors: Falls back to cached data
- Network issues: Logs error, uses cache if available
- Missing auth.yaml: Treats as empty ACL (no valid tokens)
