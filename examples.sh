#!/bin/bash

# Example usage of patchwork authentication system
# This script demonstrates different authentication methods

PATCHWORK_URL="${PATCHWORK_URL:-http://localhost:8080}"
USERNAME="alice"
TOKEN="user_token_123"
ADMIN_TOKEN="admin_token_456"
HUPROXY_TOKEN="huproxy_token_789"

echo "=== Patchwork Authentication Examples ==="
echo "Using server: $PATCHWORK_URL"
echo

# Example 1: Public namespace (no auth required)
echo "1. Public namespace access (no authentication required):"
echo "curl -X POST \"$PATCHWORK_URL/p/test-channel\" -d \"Hello from public channel\""
echo

# Example 2: User namespace with Authorization header
echo "2. User namespace with Authorization header:"
echo "# Producer (send data)"
echo "curl -X POST \"$PATCHWORK_URL/u/$USERNAME/my-channel\" \\"
echo "  -H \"Authorization: Bearer $TOKEN\" \\"
echo "  -H \"Content-Type: text/plain\" \\"
echo "  -d \"Hello from authenticated channel\""
echo
echo "# Consumer (receive data)"
echo "curl -X GET \"$PATCHWORK_URL/u/$USERNAME/my-channel\" \\"
echo "  -H \"Authorization: Bearer $TOKEN\""
echo

# Example 3: User namespace with token in query parameter
echo "3. User namespace with token in query parameter:"
echo "curl -X POST \"$PATCHWORK_URL/u/$USERNAME/my-channel?token=$TOKEN\" \\"
echo "  -d \"Hello with query token\""
echo

# Example 4: JSON data with authentication
echo "4. JSON data with authentication:"
echo "curl -X POST \"$PATCHWORK_URL/u/$USERNAME/json-channel\" \\"
echo "  -H \"Authorization: Bearer $TOKEN\" \\"
echo "  -H \"Content-Type: application/json\" \\"
echo "  -d '{\"message\": \"Hello JSON\", \"timestamp\": \"2025-01-01T00:00:00Z\"}'"
echo

# Example 5: Pubsub mode with authentication
echo "5. Pubsub mode with authentication:"
echo "curl -X POST \"$PATCHWORK_URL/u/$USERNAME/broadcast?pubsub&token=$TOKEN\" \\"
echo "  -d \"Broadcast message to all subscribers\""
echo

# Example 6: Administrative cache invalidation
echo "6. Administrative cache invalidation:"
echo "curl -X POST \"$PATCHWORK_URL/u/$USERNAME/_/invalidate_cache\" \\"
echo "  -H \"Authorization: Bearer $ADMIN_TOKEN\""
echo

# Example 7: HuProxy authentication
echo "7. HuProxy WebSocket tunneling:"
echo "# Connect to SSH through WebSocket tunnel"
echo "ssh -o 'ProxyCommand=huproxyclient -auth=Bearer:$HUPROXY_TOKEN \\"
echo "  wss://$PATCHWORK_URL/huproxy/$USERNAME/targethost/22' user@targethost"
echo

# Example 8: Different Authorization header formats
echo "8. Different Authorization header formats:"
echo "# Bearer format"
echo "curl -H \"Authorization: Bearer $TOKEN\" \"$PATCHWORK_URL/u/$USERNAME/test\""
echo
echo "# Token format"
echo "curl -H \"Authorization: token $TOKEN\" \"$PATCHWORK_URL/u/$USERNAME/test\""
echo
echo "# Direct token"
echo "curl -H \"Authorization: $TOKEN\" \"$PATCHWORK_URL/u/$USERNAME/test\""
echo

echo "=== Error Examples ==="
echo

# Example 9: Missing authentication
echo "9. Missing authentication (should fail):"
echo "curl -X POST \"$PATCHWORK_URL/u/$USERNAME/protected\" -d \"This should fail\""
echo "# Expected: 401 Unauthorized"
echo

# Example 10: Invalid token
echo "10. Invalid token (should fail):"
echo "curl -X POST \"$PATCHWORK_URL/u/$USERNAME/protected\" \\"
echo "  -H \"Authorization: Bearer invalid_token_123\" \\"
echo "  -d \"This should fail\""
echo "# Expected: 401 Unauthorized"
echo

# Example 11: Non-admin trying admin endpoint
echo "11. Non-admin trying admin endpoint (should fail):"
echo "curl -X POST \"$PATCHWORK_URL/u/$USERNAME/_/invalidate_cache\" \\"
echo "  -H \"Authorization: Bearer $TOKEN\""
echo "# Expected: 403 Forbidden"
echo

echo "=== Notes ==="
echo "- Tokens must be configured in $USERNAME/.patchwork/auth.yaml in Forgejo"
echo "- Admin tokens require 'is_admin: true' in the token configuration"
echo "- HuProxy tokens are separate from regular channel tokens"
echo "- Cache invalidation helps with immediate token updates"
echo "- Public channels (/p/*) don't require authentication"
echo "- Hook channels (/h/*, /r/*) use secret-based authentication"
