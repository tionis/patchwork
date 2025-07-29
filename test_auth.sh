#!/bin/bash

# Integration test script for patchwork authentication system
# This script demonstrates the authentication flow

echo "=== Patchwork Authentication Integration Test ==="

# Configuration
PATCHWORK_URL="${PATCHWORK_URL:-http://localhost:8080}"
TEST_USER="testuser"
ADMIN_TOKEN="admin_token_456"
USER_TOKEN="user_token_123"
HUPROXY_TOKEN="huproxy_token_789"

echo "Testing against: $PATCHWORK_URL"
echo

# Test 1: Cache invalidation with admin token
echo "1. Testing cache invalidation with admin token..."
response=$(curl -s -w "%{http_code}" -X POST \
  "$PATCHWORK_URL/u/$TEST_USER/_/invalidate_cache" \
  -H "Authorization: Bearer $ADMIN_TOKEN")

http_code="${response: -3}"
response_body="${response%???}"

if [ "$http_code" = "200" ]; then
  echo "✓ Cache invalidation successful: $response_body"
else
  echo "✗ Cache invalidation failed (HTTP $http_code): $response_body"
fi
echo

# Test 2: Cache invalidation with invalid token
echo "2. Testing cache invalidation with invalid token..."
response=$(curl -s -w "%{http_code}" -X POST \
  "$PATCHWORK_URL/u/$TEST_USER/_/invalidate_cache" \
  -H "Authorization: Bearer invalid_token")

http_code="${response: -3}"
if [ "$http_code" = "403" ] || [ "$http_code" = "401" ]; then
  echo "✓ Correctly denied invalid token (HTTP $http_code)"
else
  echo "✗ Should have denied invalid token, got HTTP $http_code"
fi
echo

# Test 3: Cache invalidation without token
echo "3. Testing cache invalidation without token..."
response=$(curl -s -w "%{http_code}" -X POST \
  "$PATCHWORK_URL/u/$TEST_USER/_/invalidate_cache")

http_code="${response: -3}"
if [ "$http_code" = "401" ]; then
  echo "✓ Correctly denied missing token (HTTP $http_code)"
else
  echo "✗ Should have denied missing token, got HTTP $http_code"
fi
echo

# Test 4: Test unknown admin endpoint
echo "4. Testing unknown admin endpoint..."
response=$(curl -s -w "%{http_code}" -X POST \
  "$PATCHWORK_URL/u/$TEST_USER/_/unknown_endpoint" \
  -H "Authorization: Bearer $ADMIN_TOKEN")

http_code="${response: -3}"
if [ "$http_code" = "404" ]; then
  echo "✓ Correctly returned 404 for unknown endpoint"
else
  echo "✗ Expected 404 for unknown endpoint, got HTTP $http_code"
fi
echo

# Test 5: Test health check (should work without auth)
echo "5. Testing health check endpoint..."
response=$(curl -s -w "%{http_code}" "$PATCHWORK_URL/healthz")
http_code="${response: -3}"
response_body="${response%???}"

if [ "$http_code" = "200" ]; then
  echo "✓ Health check successful: $response_body"
else
  echo "✗ Health check failed (HTTP $http_code): $response_body"
fi
echo

echo "=== Integration Test Complete ==="
echo
echo "Note: This test only covers the administrative endpoints."
echo "To test full authentication, you need:"
echo "1. A running Forgejo instance"
echo "2. A .patchwork repository with auth.yaml"
echo "3. Valid FORGEJO_TOKEN environment variable"
