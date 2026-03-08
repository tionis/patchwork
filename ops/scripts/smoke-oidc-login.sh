#!/usr/bin/env bash
set -euo pipefail

GO="${GO:-go}"

# This smoke check uses the in-test OIDC provider harness and verifies:
# - OIDC login callback creates a web session
# - OIDC admin session can mint machine tokens
# - forwarded https headers produce secure session cookies
"${GO}" test ./internal/httpserver \
  -run '^(TestOIDCLoginSessionCanManageAdminTokens|TestOIDCCallbackSetsSessionCookieSecureWithForwardedHTTPS)$' \
  -count=1
