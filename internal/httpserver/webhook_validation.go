package httpserver

import (
	"context"
	"net/http"
)

// WebhookValidationHook provides an extension point for future webhook
// signature validation (for example provider HMAC checks).
//
// Returning nil, nil means "not validated" and keeps signature_valid as NULL.
// Returning a bool pointer stores signature_valid as 1/0.
// Returning an error rejects the webhook request.
type WebhookValidationHook interface {
	Validate(ctx context.Context, r *http.Request, dbID, endpoint string, payload []byte) (*bool, error)
}
