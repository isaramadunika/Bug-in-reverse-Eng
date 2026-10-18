// Package httpx contains JSON helpers, typed API errors and middleware.
package httpx

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
)

// APIError is the single error contract returned by the API:
// {"error":{"code":"...","message":"...","fields":{...},"request_id":"..."}}
type APIError struct {
	Status  int               `json:"-"`
	Code    string            `json:"code"`
	Message string            `json:"message"`
	Fields  map[string]string `json:"fields,omitempty"`
}

func (e *APIError) Error() string { return e.Code + ": " + e.Message }

func NewError(status int, code, msg string) *APIError {
	return &APIError{Status: status, Code: code, Message: msg}
}

var (
	ErrUnauthenticated = NewError(http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
	ErrForbidden       = NewError(http.StatusForbidden, "forbidden", "You do not have permission to perform this action.")
	ErrNotFound        = NewError(http.StatusNotFound, "not_found", "The requested resource was not found.")
	ErrCSRF            = NewError(http.StatusForbidden, "csrf_failed", "Request verification failed. Refresh the page and try again.")
	ErrRateLimited     = NewError(http.StatusTooManyRequests, "rate_limited", "Too many requests. Please wait and try again.")
	ErrInternal        = NewError(http.StatusInternalServerError, "internal_error", "An unexpected error occurred.")
	ErrMFARequired     = NewError(http.StatusForbidden, "mfa_required", "Multi-factor verification is required.")
	ErrEmailUnverified = NewError(http.StatusForbidden, "email_unverified", "Verify your email address to continue.")
)

func Validation(fields map[string]string) *APIError {
	return &APIError{Status: http.StatusUnprocessableEntity, Code: "validation_failed",
		Message: "Some fields are invalid.", Fields: fields}
}

func BadRequest(msg string) *APIError {
	return NewError(http.StatusBadRequest, "bad_request", msg)
}

func Error(status int, msg string) *APIError {
	return NewError(status, "error", msg)
}

func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

// WriteError renders err. Non-APIError values are logged and hidden behind a
// generic 500 so internal details never leak to clients.
func WriteError(w http.ResponseWriter, r *http.Request, err error) {
	var ae *APIError
	if !errors.As(err, &ae) {
		slog.ErrorContext(r.Context(), "unhandled error", "err", err, "path", r.URL.Path, "request_id", RequestID(r.Context()))
		ae = ErrInternal
	}
	WriteJSON(w, ae.Status, map[string]any{"error": struct {
		*APIError
		RequestID string `json:"request_id,omitempty"`
	}{ae, RequestID(r.Context())}})
}

const maxJSONBody = 1 << 20

// DecodeJSON strictly decodes a bounded JSON body.
func DecodeJSON(r *http.Request, dst any) error {
	ct := r.Header.Get("Content-Type")
	if ct != "" && !strings.HasPrefix(ct, "application/json") {
		return NewError(http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json.")
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, maxJSONBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return NewError(http.StatusBadRequest, "invalid_json", "Request body is not valid JSON for this endpoint.")
	}
	if dec.More() {
		return NewError(http.StatusBadRequest, "invalid_json", "Request body must contain a single JSON object.")
	}
	return nil
}

// Handler adapts error-returning handlers.
type Handler func(w http.ResponseWriter, r *http.Request) error

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := h(w, r); err != nil {
		WriteError(w, r, err)
	}
}
