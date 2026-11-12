package sigv4

import (
	"errors"
	"strings"
	"time"
)

// The defaults New applies before its options.
const (
	// DefaultMaxBodySize bounds the body a buffered payload reads. The
	// largest legitimate AWS JSON request the Tule services take is a 64 KiB
	// secret value and the JSON around it, so 1 MiB leaves ample room.
	DefaultMaxBodySize = 1 << 20

	// DefaultMaxClockSkew is how far X-Amz-Date may be from the server's
	// clock, either way, on an Authorization header request.
	DefaultMaxClockSkew = 15 * time.Minute

	// DefaultMaxPresignExpiry is the longest X-Amz-Expires a presigned URL
	// may carry, the seven days AWS allows.
	DefaultMaxPresignExpiry = 7 * 24 * time.Hour
)

// defaultRequiredSignedHeaders are what a signature must cover unless
// WithRequiredSignedHeaders says otherwise. Host ties a request to this
// server and X-Amz-Date to a point in time.
var defaultRequiredSignedHeaders = []string{"host", "x-amz-date"}

// Option configures a Verifier.
type Option func(*Verifier)

// WithPresignedURLs sets whether a request may authenticate with a presigned
// URL, its X-Amz-* query parameters, instead of an Authorization header.
// Off by default: an AWS JSON service is only ever called with the header,
// and with this off, its X-Amz-* query parameters are plain query
// parameters.
func WithPresignedURLs(accept bool) Option {
	return func(v *Verifier) { v.presign = accept }
}

// WithBufferedPayload reads the body into memory, up to maxBytes, and hashes
// it. An X-Amz-Content-Sha256 header is optional: when absent, the body's
// hash goes into the canonical request, which is how the SDKs sign an AWS
// JSON call. When present and hex, it must match the body. The handler reads
// the buffered body. This is the default, with DefaultMaxBodySize.
func WithBufferedPayload(maxBytes int64) Option {
	return func(v *Verifier) {
		v.streamed = false
		v.maxBody = maxBytes
	}
}

// WithStreamedPayload leaves the body unread. The X-Amz-Content-Sha256
// header is required on an Authorization header request, and defaults to
// UNSIGNED-PAYLOAD on a presigned one. When it is a hex SHA-256, the body is
// replaced with a reader that hashes it as the handler reads it and fails
// the read that reaches EOF with a KindPayloadHashMismatch error when it
// does not match. This is how S3 uploads are signed.
func WithStreamedPayload() Option {
	return func(v *Verifier) { v.streamed = true }
}

// WithUnsignedPayload sets whether X-Amz-Content-Sha256 may be
// UNSIGNED-PAYLOAD, a signature that covers no part of the body. Off by
// default: whoever relays such a request can swap its body.
func WithUnsignedPayload(accept bool) Option {
	return func(v *Verifier) { v.allowUnsigned = accept }
}

// WithStreamingPayload sets whether X-Amz-Content-Sha256 may be a STREAMING-*
// value, the aws-chunked encoding. The request signature is verified; the
// per-chunk signatures are not. Off by default.
func WithStreamingPayload(accept bool) Option {
	return func(v *Verifier) { v.allowStreaming = accept }
}

// WithAnyPayloadHash sets whether X-Amz-Content-Sha256 may be any value that
// is not a hex SHA-256, UNSIGNED-PAYLOAD and STREAMING-* included. The value
// is signed as sent and the body is not checked against it. Off by default;
// object-store accepts any value today, and this keeps it doing so.
func WithAnyPayloadHash(accept bool) Option {
	return func(v *Verifier) { v.allowAnyHash = accept }
}

// WithRequiredSignedHeaders sets the headers a signature must cover, compared
// case-insensitively, and checked in the order given. With none, no header
// is required. The default is host and x-amz-date. A presigned URL signs
// X-Amz-Date in its query, so x-amz-date is not required of one.
func WithRequiredSignedHeaders(names ...string) Option {
	return func(v *Verifier) {
		v.required = make([]string, len(names))
		for i, name := range names {
			v.required[i] = strings.ToLower(name)
		}
	}
}

// WithService sets the service the credential must be scoped to, such as
// "s3" or "secretsmanager". Unset by default, which accepts any service the
// request was signed for; the Tule services do not check it today.
func WithService(name string) Option {
	return func(v *Verifier) { v.service = name }
}

// WithMaxClockSkew sets how far X-Amz-Date may be from the server's clock on
// an Authorization header request. A presigned URL is bounded by its expiry
// instead. The default is DefaultMaxClockSkew.
func WithMaxClockSkew(d time.Duration) Option {
	return func(v *Verifier) { v.maxSkew = d }
}

// WithMaxPresignExpiry sets the longest X-Amz-Expires a presigned URL may
// carry, a whole number of seconds. The default is DefaultMaxPresignExpiry.
func WithMaxPresignExpiry(d time.Duration) Option {
	return func(v *Verifier) { v.maxExpiry = d }
}

// WithErrorMap sets the function every verification failure passes through,
// so Verify, and a streamed body's read, return the service's own wire
// error. Without it they return the *Error.
func WithErrorMap(mapErr func(*Error) error) Option {
	return func(v *Verifier) { v.mapErr = mapErr }
}

// WithClock sets the clock request times are checked against. The default is
// time.Now.
func WithClock(now func() time.Time) Option {
	return func(v *Verifier) { v.now = now }
}

func (v *Verifier) validate() error {
	var errs []error
	if v.keys == nil {
		errs = append(errs, errors.New("sigv4: a KeySource is required"))
	}
	if !v.streamed && v.maxBody <= 0 {
		errs = append(errs, errors.New("sigv4: the buffered body limit must be positive"))
	}
	if v.maxSkew < 0 {
		errs = append(errs, errors.New("sigv4: the clock skew must not be negative"))
	}
	if v.maxExpiry < time.Second || v.maxExpiry%time.Second != 0 {
		errs = append(errs, errors.New("sigv4: the presign expiry must be a whole number "+
			"of seconds, at least one"))
	}
	if v.now == nil {
		errs = append(errs, errors.New("sigv4: the clock must not be nil"))
	}
	return errors.Join(errs...)
}
