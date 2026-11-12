package sigv4

// ReadBody returns a body only when the signature covers it: its hash was
// computed from it, or declared in hex and matched. A body sent under an
// opaque payload hash is covered by no hash, whatever the payload mode.

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReadBodyRefusesOpaquePayloads(t *testing.T) {
	const streaming = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
	opaque := []struct {
		opt  Option
		name string
		hash string
	}{
		{name: "UNSIGNED-PAYLOAD", hash: unsignedPayload, opt: WithUnsignedPayload(true)},
		{name: "STREAMING", hash: streaming, opt: WithStreamingPayload(true)},
		{name: "any unsigned", hash: unsignedPayload, opt: WithAnyPayloadHash(true)},
		{name: "any streaming", hash: streaming, opt: WithAnyPayloadHash(true)},
		{name: "any other", hash: "not-a-hash", opt: WithAnyPayloadHash(true)},
	}
	svc := jsonServices[0]
	for _, streamed := range []bool{false, true} {
		for _, tt := range opaque {
			t.Run(modeLabel(streamed)+"/"+tt.name, func(t *testing.T) {
				opts := []Option{tt.opt}
				if streamed {
					opts = append(opts, WithStreamedPayload())
				}
				v := jsonVerifier(t, opts...)
				r := svc.signWith(t, svc.body, tt.hash, map[string]string{
					"Content-Type":         jsonType,
					targetHeader:           svc.readTarget,
					"X-Amz-Content-Sha256": tt.hash,
				})
				if err := v.check(r); err != nil {
					t.Fatalf("Verify: %v", err)
				}
				got, err := v.ReadBody(r, 1<<20)
				if got != nil {
					t.Fatalf("ReadBody returned %q as verified", got)
				}
				wantKind(t, err, KindUnverifiedPayload)
			})
		}
	}
}

func TestReadBodyReturnsCoveredPayloads(t *testing.T) {
	svc := jsonServices[0]
	covered := []struct {
		request func(t *testing.T) *http.Request
		name    string
		opts    []Option
	}{
		{
			name: "buffered, hash computed from the body",
			request: func(t *testing.T) *http.Request {
				t.Helper()
				return svc.signJSON(t, svc.body)
			},
		},
		{
			name:    "buffered, hex hash declared and matched",
			request: declaredHex(svc),
		},
		{
			name:    "streamed, hex hash declared and matched",
			request: declaredHex(svc),
			opts:    []Option{WithStreamedPayload()},
		},
	}
	for _, tt := range covered {
		t.Run(tt.name, func(t *testing.T) {
			v := jsonVerifier(t, tt.opts...)
			r := tt.request(t)
			if err := v.check(r); err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if got, err := v.ReadBody(r, 1<<20); err != nil || string(got) != svc.body {
				t.Fatalf("ReadBody = %q, %v", got, err)
			}
		})
	}
}

func declaredHex(svc jsonService) func(t *testing.T) *http.Request {
	return func(t *testing.T) *http.Request {
		t.Helper()
		hash := sha256Hex(svc.body)
		return svc.signWith(t, svc.body, hash, map[string]string{
			"Content-Type":         jsonType,
			targetHeader:           svc.readTarget,
			"X-Amz-Content-Sha256": hash,
		})
	}
}

func TestReadBodyWireErrors(t *testing.T) {
	v := s3Verifier(t, WithErrorMap(s3Map))
	orig, _ := deleteBodies()

	r := s3Put(t, s3Target+"?delete", orig, nil)
	if err := v.check(r); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	_, err := v.ReadBody(r, 16)
	wantWire(t, err, wire{
		status: http.StatusBadRequest, code: "MaxMessageLengthExceeded",
		message: "Your request was too big.",
	})

	// A body a middleware wrapped after Verify can no longer be told
	// verified, so it is refused.
	r = s3Put(t, s3Target+"?delete", orig, nil)
	if err = v.check(r); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	r.Body = http.MaxBytesReader(httptest.NewRecorder(), r.Body, 1<<20)
	_, err = v.ReadBody(r, 1<<20)
	wantWire(t, err, wire{
		status: http.StatusBadRequest, code: "InvalidRequest",
		message: "The request body is not covered by the signature.",
	})
}
