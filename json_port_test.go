package sigv4

// The tests of secret-store's and accounts' verifiers, ported: the same
// conditions, through a verifier configured as those services are to
// configure it, run once for each service. Each case checks the Kind and the
// error type the service's map turns it into.

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

const (
	typeMissingAuthToken   = "MissingAuthenticationTokenException"
	typeIncompleteSig      = "IncompleteSignatureException"
	typeInvalidSignature   = "InvalidSignatureException"
	typeUnrecognizedClient = "UnrecognizedClientException"
)

// wantJSONType fails unless err is an *Error the service maps to errType,
// and returns what the service answers with.
func wantJSONType(t *testing.T, svc jsonService, err error, errType string) wire {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("Verify = %v, want an *Error", err)
	}
	w := jsonWire(e, svc.invalidInput)
	if w.code != errType {
		t.Fatalf("error type = %s (kind %s), want %s", w.code, e.Kind, errType)
	}
	return w
}

func TestJSONVerifyAcceptsASignedRequest(t *testing.T) {
	for _, svc := range jsonServices {
		t.Run(svc.name, func(t *testing.T) {
			req := svc.signJSON(t, svc.body)
			if err := jsonVerifier(t).check(req); err != nil {
				t.Fatalf("Verify: %v", err)
			}

			// The handler must still see the body the signature covered.
			read, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			if string(read) != svc.body {
				t.Fatalf("body = %q, want %q", read, svc.body)
			}
		})
	}
}

// rejectCase is one way a request can fail verification: how to break a
// correctly signed request, and the error type that must come back.
type rejectCase struct {
	tamper func(svc jsonService, r *http.Request)
	// request signs the request in place of signJSON.
	request  func(t *testing.T, svc jsonService) *http.Request
	verifier func(t *testing.T) *Verifier
	wantType func(svc jsonService) string
	name     string
}

func fixedType(errType string) func(jsonService) string {
	return func(jsonService) string { return errType }
}

// rejectCases is split in two only to keep each table short: the first covers
// what the Authorization header itself must carry, the second what the
// signature over the request must cover.
func rejectCases() []rejectCase {
	return append(headerRejectCases(), signatureRejectCases()...)
}

func headerRejectCases() []rejectCase {
	return []rejectCase{
		{
			// Declared and signed, as every x-amz-* header must be.
			name: "declared payload hash does not match the body",
			request: func(t *testing.T, svc jsonService) *http.Request {
				t.Helper()
				hash := strings.Repeat("a", 64)
				return svc.signWith(t, svc.body, hash, map[string]string{
					"Content-Type":         jsonType,
					targetHeader:           svc.readTarget,
					"X-Amz-Content-Sha256": hash,
				})
			},
			wantType: func(svc jsonService) string { return svc.invalidInput },
		},
		{
			name:     "no Authorization header",
			tamper:   func(_ jsonService, r *http.Request) { r.Header.Del("Authorization") },
			wantType: fixedType(typeMissingAuthToken),
		},
		{
			name: "unsupported algorithm",
			tamper: func(_ jsonService, r *http.Request) {
				r.Header.Set("Authorization", "AWS4-HMAC-SHA512 Credential=x")
			},
			wantType: fixedType(typeIncompleteSig),
		},
		{
			name: "incomplete header",
			tamper: func(_ jsonService, r *http.Request) {
				r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=x/y/z/w/aws4_request")
			},
			wantType: fixedType(typeIncompleteSig),
		},
		{
			name:     "missing date",
			tamper:   func(_ jsonService, r *http.Request) { r.Header.Del("X-Amz-Date") },
			wantType: fixedType(typeIncompleteSig),
		},
	}
}

func signatureRejectCases() []rejectCase {
	return []rejectCase{
		{
			name: "tampered body",
			tamper: func(_ jsonService, r *http.Request) {
				r.Body = io.NopCloser(strings.NewReader(`{}`))
			},
			// The body is hashed into the signature, so changing it is a
			// signature failure rather than a hash mismatch.
			wantType: fixedType(typeInvalidSignature),
		},
		{
			name: "tampered target",
			tamper: func(svc jsonService, r *http.Request) {
				r.Header.Set(targetHeader, svc.removeTarget)
			},
			wantType: fixedType(typeInvalidSignature),
		},
		{
			name: "unknown access key",
			verifier: func(t *testing.T) *Verifier {
				t.Helper()
				return mustNew(
					t,
					mustStatic(t,
						StaticKeyConfig{AccessKeyID: "OTHER", SecretAccessKey: testSecretKey},
					),
					append(jsonOptions(), WithClock(fixedClock(signedAt)))...)
			},
			wantType: fixedType(typeUnrecognizedClient),
		},
		{
			name: "wrong secret key",
			verifier: func(t *testing.T) *Verifier {
				t.Helper()
				return mustNew(
					t,
					mustStatic(t,
						StaticKeyConfig{AccessKeyID: testAccessKey, SecretAccessKey: "wrong"},
					),
					append(jsonOptions(), WithClock(fixedClock(signedAt)))...)
			},
			wantType: fixedType(typeInvalidSignature),
		},
		{
			name: "expired signature",
			verifier: func(t *testing.T) *Verifier {
				t.Helper()
				return jsonVerifier(t, WithClock(fixedClock(signedAt.Add(time.Hour))))
			},
			wantType: fixedType(typeInvalidSignature),
		},
	}
}

func TestJSONVerifyRejects(t *testing.T) {
	for _, svc := range jsonServices {
		for _, tt := range rejectCases() {
			t.Run(svc.name+"/"+tt.name, func(t *testing.T) {
				req := svc.signJSON(t, svc.body)
				if tt.request != nil {
					req = tt.request(t, svc)
				}
				if tt.tamper != nil {
					tt.tamper(svc, req)
				}

				verifier := jsonVerifier(t)
				if tt.verifier != nil {
					verifier = tt.verifier(t)
				}

				wantJSONType(t, svc, verifier.check(req), tt.wantType(svc))
			})
		}
	}
}

func TestJSONVerifyRejectsAnOversizedBody(t *testing.T) {
	for _, svc := range jsonServices {
		t.Run(svc.name, func(t *testing.T) {
			req := svc.signJSON(t, "{}")
			req.Body = io.NopCloser(strings.NewReader(strings.Repeat("a", DefaultMaxBodySize+1)))

			w := wantJSONType(t, svc, jsonVerifier(t).check(req), svc.invalidInput)
			if w.status != http.StatusRequestEntityTooLarge {
				t.Fatalf("status = %d, want %d", w.status, http.StatusRequestEntityTooLarge)
			}
		})
	}
}

func TestJSONVerifyRejectsAnUnsignedPayload(t *testing.T) {
	// A request signed with UNSIGNED-PAYLOAD has a signature that covers no
	// part of the body, so whoever relays it can swap the body for another
	// operation's. Only a real hash binds the body, so nothing else is
	// accepted.
	for _, svc := range jsonServices {
		t.Run(svc.name, func(t *testing.T) {
			req := svc.signWith(t, svc.body, unsignedPayload, map[string]string{
				"Content-Type":         jsonType,
				targetHeader:           svc.readTarget,
				"X-Amz-Content-Sha256": unsignedPayload,
			})
			req.Body = io.NopCloser(strings.NewReader(svc.otherBody))

			wantJSONType(t, svc, jsonVerifier(t).check(req), typeIncompleteSig)
		})
	}
}

func TestJSONVerifyRequiresTheHeadersThatNameTheRequest(t *testing.T) {
	for _, svc := range jsonServices {
		t.Run(svc.name+"/unsigned operation header", func(t *testing.T) {
			// Signed without the operation header, which is then added: the
			// signature covers a request that does not say what it does, so
			// the relay picks the operation. Here a read becomes a removal.
			req := svc.signWith(t, svc.body, sha256Hex(svc.body), map[string]string{
				"Content-Type": jsonType,
			})
			req.Header.Set(targetHeader, svc.removeTarget)

			wantJSONType(t, svc, jsonVerifier(t).check(req), typeIncompleteSig)
		})
	}
}
