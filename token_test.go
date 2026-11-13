package sigv4

// Temporary credentials: requests signed by the AWS SDK with a session token,
// through SignHTTP and PresignHTTP, against a KeySource that knows the
// token the way an STS-backed one would.

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

const (
	tempAccessKey = "ASIAEXAMPLE"
	tempSecretKey = "temporary secret"
	tempToken     = "FwoGZXIvYXdzEXAMPLETOKEN//+="
	tempAccount   = "111122223333"
	tempARN       = "arn:aws:sts::111122223333:assumed-role/dev/session"
)

var tempCreds = aws.Credentials{
	AccessKeyID: tempAccessKey, SecretAccessKey: tempSecretKey, SessionToken: tempToken,
}

// tempKeys is a KeySource over one temporary key, which takes only its own
// session token.
type tempKeys struct {
	expired bool
}

func (k tempKeys) SigningKey(_ context.Context, s Scope) (Key, error) {
	switch {
	case s.AccessKeyID != tempAccessKey, s.SessionToken == "":
		// AWS reports a temporary key without its token as an unknown key.
		return Key{}, ErrUnknownAccessKey
	case s.SessionToken != tempToken:
		return Key{}, ErrInvalidSessionToken
	case k.expired:
		return Key{}, ErrExpiredSessionToken
	}
	return Key{
		Principal: Principal{AccountID: tempAccount, ARN: tempARN, AccessKeyID: tempAccessKey},
		Signing:   DeriveSigningKey(tempSecretKey, s.Date, s.Region, s.Service),
	}, nil
}

func (svc sdkService) tempVerifier(t *testing.T, keys KeySource, opts ...Option) *Verifier {
	t.Helper()
	all := append([]Option{WithClock(fixedClock(sdkTime.Add(time.Minute)))}, svc.opts...)
	return mustNew(t, keys, append(all, opts...)...)
}

// setToken sets the session token where the SDK put it: the header of a
// signed request, the query of a presigned one.
func setToken(r *http.Request, presign bool, token string) {
	if !presign {
		r.Header.Set(tokenHeader, token)
		return
	}
	q := r.URL.Query()
	if token == "" {
		q.Del(tokenHeader)
	} else {
		q.Set(tokenHeader, token)
	}
	r.URL.RawQuery = q.Encode()
}

func TestSessionTokenVerifies(t *testing.T) {
	for _, svc := range sdkServices() {
		for _, presign := range []bool{false, true} {
			t.Run(svc.name+"/"+modeName(presign), func(t *testing.T) {
				r := svc.signAt(t, presign, tempCreds, sdkTime)
				if presign != (r.URL.Query().Get(tokenHeader) == tempToken) ||
					presign == (r.Header.Get(tokenHeader) == tempToken) {
					t.Fatalf("token not where the SDK puts it: query %q, header %q",
						r.URL.Query().Get(tokenHeader), r.Header.Get(tokenHeader))
				}

				got, err := svc.tempVerifier(t, tempKeys{}).Verify(r)
				if err != nil {
					t.Fatalf("Verify: %v", err)
				}
				p, ok := PrincipalFrom(got.Context())
				want := Principal{AccountID: tempAccount, ARN: tempARN, AccessKeyID: tempAccessKey}
				if !ok || p != want {
					t.Fatalf("principal = %+v, %v; want %+v", p, ok, want)
				}
			})
		}
	}
}

func TestSessionTokenRefused(t *testing.T) {
	type refusal struct {
		edit func(r *http.Request, presign bool)
		keys KeySource
		name string
		want Kind
	}
	refusals := []refusal{
		{
			name: "tampered token",
			edit: func(r *http.Request, presign bool) { setToken(r, presign, tempToken+"x") },
			keys: tempKeys{}, want: KindInvalidSessionToken,
		},
		{
			name: "token removed",
			edit: func(r *http.Request, _ bool) {
				r.Header.Del(tokenHeader)
				setToken(r, true, "")
			},
			keys: tempKeys{}, want: KindUnknownAccessKey,
		},
		{
			name: "header and query disagree",
			// The query parameter is always signed, so a second token there
			// passes the coverage check and fails as a token.
			edit: func(r *http.Request, _ bool) { setToken(r, true, "another token") },
			keys: tempKeys{}, want: KindInvalidSessionToken,
		},
		{name: "expired token", keys: tempKeys{expired: true}, want: KindExpiredSessionToken},
		{
			name: "static key refuses a token",
			keys: mustStatic(t, StaticKeyConfig{
				AccessKeyID: tempAccessKey, SecretAccessKey: tempSecretKey,
			}),
			want: KindInvalidSessionToken,
		},
	}
	for _, svc := range sdkServices() {
		for _, presign := range []bool{false, true} {
			for _, tt := range refusals {
				t.Run(svc.name+"/"+modeName(presign)+"/"+tt.name, func(t *testing.T) {
					r := svc.signAt(t, presign, tempCreds, sdkTime)
					if tt.edit != nil {
						tt.edit(r, presign)
					}
					wantKind(t, svc.tempVerifier(t, tt.keys).check(r), tt.want)
				})
			}
		}
	}
}

func TestSessionTokenOnAnUnsignedHeader(t *testing.T) {
	// Signed without a token, which is then attached: the signature does
	// not cover it, so whoever relays the request could have chosen it.
	for _, svc := range sdkServices() {
		for _, presign := range []bool{false, true} {
			t.Run(svc.name+"/"+modeName(presign), func(t *testing.T) {
				creds := tempCreds
				creds.SessionToken = ""
				r := svc.signAt(t, presign, creds, sdkTime)
				r.Header.Set(tokenHeader, tempToken)

				e := asKind(t, svc.tempVerifier(t, tempKeys{}).check(r), KindUnsignedHeader)
				if e.Header != "x-amz-security-token" || e.Presigned != presign {
					t.Fatalf("error = %+v", e)
				}
			})
		}
	}
}

func TestSessionTokenWireErrors(t *testing.T) {
	s3, sm, smMap := sdkServices()[0], sdkServices()[1], jsonServices[0].wireMap
	tests := []struct {
		keys KeySource
		edit func(*http.Request)
		mapE func(*Error) error
		want wire
		name string
		svc  sdkService
	}{
		{
			name: "s3 invalid token", svc: s3, mapE: s3Map, keys: tempKeys{},
			edit: func(r *http.Request) { r.Header.Set(tokenHeader, "forged") },
			want: wire{
				status: http.StatusBadRequest, code: "InvalidToken",
				message: "The provided token is malformed or otherwise invalid.",
			},
		},
		{
			name: "s3 expired token", svc: s3, mapE: s3Map, keys: tempKeys{expired: true},
			want: wire{
				status: http.StatusBadRequest, code: "ExpiredToken",
				message: "The provided token has expired.",
			},
		},
		{
			name: "json invalid token", svc: sm, mapE: smMap, keys: tempKeys{},
			edit: func(r *http.Request) { r.Header.Set(tokenHeader, "forged") },
			want: wire{
				status: http.StatusForbidden, code: "UnrecognizedClientException",
				message: "The security token included in the request is invalid.",
			},
		},
		{
			name: "json expired token", svc: sm, mapE: smMap, keys: tempKeys{expired: true},
			want: wire{
				status: http.StatusForbidden, code: "ExpiredTokenException",
				message: "The security token included in the request is expired",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := tt.svc.signAt(t, false, tempCreds, sdkTime)
			if tt.edit != nil {
				tt.edit(r)
			}
			wantWire(t, tt.svc.tempVerifier(t, tt.keys, WithErrorMap(tt.mapE)).check(r), tt.want)
		})
	}

	// S3 answers a token header outside the signed headers with
	// HeadersNotSigned.
	creds := tempCreds
	creds.SessionToken = ""
	r := s3.signAt(t, false, creds, sdkTime)
	r.Header.Set(tokenHeader, tempToken)
	wantWire(t, s3.tempVerifier(t, tempKeys{}, WithErrorMap(s3Map)).check(r), wire{
		status: http.StatusForbidden, code: "AccessDenied",
		message: "There were headers present in the request which were not signed",
	})
}
