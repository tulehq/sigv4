package sigv4

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNewRejectsBadOptions(t *testing.T) {
	keys := mustStatic(t,
		StaticKeyConfig{AccessKeyID: testAccessKey, SecretAccessKey: testSecretKey},
	)
	tests := []struct {
		keys KeySource
		name string
		opts []Option
	}{
		{name: "no KeySource"},
		{name: "zero body limit", keys: keys, opts: []Option{WithBufferedPayload(0)}},
		{name: "negative skew", keys: keys, opts: []Option{WithMaxClockSkew(-time.Second)}},
		{name: "zero expiry", keys: keys, opts: []Option{WithMaxPresignExpiry(0)}},
		{
			name: "fractional expiry",
			keys: keys,
			opts: []Option{WithMaxPresignExpiry(1500 * time.Millisecond)},
		},
		{name: "nil clock", keys: keys, opts: []Option{WithClock(nil)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if v, err := New(tt.keys, tt.opts...); err == nil {
				t.Fatalf("New = %v, want an error", v)
			}
		})
	}

	// A streamed payload has no body limit, so WithBufferedPayload's is moot.
	if _, err := New(keys, WithBufferedPayload(0), WithStreamedPayload()); err != nil {
		t.Fatalf("streamed: %v", err)
	}
}

func TestDefaults(t *testing.T) {
	svc := jsonServices[0]
	v := mustNew(
		t,
		mustStatic(t, StaticKeyConfig{AccessKeyID: testAccessKey, SecretAccessKey: testSecretKey}),
		WithClock(fixedClock(signedAt)),
	)

	// An AWS JSON call signed by the SDK verifies with the defaults.
	if err := v.check(svc.signJSON(t, svc.body)); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// Host and X-Amz-Date are required; X-Amz-Target is not.
	r := svc.signWith(t, svc.body, sha256Hex(svc.body), map[string]string{"Content-Type": jsonType})
	if err := v.check(r); err != nil {
		t.Fatalf("Verify without X-Amz-Target: %v", err)
	}
	r = withAuth(func(t *testing.T) *http.Request {
		t.Helper()
		return svc.signJSON(t, svc.body)
	}, replacer("host;", ""))(t)
	if e := asKind(t, v.check(r), KindUnsignedHeader); e.Header != "host" {
		t.Fatalf("Header = %q, want host", e.Header)
	}
}

func TestBufferedPayloadLimit(t *testing.T) {
	svc := jsonServices[0]
	v := jsonVerifier(t, WithBufferedPayload(int64(len(svc.body))))
	if err := v.check(svc.signJSON(t, svc.body)); err != nil {
		t.Fatalf("body at the limit: %v", err)
	}
	wantKind(t, v.check(svc.signJSON(t, svc.body+" ")), KindBodyTooLarge)
}

func TestBodyUnreadableWrapsTheReadError(t *testing.T) {
	svc := jsonServices[0]
	r := svc.signJSON(t, svc.body)
	r.Body = io.NopCloser(failingReader{})
	e := asKind(t, jsonVerifier(t).check(r), KindBodyUnreadable)
	if !errors.Is(e, errConnReset) {
		t.Fatalf("Err = %v, want the read error", e.Err)
	}
}

type opaqueCase struct {
	name    string
	hash    string
	wantMsg string // empty when accepted
	opts    []Option
}

func opaqueCases() []opaqueCase {
	const streaming = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
	return []opaqueCase{
		{
			name: "unsigned allowed", hash: unsignedPayload,
			opts: []Option{WithUnsignedPayload(true)},
		},
		{
			name: "streaming allowed", hash: streaming,
			opts: []Option{WithStreamingPayload(true)},
		},
		{
			name: "any allowed", hash: "anything",
			opts: []Option{WithAnyPayloadHash(true)},
		},
		{
			name: "streaming refused, unsigned allowed", hash: streaming,
			opts: []Option{WithUnsignedPayload(true)},
			wantMsg: "x-amz-content-sha256 must be the hex SHA-256 of the request body or " +
				"UNSIGNED-PAYLOAD; STREAMING-* payloads are not accepted.",
		},
		{
			name: "other refused, unsigned allowed", hash: "anything",
			opts: []Option{WithUnsignedPayload(true), WithStreamingPayload(true)},
			wantMsg: "x-amz-content-sha256 must be the hex SHA-256 of the request body or " +
				"UNSIGNED-PAYLOAD.",
		},
		{
			name: "unsigned refused, streaming allowed", hash: unsignedPayload,
			opts: []Option{WithStreamingPayload(true)},
			wantMsg: "x-amz-content-sha256 must be the hex SHA-256 of the request body; " +
				"UNSIGNED-PAYLOAD is not accepted.",
		},
	}
}

func TestOpaquePayloadHashes(t *testing.T) {
	svc := jsonServices[0]
	for _, streamed := range []bool{false, true} {
		for _, tt := range opaqueCases() {
			t.Run(modeLabel(streamed)+"/"+tt.name, func(t *testing.T) {
				opts := tt.opts
				if streamed {
					opts = slices.Concat(opts, []Option{WithStreamedPayload()})
				}
				r := svc.signWith(t, svc.body, tt.hash, map[string]string{
					"Content-Type":         jsonType,
					targetHeader:           svc.readTarget,
					"X-Amz-Content-Sha256": tt.hash,
				})
				err := jsonVerifier(t, opts...).check(r)
				if tt.wantMsg == "" {
					if err != nil {
						t.Fatalf("Verify: %v", err)
					}
					// The body is not checked against an opaque hash.
					if got, _ := io.ReadAll(r.Body); string(got) != svc.body {
						t.Fatalf("body = %q", got)
					}
					return
				}
				if e := asKind(t, err, KindPayloadHashNotAccepted); e.Message != tt.wantMsg {
					t.Fatalf("message = %q, want %q", e.Message, tt.wantMsg)
				}
			})
		}
	}
}

func modeLabel(streamed bool) string {
	if streamed {
		return "streamed"
	}
	return "buffered"
}

func TestStreamedPayloadLeavesTheBodyUnread(t *testing.T) {
	r := s3SignedRequest(t, s3Target, s3AccessKey, s3SecretKey)
	body := &countingReader{r: strings.NewReader(s3Body)}
	r.Body = io.NopCloser(body)
	if err := s3Verifier(t).check(r); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if body.n != 0 {
		t.Fatalf("Verify read %d bytes of the body", body.n)
	}
	if got, err := io.ReadAll(r.Body); err != nil || string(got) != s3Body {
		t.Fatalf("body = %q, %v", got, err)
	}
}

type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err //nolint:wrapcheck // io.Reader contract
}

func TestStreamedPayloadAcceptsUpperCaseHex(t *testing.T) {
	r := s3SignedRequest(t, s3Target, s3AccessKey, s3SecretKey)
	if err := s3Verifier(t).check(r); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	// The declared hash is compared case-insensitively, as before.
	pv, ok := r.Body.(*payloadVerifier)
	if !ok {
		t.Fatalf("body is %T, want a payload verifier", r.Body)
	}
	pv.want = strings.ToUpper(pv.want)
	if _, err := io.ReadAll(r.Body); err != nil {
		t.Fatalf("read: %v", err)
	}
}

func TestMaxClockSkew(t *testing.T) {
	svc := jsonServices[0]
	at := func(d time.Duration) *Verifier {
		return jsonVerifier(
			t,
			WithMaxClockSkew(time.Minute),
			WithClock(fixedClock(signedAt.Add(d))),
		)
	}
	for _, d := range []time.Duration{time.Minute, -time.Minute} {
		if err := at(d).check(svc.signJSON(t, svc.body)); err != nil {
			t.Fatalf("skew %v: %v", d, err)
		}
	}
	for _, d := range []time.Duration{time.Minute + time.Second, -time.Minute - time.Second} {
		wantKind(t, at(d).check(svc.signJSON(t, svc.body)), KindRequestTimeTooSkewed)
	}
}

func TestMaxPresignExpiry(t *testing.T) {
	v := s3Verifier(t, WithMaxPresignExpiry(time.Hour))
	if err := v.check(s3PresignedRequest(t, s3Target, time.Hour)); err != nil {
		t.Fatalf("an hour: %v", err)
	}
	r := s3PresignedRequest(t, s3Target, time.Hour+time.Second)
	e := asKind(t, v.check(r), KindInvalidExpires)
	if want := "X-Amz-Expires must be a number of seconds between 1 and 3600"; e.Message != want {
		t.Fatalf("message = %q, want %q", e.Message, want)
	}
}

func TestPresignedURLDoesNotNeedXAmzDateSigned(t *testing.T) {
	// X-Amz-Date is signed in a presigned URL's query, so requiring it
	// signed as a header does not refuse one.
	v := s3Verifier(t, WithRequiredSignedHeaders("Host", "X-Amz-Date"))
	if err := v.check(s3PresignedRequest(t, s3Target, time.Hour)); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	e := asKind(t, s3Verifier(t, WithRequiredSignedHeaders("content-type")).check(
		s3PresignedRequest(t, s3Target, time.Hour)), KindUnsignedHeader)
	if !e.Presigned || e.Header != "content-type" {
		t.Fatalf("error = %+v", e)
	}
}

// keyFunc is a KeySource from a function.
type keyFunc func(ctx context.Context, scope Scope) (Key, error)

func (f keyFunc) SigningKey(ctx context.Context, scope Scope) (Key, error) {
	return f(ctx, scope)
}

func TestKeySourceGetsTheCredentialScope(t *testing.T) {
	svc := jsonServices[0]
	static := mustStatic(t,
		StaticKeyConfig{AccessKeyID: testAccessKey, SecretAccessKey: testSecretKey},
	)

	var got Scope
	recording := keyFunc(func(ctx context.Context, scope Scope) (Key, error) {
		got = scope
		return static.SigningKey(ctx, scope)
	})
	v := mustNew(t, recording, append(jsonOptions(), WithClock(fixedClock(signedAt)))...)
	if err := v.check(svc.signJSON(t, svc.body)); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	want := Scope{
		AccessKeyID: testAccessKey,
		Date:        "20260304",
		Region:      "us-east-1",
		Service:     svc.name,
	}
	if got != want {
		t.Fatalf("scope = %+v, want %+v", got, want)
	}
}

func TestKeySourceFailures(t *testing.T) {
	svc := jsonServices[0]
	lookupErr := errors.New("key store unavailable")
	tests := []struct {
		source  KeySource
		wantErr error
		name    string
		want    Kind
	}{
		{
			name: "wrapped unknown key",
			source: keyFunc(func(context.Context, Scope) (Key, error) {
				return Key{}, errors.Join(ErrUnknownAccessKey, errors.New("revoked"))
			}),
			want:    KindUnknownAccessKey,
			wantErr: ErrUnknownAccessKey,
		},
		{
			name: "lookup failure",
			source: keyFunc(func(context.Context, Scope) (Key, error) {
				return Key{}, lookupErr
			}),
			want:    KindKeyLookupFailed,
			wantErr: lookupErr,
		},
		{
			name:   "empty key",
			source: keyFunc(func(context.Context, Scope) (Key, error) { return Key{}, nil }),
			want:   KindKeyLookupFailed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := mustNew(t, tt.source, append(jsonOptions(), WithClock(fixedClock(signedAt)))...)
			err := v.check(svc.signJSON(t, svc.body))
			wantKind(t, err, tt.want)
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want it to wrap %v", err, tt.wantErr)
			}
		})
	}
}

func TestDeriveSigningKey(t *testing.T) {
	// The example in the AWS documentation's "Derive a signing key".
	got := DeriveSigningKey(
		"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		"20120215",
		"us-east-1",
		"iam",
	)
	want, err := hex.DecodeString(
		"f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("key = %x, want %x", got, want)
	}
}

func TestStaticKey(t *testing.T) {
	ctx := context.Background()
	scope := Scope{AccessKeyID: "AKID", Date: "20261015", Region: "us-east-1", Service: "s3"}

	key, err := mustStatic(t, StaticKeyConfig{AccessKeyID: "AKID", SecretAccessKey: "secret"}).
		SigningKey(ctx, scope)
	if err != nil {
		t.Fatalf("SigningKey: %v", err)
	}
	want := Principal{
		AccountID: DefaultAccountID, ARN: "arn:aws:iam::000000000000:root", AccessKeyID: "AKID",
		Root: true,
	}
	if !reflect.DeepEqual(key.Principal, want) {
		t.Fatalf("principal = %+v, want %+v", key.Principal, want)
	}
	if !bytes.Equal(key.Signing, DeriveSigningKey("secret", "20261015", "us-east-1", "s3")) {
		t.Fatalf("signing key = %x", key.Signing)
	}

	named := mustStatic(t, StaticKeyConfig{
		AccessKeyID: "AKID", SecretAccessKey: "secret",
		AccountID: "123456789012", ARN: "arn:aws:iam::123456789012:user/dev",
	})
	if key, _ = named.SigningKey(
		ctx,
		scope,
	); key.Principal.ARN != "arn:aws:iam::123456789012:user/dev" ||
		key.Principal.AccountID != "123456789012" {
		t.Fatalf("principal = %+v", key.Principal)
	}
	accountOnly := mustStatic(t, StaticKeyConfig{
		AccessKeyID: "AKID", SecretAccessKey: "secret", AccountID: "123456789012",
	})
	if key, _ = accountOnly.SigningKey(
		ctx,
		scope,
	); key.Principal.ARN != "arn:aws:iam::123456789012:root" {
		t.Fatalf("default ARN = %q", key.Principal.ARN)
	}

	other := scope
	other.AccessKeyID = "akid"
	if _, err = named.SigningKey(ctx, other); !errors.Is(err, ErrUnknownAccessKey) {
		t.Fatalf("other key: err = %v, want ErrUnknownAccessKey", err)
	}
	withToken := scope
	withToken.SessionToken = "token"
	if _, err = named.SigningKey(ctx, withToken); !errors.Is(err, ErrInvalidSessionToken) {
		t.Fatalf("token: err = %v, want ErrInvalidSessionToken", err)
	}
}

func TestVerifyPutsThePrincipalInTheContext(t *testing.T) {
	svc := jsonServices[0]
	r := svc.signJSON(t, svc.body)
	if _, ok := PrincipalFrom(r.Context()); ok {
		t.Fatal("an unverified request carries a principal")
	}
	got, err := jsonVerifier(t).Verify(r)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	// The static key's principal: Root, with no policies.
	want := Principal{
		AccountID: DefaultAccountID, ARN: "arn:aws:iam::000000000000:root",
		AccessKeyID: testAccessKey, Root: true,
	}
	if p, ok := PrincipalFrom(got.Context()); !ok || !reflect.DeepEqual(p, want) {
		t.Fatalf("principal = %+v, %v; want %+v", p, ok, want)
	}
	if body, _ := io.ReadAll(got.Body); string(body) != svc.body {
		t.Fatalf("body = %q", body)
	}

	r = svc.signJSON(t, svc.body)
	r.Header.Del("Authorization")
	if got, err = jsonVerifier(t).Verify(r); got != nil || err == nil {
		t.Fatalf("Verify = %v, %v; want nil and an error", got, err)
	}
}

// policyKeys is a KeySource that answers with the static test key's signing
// key and its own principal, the way the identity service supplies one.
type policyKeys struct {
	static    *StaticKey
	principal Principal
}

func (k policyKeys) SigningKey(ctx context.Context, scope Scope) (Key, error) {
	key, err := k.static.SigningKey(ctx, scope)
	key.Principal = k.principal
	return key, err
}

func TestVerifyPassesRootAndPoliciesThrough(t *testing.T) {
	policies := []json.RawMessage{
		json.RawMessage(`{"Version":"2012-10-17","Statement":[` +
			`{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"*"}]}`),
		// Not valid JSON: sigv4 does not interpret policies.
		json.RawMessage(`{not a policy`),
	}
	static := mustStatic(
		t,
		StaticKeyConfig{AccessKeyID: testAccessKey, SecretAccessKey: testSecretKey},
	)
	for name, want := range map[string]Principal{
		"policies": {
			AccountID: "111122223333", ARN: "arn:aws:iam::111122223333:user/dev",
			AccessKeyID: testAccessKey, Policies: policies,
		},
		"root": {
			AccountID: "111122223333", ARN: "arn:aws:iam::111122223333:root",
			AccessKeyID: testAccessKey, Root: true, Policies: policies,
		},
	} {
		t.Run(name, func(t *testing.T) {
			svc := jsonServices[0]
			v := mustNew(t, policyKeys{static: static, principal: want},
				append(jsonOptions(), WithClock(fixedClock(signedAt)))...)
			got, err := v.Verify(svc.signJSON(t, svc.body))
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			p, ok := PrincipalFrom(got.Context())
			if !ok || !reflect.DeepEqual(p, want) {
				t.Fatalf("principal = %+v, %v; want %+v", p, ok, want)
			}
		})
	}
}

// Principals shaped as the IAM User Guide's examples: aws:PrincipalArn,
// aws:userid and aws:PrincipalType as AWS gives them for each kind of
// principal, and, for the role session, its role tags and session tags as
// merged.
func TestVerifyPassesPrincipalAttributesThrough(t *testing.T) {
	static := mustStatic(
		t,
		StaticKeyConfig{AccessKeyID: testAccessKey, SecretAccessKey: testSecretKey},
	)
	for name, want := range map[string]Principal{
		"user": {
			AccountID:    "111122223333",
			ARN:          "arn:aws:iam::111122223333:user/division_abc/subdivision_xyz/app-runner",
			PrincipalARN: "arn:aws:iam::111122223333:user/division_abc/subdivision_xyz/app-runner",
			UserID:       "AIDACKCEVSQ6C2EXAMPLE",
			Type:         PrincipalTypeUser,
			Tags:         map[string]string{"team": "yellow"},
			AccessKeyID:  testAccessKey,
		},
		"role session": {
			AccountID:    "111122223333",
			ARN:          "arn:aws:sts::111122223333:assumed-role/RDSAccess/ci-session",
			PrincipalARN: "arn:aws:iam::111122223333:role/application_abc/component_xyz/RDSAccess",
			UserID:       "AROADBQP57FF2AEXAMPLE:ci-session",
			Type:         PrincipalTypeAssumedRole,
			Tags:         map[string]string{"Department": "engineering", "Project": "Pegasus"},
			AccessKeyID:  testAccessKey,
		},
		"root": {
			AccountID:    "111122223333",
			ARN:          "arn:aws:iam::111122223333:root",
			PrincipalARN: "arn:aws:iam::111122223333:root",
			UserID:       "111122223333",
			Type:         PrincipalTypeAccount,
			AccessKeyID:  testAccessKey,
			Root:         true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			svc := jsonServices[0]
			v := mustNew(t, policyKeys{static: static, principal: want},
				append(jsonOptions(), WithClock(fixedClock(signedAt)))...)
			got, err := v.Verify(svc.signJSON(t, svc.body))
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			p, ok := PrincipalFrom(got.Context())
			if !ok || !reflect.DeepEqual(p, want) {
				t.Fatalf("principal = %+v, %v; want %+v", p, ok, want)
			}
		})
	}
}

func TestPrincipalTypesAreAWSValues(t *testing.T) {
	// The aws:PrincipalType values of the IAM User Guide's principal key
	// values table.
	for got, want := range map[PrincipalType]string{
		PrincipalTypeAccount:     "Account",
		PrincipalTypeUser:        "User",
		PrincipalTypeAssumedRole: "AssumedRole",
	} {
		if string(got) != want {
			t.Errorf("principal type = %q, want %q", got, want)
		}
	}
}

func TestVerifyPutsTheScopeInTheContext(t *testing.T) {
	svc := jsonServices[0]
	r := svc.signJSON(t, svc.body)
	if _, ok := ScopeFrom(r.Context()); ok {
		t.Fatal("an unverified request carries a scope")
	}
	got, err := jsonVerifier(t).Verify(r)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// The scope is the one the Authorization header's credential names.
	_, cred, _ := strings.Cut(r.Header.Get("Authorization"), "Credential=")
	cred, _, _ = strings.Cut(cred, ",")
	parts := strings.Split(cred, "/")
	if len(parts) != 5 {
		t.Fatalf("credential = %q", cred)
	}
	want := Scope{AccessKeyID: parts[0], Date: parts[1], Region: parts[2], Service: parts[3]}
	if s, ok := ScopeFrom(got.Context()); !ok || s != want {
		t.Fatalf("scope = %+v, %v; want %+v", s, ok, want)
	}
}

func TestErrorMapAppliesToStreamedBody(t *testing.T) {
	r := s3SignedRequest(t, s3Target, s3AccessKey, s3SecretKey)
	r.Body = io.NopCloser(strings.NewReader("tampered"))
	if err := s3Verifier(t, WithErrorMap(s3Map)).check(r); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	_, err := io.ReadAll(r.Body)
	wantWire(t, err, wire{
		status: http.StatusBadRequest, code: "XAmzContentSHA256Mismatch", message: hashMismatchText,
	})
}

func TestKindString(t *testing.T) {
	for k := KindMissingAuth; k <= KindSignatureMismatch; k++ {
		if s := k.String(); s == "" || strings.HasPrefix(s, "Kind(") {
			t.Fatalf("Kind %d has no name", k)
		}
	}
	if got := Kind(0).String(); got != "Kind(0)" {
		t.Fatalf("Kind(0) = %q", got)
	}
	e := &Error{Kind: KindExpired, Message: "Request has expired"}
	if got := e.Error(); got != "sigv4: Expired: Request has expired" {
		t.Fatalf("Error() = %q", got)
	}
}

func TestVerifyConcurrently(t *testing.T) {
	svc := jsonServices[0]
	v := jsonVerifier(t)
	reqs := make([]*http.Request, 16)
	for i := range reqs {
		reqs[i] = svc.signJSON(t, svc.body)
	}

	var wg sync.WaitGroup
	errs := make([]error, len(reqs))
	for i, r := range reqs {
		wg.Go(func() { errs[i] = v.check(r) })
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
}

func TestStaticKeyRefusesAnEmptyKey(t *testing.T) {
	// An empty access key ID and secret would accept a request signed with
	// an empty key, which any client can produce.
	for _, cfg := range []StaticKeyConfig{
		{},
		{AccessKeyID: "AKID"},
		{SecretAccessKey: "secret"},
	} {
		if k, err := NewStaticKey(cfg); err == nil || k != nil {
			t.Fatalf("NewStaticKey(%+v) = %v, %v; want an error", cfg, k, err)
		}
	}
}

func TestKeySourceWithoutAnAccountFails(t *testing.T) {
	// A handler scopes data by the principal's account; a key that names
	// none must not verify a request as if it did.
	svc := jsonServices[0]
	noAccount := keyFunc(func(_ context.Context, s Scope) (Key, error) {
		return Key{
			Principal: Principal{ARN: "arn:aws:iam::000000000000:root", AccessKeyID: s.AccessKeyID},
			Signing:   DeriveSigningKey(testSecretKey, s.Date, s.Region, s.Service),
		}, nil
	})
	v := mustNew(t, noAccount, append(jsonOptions(), WithClock(fixedClock(signedAt)))...)
	wantKind(t, v.check(svc.signJSON(t, svc.body)), KindKeyLookupFailed)
}
