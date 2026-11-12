package sigv4

// The tests of object-store's verifier, ported: the same conditions, through
// a verifier configured as object-store is to configure it.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

const (
	s3AccessKey = "AKID"
	s3SecretKey = "secret"
	// s3Body is what signed S3 requests upload.
	s3Body = "hello"
)

var s3SignTime = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

func s3Verifier(t *testing.T, opts ...Option) *Verifier {
	t.Helper()
	all := append(s3Options(), WithClock(fixedClock(s3SignTime.Add(time.Minute))))
	return mustNew(t, NewStaticKey(s3AccessKey, s3SecretKey), append(all, opts...)...)
}

// s3Signer signs the way the S3 client signs: without re-escaping the path.
func s3Signer() *v4.Signer {
	return v4.NewSigner(func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true })
}

// s3SignedRequest builds a PUT of s3Body signed by the AWS SDK signer.
func s3SignedRequest(t *testing.T, target, accessKey, secretKey string) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(
		context.Background(), http.MethodPut, target, strings.NewReader(s3Body),
	)
	hash := sha256Hex(s3Body)
	r.Header.Set("X-Amz-Content-Sha256", hash)
	r.Header.Set("Content-Type", "text/plain")

	err := s3Signer().SignHTTP(context.Background(), aws.Credentials{
		AccessKeyID: accessKey, SecretAccessKey: secretKey,
	}, r, hash, "s3", "eu-west-1", s3SignTime)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return r
}

// s3PresignedRequest presigns a GET of target, as a download link is.
func s3PresignedRequest(t *testing.T, target string, expires time.Duration) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	q := r.URL.Query()
	q.Set("X-Amz-Expires", strconv.Itoa(int(expires.Seconds())))
	r.URL.RawQuery = q.Encode()

	u, _, err := s3Signer().PresignHTTP(context.Background(), aws.Credentials{
		AccessKeyID: s3AccessKey, SecretAccessKey: s3SecretKey,
	}, r, unsignedPayload, "s3", "us-east-1", s3SignTime)
	if err != nil {
		t.Fatalf("presign: %v", err)
	}
	return httptest.NewRequestWithContext(context.Background(), http.MethodGet, u, nil)
}

func TestS3VerifyHeader(t *testing.T) {
	const target = "http://localhost:9000/bucket/dir/sub%20dir/file%3D%2B%26%40%21.txt?uploads="
	r := s3SignedRequest(t, target, s3AccessKey, s3SecretKey)
	if err := s3Verifier(t).Verify(r); err != nil {
		t.Fatalf("verify: %v", err)
	}
	got, err := io.ReadAll(r.Body)
	if err != nil || string(got) != s3Body {
		t.Fatalf("body: %q %v", got, err)
	}
}

func TestS3VerifyHeaderFailures(t *testing.T) {
	const target = "http://localhost:9000/bucket/key"

	r := s3SignedRequest(t, target, s3AccessKey, s3SecretKey)
	r.URL.Path = "/bucket/other"
	wantKind(t, s3Verifier(t).Verify(r), KindSignatureMismatch)

	r = s3SignedRequest(t, target, s3AccessKey, "wrong")
	wantKind(t, s3Verifier(t).Verify(r), KindSignatureMismatch)

	r = s3SignedRequest(t, target, "OTHER", s3SecretKey)
	wantKind(t, s3Verifier(t).Verify(r), KindUnknownAccessKey)

	r = s3SignedRequest(t, target, s3AccessKey, s3SecretKey)
	v := s3Verifier(t, WithClock(fixedClock(s3SignTime.Add(time.Hour))))
	wantKind(t, v.Verify(r), KindRequestTimeTooSkewed)

	r = httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	wantKind(t, s3Verifier(t).Verify(r), KindMissingAuth)

	r.Header.Set("Authorization", "AWS AKID:abc")
	wantKind(t, s3Verifier(t).Verify(r), KindUnsupportedAlgorithm)
}

func TestS3VerifyPayloadMismatch(t *testing.T) {
	r := s3SignedRequest(t, "http://localhost:9000/bucket/key", s3AccessKey, s3SecretKey)
	// The signature covers the declared hash, not the body, so a body swapped
	// in flight passes Verify and fails the read that reaches its end.
	r.Body = io.NopCloser(strings.NewReader("tampered"))
	if err := s3Verifier(t).Verify(r); err != nil {
		t.Fatalf("verify: %v", err)
	}
	_, err := io.ReadAll(r.Body)
	wantKind(t, err, KindPayloadHashMismatch)
}

func TestS3VerifyPresigned(t *testing.T) {
	const target = "http://localhost:9000/bucket/up/loaded%20file.txt"

	r := s3PresignedRequest(t, target, time.Hour)
	if err := s3Verifier(t).Verify(r); err != nil {
		t.Fatalf("verify: %v", err)
	}

	r = s3PresignedRequest(t, target, 30*time.Second)
	wantKind(t, s3Verifier(t).Verify(r), KindExpired)

	r = s3PresignedRequest(t, target, time.Hour)
	r.Method = http.MethodPut
	wantKind(t, s3Verifier(t).Verify(r), KindSignatureMismatch)
}
