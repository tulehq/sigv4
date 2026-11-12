package sigv4

// Regression tests for the findings of the security review, each a request
// that used to verify and must not.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// s3Put returns a PUT of body signed by the SDK as the S3 client signs it,
// with the headers set before signing.
func s3Put(t *testing.T, target, body string, headers map[string]string) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(
		context.Background(), http.MethodPut, target, strings.NewReader(body),
	)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	hash := sha256Hex(body)
	r.Header.Set("X-Amz-Content-Sha256", hash)
	err := s3Signer().SignHTTP(context.Background(), aws.Credentials{
		AccessKeyID: s3AccessKey, SecretAccessKey: s3SecretKey,
	}, r, hash, "s3", "eu-west-1", s3SignTime)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return r
}

func TestUnsignedAmzHeadersAreRefused(t *testing.T) {
	// An unsigned X-Amz-Copy-Source would turn a signed upload into a copy
	// of another object; every x-amz-* header must be signed.
	r := s3Put(t, s3Target, s3Body, nil)
	r.Header.Set("X-Amz-Copy-Source", "private/secrets.txt")
	r.Header.Set("X-Amz-Acl", "public-read")
	e := asKind(t, s3Verifier(t).check(r), KindUnsignedHeader)
	if e.Header != "x-amz-acl" || e.Presigned {
		t.Fatalf("error = %+v, want the first unsigned header, x-amz-acl", e)
	}

	r = s3PresignedRequest(t, s3Target, time.Hour)
	r.Header.Set("X-Amz-Copy-Source", "private/secrets.txt")
	e = asKind(t, s3Verifier(t).check(r), KindUnsignedHeader)
	if e.Header != "x-amz-copy-source" || !e.Presigned {
		t.Fatalf("error = %+v", e)
	}

	// An X-Amzn-* header is not an x-amz-* one; the signer leaves
	// X-Amzn-Trace-Id out.
	r = s3Put(t, s3Target, s3Body, nil)
	r.Header.Set("X-Amzn-Trace-Id", "Root=1-abc")
	if err := s3Verifier(t).check(r); err != nil {
		t.Fatalf("X-Amzn-Trace-Id: %v", err)
	}
}

func TestSignedAmzHeadersVerify(t *testing.T) {
	// The SDK signs every x-amz-* header it sends: in the header of a
	// signed request, and on a presigned URL either hoisted into the query
	// or, for those it keeps as headers, among the signed headers.
	headers := map[string]string{
		"X-Amz-Copy-Source": "bucket/other", "X-Amz-Acl": "private",
		"X-Amz-Meta-Note": "a b", "X-Amz-Storage-Class": "STANDARD",
	}
	if err := s3Verifier(t).check(s3Put(t, s3Target, s3Body, headers)); err != nil {
		t.Fatalf("signed: %v", err)
	}

	r := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodPut,
		s3Target+"?X-Amz-Expires=3600",
		nil,
	)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	r.Header.Set("X-Amz-Tagging", "a=b")
	r.Header.Set("X-Amz-Expected-Bucket-Owner", "111122223333")
	u, signedHeaders, err := s3Signer().PresignHTTP(context.Background(), aws.Credentials{
		AccessKeyID: s3AccessKey, SecretAccessKey: s3SecretKey,
	}, r, unsignedPayload, "s3", "eu-west-1", s3SignTime)
	if err != nil {
		t.Fatalf("presign: %v", err)
	}
	pr := httptest.NewRequestWithContext(context.Background(), http.MethodPut, u, nil)
	for k, vals := range signedHeaders {
		if !strings.EqualFold(k, "host") {
			pr.Header[k] = vals
		}
	}
	if err = s3Verifier(t).check(pr); err != nil {
		t.Fatalf("presigned: %v", err)
	}
}
