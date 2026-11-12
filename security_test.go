package sigv4

// Regression tests for the findings of the security review, each a request
// that used to verify and must not.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
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

// deleteBodies returns a DeleteObjects body and a forged one of the same
// length naming another key, padded with the spaces XML ignores.
func deleteBodies() (orig, forged string) {
	var sb strings.Builder
	sb.WriteString("<Delete>")
	for sb.Len() < 6000 {
		sb.WriteString("<Object><Key>logs/tmp-00000000</Key></Object>")
	}
	sb.WriteString("</Delete>")
	orig = sb.String()
	forged = "<Delete><Object><Key>prod/important.db</Key></Object></Delete>"
	return orig, forged + strings.Repeat(" ", len(orig)-len(forged))
}

type deleteRequest struct {
	XMLName xml.Name `xml:"Delete"`
	Keys    []string `xml:"Object>Key"`
}

func TestStreamedEarlyStopFailsOnClose(t *testing.T) {
	// A decoder stops at the end of its value, short of Content-Length, so
	// its reads never reach the check; Close reads the rest and makes it.
	orig, forged := deleteBodies()
	r := s3Put(t, s3Target+"?delete", orig, nil)
	r.Body = io.NopCloser(strings.NewReader(forged))
	if err := s3Verifier(t).check(r); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	var d deleteRequest
	if err := xml.NewDecoder(r.Body).Decode(&d); err != nil {
		t.Fatalf("decode: %v", err)
	}
	wantKind(t, r.Body.Close(), KindPayloadHashMismatch)

	// The same early stop over the signed body closes cleanly.
	r = s3Put(t, s3Target+"?delete", orig, nil)
	if err := s3Verifier(t).check(r); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if err := xml.NewDecoder(r.Body).Decode(&d); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := r.Body.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestStreamedCloseUnknownLength(t *testing.T) {
	// Without a Content-Length, Close reads to EOF, up to
	// DefaultMaxBodySize, and fails a body it cannot verify within it.
	r := streamed(t, strings.NewReader(tampered), -1)
	wantKind(t, r.Body.Close(), KindPayloadHashMismatch)

	r = streamed(t, strings.NewReader(s3Body), -1)
	if err := r.Body.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestReadBody(t *testing.T) {
	orig, forged := deleteBodies()
	v := s3Verifier(t)

	r := s3Put(t, s3Target+"?delete", orig, nil)
	if err := v.check(r); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	got, err := v.ReadBody(r, 1<<20)
	if err != nil || string(got) != orig {
		t.Fatalf("ReadBody = %d bytes, %v", len(got), err)
	}

	r = s3Put(t, s3Target+"?delete", orig, nil)
	r.Body = io.NopCloser(strings.NewReader(forged))
	if err = v.check(r); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got, err = v.ReadBody(r, 1<<20); got != nil {
		t.Fatalf("ReadBody returned the forged body")
	}
	wantKind(t, err, KindPayloadHashMismatch)

	r = s3Put(t, s3Target+"?delete", orig, nil)
	if err = v.check(r); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	_, err = v.ReadBody(r, int64(len(orig)-1))
	wantKind(t, err, KindBodyTooLarge)
}

func TestReadBodyRefusesAnUnverifiedBody(t *testing.T) {
	// An UNSIGNED-PAYLOAD body is covered by no hash, so it cannot be
	// returned as verified.
	r := httptest.NewRequestWithContext(
		context.Background(), http.MethodPut, s3Target, strings.NewReader(s3Body),
	)
	r.Header.Set("X-Amz-Content-Sha256", unsignedPayload)
	err := s3Signer().SignHTTP(context.Background(), aws.Credentials{
		AccessKeyID: s3AccessKey, SecretAccessKey: s3SecretKey,
	}, r, unsignedPayload, "s3", "eu-west-1", s3SignTime)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	v := s3Verifier(t, WithErrorMap(s3Map))
	if err = v.check(r); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	_, err = v.ReadBody(r, 1<<20)
	var we *wireError
	if !errors.As(err, &we) {
		t.Fatalf("ReadBody = %v, want the mapped error", err)
	}
	_, err = s3Verifier(t).ReadBody(r, 1<<20)
	wantKind(t, err, KindUnverifiedPayload)

	// A buffered body is the bytes the signature covered.
	svc := jsonServices[0]
	jv := jsonVerifier(t)
	r = svc.signJSON(t, svc.body)
	if err = jv.check(r); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got, err := jv.ReadBody(r, 1<<20); err != nil || string(got) != svc.body {
		t.Fatalf("ReadBody = %q, %v", got, err)
	}
}

func TestSignedHeadersMustBeStrict(t *testing.T) {
	tests := []struct {
		list string
		ok   bool
	}{
		{list: "host", ok: true},
		{list: "content-type;host;x-amz-date;x-amz-target", ok: true},
		{list: "host;x-amz-date;x-amz-meta-a_b.c", ok: true},
		{list: ""},
		{list: "host;"},
		{list: ";host"},
		{list: "host;;x-amz-date"},
		{list: "Host;x-amz-date"},
		{list: "host;x-amz-date; x-amz-target"},
		{list: "host ;x-amz-date"},
		{list: "x-amz-date;host"},
		{list: "host;host"},
		{list: "host;x-amz-date;a"},
		{list: "host;x amz"},
		{list: "host;x:amz"},
	}
	for _, tt := range tests {
		t.Run(tt.list, func(t *testing.T) {
			names, ok := parseSignedHeaders(tt.list)
			if ok != tt.ok {
				t.Fatalf("ok = %v, want %v", ok, tt.ok)
			}
			if ok && strings.Join(names, ";") != tt.list {
				t.Fatalf("names = %q", names)
			}
		})
	}

	many := make([]string, MaxSignedHeaders+1)
	for i := range many {
		many[i] = fmt.Sprintf("x-h%04d", i)
	}
	if _, ok := parseSignedHeaders(strings.Join(many[:MaxSignedHeaders], ";")); !ok {
		t.Fatalf("%d headers refused", MaxSignedHeaders)
	}
	if _, ok := parseSignedHeaders(strings.Join(many, ";")); ok {
		t.Fatalf("%d headers accepted", MaxSignedHeaders+1)
	}
}

// handSigned signs a JSON request by hand, with the SignedHeaders list and
// canonical headers given, as a client that does not follow the spec could.
func handSigned(t *testing.T, r *http.Request, signedHeaders, canonHeaders, payload string) {
	t.Helper()
	date := signedAt.Format(amzDateFmt)
	creq := strings.Join([]string{r.Method, "/", "", canonHeaders, signedHeaders, payload}, "\n")
	sum := sha256.Sum256([]byte(creq))
	scope := signedAt.Format(dateFmt) + "/us-east-1/secretsmanager/aws4_request"
	sts := algorithm + "\n" + date + "\n" + scope + "\n" + hex.EncodeToString(sum[:])
	key := DeriveSigningKey(testSecretKey, signedAt.Format(dateFmt), "us-east-1", "secretsmanager")
	r.Header.Set("Authorization", algorithm+" Credential="+testAccessKey+"/"+scope+
		", SignedHeaders="+signedHeaders+", Signature="+hex.EncodeToString(hmacSHA256(key, sts)))
}

func TestRequiredHeadersAreBoundAsSigned(t *testing.T) {
	// The required-header check and the canonical request must agree on
	// the names: " x-amz-target" and "Host" passed the check folded and
	// trimmed while signing an empty value, so the target or host could be
	// swapped.
	const body = `{"SecretId":"prod/db"}`
	date := signedAt.Format(amzDateFmt)
	mk := func() *http.Request {
		r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
			"http://secrets.local:4000/", strings.NewReader(body))
		r.Header.Set("X-Amz-Date", date)
		r.Header.Set(targetHeader, "secretsmanager.GetSecretValue")
		return r
	}

	r := mk()
	handSigned(t, r, "host;x-amz-date; x-amz-target",
		"host:secrets.local:4000\nx-amz-date:"+date+"\n x-amz-target:\n", sha256Hex(body))
	r.Header.Set(targetHeader, "secretsmanager.DeleteSecret")
	wantKind(t, jsonVerifier(t).check(r), KindIncompleteAuth)

	r = mk()
	handSigned(t, r, "Host;x-amz-date;x-amz-target",
		"Host:\nx-amz-date:"+date+"\nx-amz-target:secretsmanager.GetSecretValue\n", sha256Hex(body))
	r.Host = "other-server:9999"
	wantKind(t, jsonVerifier(t).check(r), KindIncompleteAuth)

	// Signed as the spec says, the same request verifies.
	r = mk()
	handSigned(
		t,
		r,
		"host;x-amz-date;x-amz-target",
		"host:secrets.local:4000\nx-amz-date:"+date+"\nx-amz-target:secretsmanager.GetSecretValue\n",
		sha256Hex(body),
	)
	if err := jsonVerifier(t).check(r); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestRepeatedSignedHeadersDoNotAmplify(t *testing.T) {
	// A 256 KiB header named a thousand times in SignedHeaders would make a
	// 256 MiB canonical request before the signature is checked.
	big := strings.Repeat("x", 256<<10)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"http://secrets.local:4000/", strings.NewReader("{}"))
	r.Header.Set("X-Amz-Date", signedAt.Format(amzDateFmt))
	r.Header.Set(targetHeader, "secretsmanager.GetSecretValue")
	r.Header.Set("A", big)
	r.Header.Set("Authorization", algorithm+" Credential="+testAccessKey+
		"/20260304/us-east-1/secretsmanager/aws4_request, SignedHeaders=host;x-amz-date;x-amz-target"+
		strings.Repeat(";a", 1000)+", Signature=00")

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	err := jsonVerifier(t).check(r)
	runtime.ReadMemStats(&after)
	wantKind(t, err, KindIncompleteAuth)
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 4<<20 {
		t.Fatalf("Verify allocated %d MiB", alloc>>20)
	}
}

func TestNilErrorMapFailsClosed(t *testing.T) {
	nilMap := WithErrorMap(func(*Error) error { return nil })

	svc := jsonServices[0]
	r := svc.signJSON(t, svc.body)
	r.Header.Set("Authorization", algorithm+" Credential=x/y/z/w/aws4_request, "+
		"SignedHeaders=host, Signature=00")
	got, err := jsonVerifier(t, nilMap).Verify(r)
	if got != nil {
		t.Fatalf("Verify returned a request for a failed verification")
	}
	wantKind(t, err, KindUnsignedHeader)

	// A streamed body that fails must keep failing, not read as an empty
	// body that never ends.
	r = s3Put(t, s3Target, s3Body, nil)
	r.Body = io.NopCloser(strings.NewReader(tampered))
	if err = s3Verifier(t, nilMap).check(r); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, rerr := io.ReadAll(r.Body)
		done <- rerr
	}()
	select {
	case err = <-done:
		wantKind(t, err, KindPayloadHashMismatch)
	case <-time.After(5 * time.Second):
		t.Fatal("ReadAll did not return")
	}
	wantKind(t, r.Body.Close(), KindPayloadHashMismatch)
}

func TestStreamedFailureIsSticky(t *testing.T) {
	r := streamed(t, strings.NewReader(tampered), int64(len(s3Body)))
	b := make([]byte, len(s3Body))
	_, err := io.ReadFull(r.Body, b)
	wantKind(t, err, KindPayloadHashMismatch)
	for i := range 3 {
		n, err := r.Body.Read(b)
		if n != 0 {
			t.Fatalf("read %d returned %d bytes", i, n)
		}
		wantKind(t, err, KindPayloadHashMismatch)
	}
}

func TestQuerySortsByKeyThenValue(t *testing.T) {
	// The SDK sorts the canonical query by encoded name, then by encoded
	// value; sorting "name=value" strings puts "a-b=2" before "a=1".
	for _, q := range []string{
		"a=1&a-b=2", "prefix=x&prefix1=y", "Action=X&Action.1=y", "k=b&k=a&k=", "a%20b=1&a=2",
	} {
		t.Run(q, func(t *testing.T) {
			r := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
				"http://localhost:9000/bucket?"+q, nil)
			hash := sha256Hex("")
			r.Header.Set("X-Amz-Content-Sha256", hash)
			err := s3Signer().SignHTTP(context.Background(), aws.Credentials{
				AccessKeyID: s3AccessKey, SecretAccessKey: s3SecretKey,
			}, r, hash, "s3", "eu-west-1", s3SignTime)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			if err = s3Verifier(t).check(r); err != nil {
				t.Fatalf("Verify: %v", err)
			}
		})
	}
}
