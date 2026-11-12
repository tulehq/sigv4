package sigv4

// A streamed body is checked against its declared hash on the read that
// reaches Content-Length, so a handler that reads exactly that many bytes
// and stops still sees a mismatch.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// streamed returns a verified S3 PUT whose declared hash is s3Body's, sent
// with body and Content-Length length (-1 for unknown, which the signer then
// leaves out of the signed headers).
func streamed(t *testing.T, body io.Reader, length int64) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPut, s3Target, body)
	r.ContentLength = length
	hash := sha256Hex(s3Body)
	r.Header.Set("X-Amz-Content-Sha256", hash)
	err := s3Signer().SignHTTP(context.Background(), aws.Credentials{
		AccessKeyID: s3AccessKey, SecretAccessKey: s3SecretKey,
	}, r, hash, "s3", "eu-west-1", s3SignTime)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err = s3Verifier(t).Verify(r); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	return r
}

// tampered is a body as long as s3Body that is not s3Body.
var tampered = strings.ToUpper(s3Body)

func TestStreamedPayloadConsumers(t *testing.T) {
	n := int64(len(s3Body))
	consumers := []struct {
		read func(r *http.Request) ([]byte, error)
		name string
	}{
		{name: "io.ReadFull", read: func(r *http.Request) ([]byte, error) {
			b := make([]byte, r.ContentLength)
			_, err := io.ReadFull(r.Body, b)
			return b, err //nolint:wrapcheck // the test checks the error ReadFull returns
		}},
		{name: "io.LimitReader", read: func(r *http.Request) ([]byte, error) {
			return io.ReadAll(io.LimitReader(r.Body, r.ContentLength))
		}},
		{name: "http.MaxBytesReader", read: func(r *http.Request) ([]byte, error) {
			return io.ReadAll(http.MaxBytesReader(httptest.NewRecorder(), r.Body, r.ContentLength))
		}},
		{
			name: "io.ReadAll",
			read: func(r *http.Request) ([]byte, error) { return io.ReadAll(r.Body) },
		},
		{name: "one byte at a time", read: func(r *http.Request) ([]byte, error) {
			return io.ReadAll(io.LimitReader(oneByteReader{r.Body}, r.ContentLength))
		}},
	}
	for _, c := range consumers {
		t.Run(c.name+"/matching", func(t *testing.T) {
			got, err := c.read(streamed(t, strings.NewReader(s3Body), n))
			if err != nil || string(got) != s3Body {
				t.Fatalf("read = %q, %v", got, err)
			}
		})
		t.Run(c.name+"/tampered", func(t *testing.T) {
			_, err := c.read(streamed(t, strings.NewReader(tampered), n))
			wantKind(t, err, KindPayloadHashMismatch)
		})
	}
}

// oneByteReader reads one byte per call, as a slow connection may.
type oneByteReader struct{ r io.Reader }

func (o oneByteReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return o.r.Read(p) //nolint:wrapcheck // io.Reader contract
}

func TestStreamedPayloadShortBody(t *testing.T) {
	// A body that ends before its Content-Length fails at EOF.
	r := streamed(t, strings.NewReader(s3Body[:3]), int64(len(s3Body)))
	_, err := io.ReadAll(r.Body)
	wantKind(t, err, KindPayloadHashMismatch)
}

func TestStreamedPayloadLongerThanContentLength(t *testing.T) {
	// The first Content-Length bytes match, but what follows is not covered
	// by the declared hash, so the read that runs past it fails and hands
	// none of it over.
	r := streamed(t, strings.NewReader(s3Body+" and more"), int64(len(s3Body)))
	got, err := io.ReadAll(r.Body)
	wantKind(t, err, KindPayloadHashMismatch)
	if len(got) > len(s3Body) {
		t.Fatalf("read %q, past Content-Length", got)
	}
}

func TestStreamedPayloadReadsPastAMatchedLength(t *testing.T) {
	// Content-Length is reached and matched on one read, and the extra bytes
	// arrive on the next.
	body := io.MultiReader(strings.NewReader(s3Body), strings.NewReader("extra"))
	r := streamed(t, body, int64(len(s3Body)))
	b := make([]byte, len(s3Body))
	if _, err := io.ReadFull(r.Body, b); err != nil {
		t.Fatalf("first read: %v", err)
	}
	n, err := r.Body.Read(make([]byte, 16))
	wantKind(t, err, KindPayloadHashMismatch)
	if n != 0 {
		t.Fatalf("read %d bytes past Content-Length", n)
	}
}

func TestStreamedPayloadUnknownLength(t *testing.T) {
	// Without a Content-Length the hash is checked at EOF, as before.
	got, err := io.ReadAll(streamed(t, strings.NewReader(s3Body), -1).Body)
	if err != nil || string(got) != s3Body {
		t.Fatalf("matching: %q, %v", got, err)
	}
	_, err = io.ReadAll(streamed(t, strings.NewReader(tampered), -1).Body)
	wantKind(t, err, KindPayloadHashMismatch)

	// Read short of its end, a body of unknown length is not checked.
	b := make([]byte, 2)
	if _, err = io.ReadFull(streamed(t, strings.NewReader(tampered), -1).Body, b); err != nil {
		t.Fatalf("partial read: %v", err)
	}
}

func TestStreamedPayloadReadErrorPassesThrough(t *testing.T) {
	r := streamed(t, io.MultiReader(strings.NewReader("he"), failingReader{}), int64(len(s3Body)))
	_, err := io.ReadAll(r.Body)
	if !errors.Is(err, errConnReset) {
		t.Fatalf("err = %v, want the body's own read error", err)
	}
}

func TestStreamedPayloadEmptyBody(t *testing.T) {
	r := httptest.NewRequestWithContext(
		context.Background(), http.MethodPut, s3Target, bytes.NewReader(nil),
	)
	hash := sha256Hex("")
	r.Header.Set("X-Amz-Content-Sha256", hash)
	err := s3Signer().SignHTTP(context.Background(), aws.Credentials{
		AccessKeyID: s3AccessKey, SecretAccessKey: s3SecretKey,
	}, r, hash, "s3", "eu-west-1", s3SignTime)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err = s3Verifier(t).Verify(r); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got, err := io.ReadAll(r.Body); err != nil || len(got) != 0 {
		t.Fatalf("read = %q, %v", got, err)
	}
}
