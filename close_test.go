package sigv4

// Close reads what a handler left of a streamed body, but as net/http does:
// no more than maxDrain, and nothing at all when more than that is left.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// zeros is an endless body of zero bytes, counting what is read of it.
type zeros struct{ read int64 }

func (z *zeros) Read(b []byte) (int, error) {
	clear(b)
	z.read += int64(len(b))
	return len(b), nil
}

// declared returns a verified S3 PUT declaring length bytes of the hash of
// s3Body, whose body is body.
func declared(t *testing.T, length int64, body io.Reader) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPut, s3Target, nil)
	r.ContentLength = length
	hash := sha256Hex(s3Body)
	r.Header.Set("X-Amz-Content-Sha256", hash)
	err := s3Signer().SignHTTP(context.Background(), aws.Credentials{
		AccessKeyID: s3AccessKey, SecretAccessKey: s3SecretKey,
	}, r, hash, "s3", "eu-west-1", s3SignTime)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	r.Body = io.NopCloser(body)
	if err = s3Verifier(t).check(r); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	return r
}

func TestCloseDrainIsBounded(t *testing.T) {
	// More than maxDrain left: Close reads none of it and reports the body
	// unverified, as net/http closes the connection rather than read it.
	body := &zeros{}
	r := declared(t, 2<<30, body)
	start := time.Now()
	wantKind(t, r.Body.Close(), KindUnverifiedPayload)
	if body.read != 0 || time.Since(start) > time.Second {
		t.Fatalf("Close read %d bytes in %v", body.read, time.Since(start))
	}

	// Within maxDrain, Close reads the rest and checks it.
	r = declared(t, maxDrain, strings.NewReader(strings.Repeat("x", maxDrain)))
	wantKind(t, r.Body.Close(), KindPayloadHashMismatch)

	// An unknown length is read up to maxDrain; a valid body longer than
	// that, left unread, is unverified, not a mismatch.
	big := strings.Repeat("y", 3<<20)
	r = httptest.NewRequestWithContext(context.Background(), http.MethodPut, s3Target,
		strings.NewReader(big))
	r.ContentLength = -1
	hash := sha256Hex(big)
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
	if _, err = io.ReadFull(r.Body, make([]byte, 10)); err != nil {
		t.Fatalf("read: %v", err)
	}
	wantKind(t, r.Body.Close(), KindUnverifiedPayload)
}

// startSlowPut sends the head of a signed PUT declaring 1 MiB, and one byte
// of its body, to host, and returns the open connection.
func startSlowPut(t *testing.T, host string) net.Conn {
	t.Helper()
	r := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodPut,
		"http://"+host+"/b/k",
		nil,
	)
	r.ContentLength = 1 << 20
	hash := sha256Hex(s3Body)
	r.Header.Set("X-Amz-Content-Sha256", hash)
	err := s3Signer().SignHTTP(context.Background(), aws.Credentials{
		AccessKeyID: s3AccessKey, SecretAccessKey: s3SecretKey,
	}, r, hash, "s3", "eu-west-1", s3SignTime)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	conn, err := net.Dial("tcp", host)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() {
		if cerr := conn.Close(); cerr != nil && !errors.Is(cerr, net.ErrClosed) {
			t.Errorf("close: %v", cerr)
		}
	})
	var head strings.Builder
	fmt.Fprintf(
		&head,
		"PUT /b/k HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n",
		host,
		r.ContentLength,
	)
	for k, vs := range r.Header {
		fmt.Fprintf(&head, "%s: %s\r\n", k, vs[0])
	}
	head.WriteString("\r\nx")
	if _, err = io.WriteString(conn, head.String()); err != nil {
		t.Fatalf("write: %v", err)
	}
	return conn
}

func TestCloseDoesNotWaitOnASlowClient(t *testing.T) {
	// A handler that refuses an upload and closes its body answers at once,
	// however slowly the client sends a body longer than maxDrain.
	v := s3Verifier(t)
	closed := make(chan error, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vr, err := v.Verify(r)
		if err != nil {
			closed <- err
			w.WriteHeader(http.StatusForbidden)
			return
		}
		closed <- vr.Body.Close()
		w.WriteHeader(http.StatusPreconditionFailed)
	}))
	defer srv.Close()

	conn := startSlowPut(t, strings.TrimPrefix(srv.URL, "http://"))
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	start := time.Now()
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("no response within 2s: %v", err)
	}
	if err = resp.Body.Close(); err != nil {
		t.Fatalf("close response: %v", err)
	}
	if resp.StatusCode != http.StatusPreconditionFailed || time.Since(start) > time.Second {
		t.Fatalf("status %d after %v", resp.StatusCode, time.Since(start))
	}
	wantKind(t, <-closed, KindUnverifiedPayload)
}

// closingBody fails every read after Close, as net/http's request body does.
type closingBody struct {
	r      io.Reader
	closed bool
}

func (c *closingBody) Read(b []byte) (int, error) {
	if c.closed {
		return 0, errors.New("http: invalid Read on closed Body")
	}
	return c.r.Read(b) //nolint:wrapcheck // io.Reader contract
}

func (c *closingBody) Close() error {
	c.closed = true
	return nil
}

func TestCloseIsIdempotent(t *testing.T) {
	for _, tt := range []struct {
		name string
		body string
		read bool
		want Kind // 0 for a clean close
	}{
		{name: "read in full", body: s3Body, read: true},
		{name: "left unread", body: s3Body},
		{name: "mismatch", body: tampered, want: KindPayloadHashMismatch},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := declared(t, int64(len(s3Body)), strings.NewReader(tt.body))
			r.Body.(*payloadVerifier).body = &closingBody{r: strings.NewReader(tt.body)}
			if tt.read {
				if _, err := io.ReadAll(r.Body); err != nil {
					t.Fatalf("read: %v", err)
				}
			}
			for i := range 2 {
				err := r.Body.Close()
				if tt.want == 0 {
					if err != nil {
						t.Fatalf("Close %d: %v", i+1, err)
					}
					continue
				}
				wantKind(t, err, tt.want)
			}
		})
	}
}
