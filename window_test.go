package sigv4

// The window a presigned URL is valid in: it opens at X-Amz-Date, which may
// not be ahead of the clock by more than the skew, and closes no later than
// the maximum expiry from now, so dating a URL ahead cannot stretch its life.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// presignAt presigns a GET for s3 with the SDK, dated signTime and valid for
// expires.
func presignAt(t *testing.T, signTime time.Time, expires time.Duration) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, s3Target, nil)
	q := r.URL.Query()
	q.Set("X-Amz-Expires", strconv.Itoa(int(expires/time.Second)))
	r.URL.RawQuery = q.Encode()

	u, _, err := s3Signer().PresignHTTP(context.Background(), aws.Credentials{
		AccessKeyID: s3AccessKey, SecretAccessKey: s3SecretKey,
	}, r, unsignedPayload, "s3", "us-east-1", signTime)
	if err != nil {
		t.Fatalf("presign: %v", err)
	}
	return httptest.NewRequestWithContext(context.Background(), http.MethodGet, u, nil)
}

func TestPresignWindow(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	const week = 7 * 24 * time.Hour
	tests := []struct {
		name    string
		signed  time.Duration // X-Amz-Date relative to now
		expires time.Duration
		want    Kind // 0 when accepted
	}{
		{name: "signed now", signed: 0, expires: time.Hour},
		{name: "signed a week ago, valid a week", signed: -week + time.Minute, expires: week},
		{name: "ahead within the skew", signed: 10 * time.Minute, expires: time.Hour},
		{name: "ahead by the skew exactly", signed: 15 * time.Minute, expires: time.Hour},
		{
			name: "ahead beyond the skew", signed: 15*time.Minute + time.Second,
			expires: time.Hour, want: KindRequestNotYetValid,
		},
		{
			name:    "a day ahead",
			signed:  24 * time.Hour,
			expires: time.Hour,
			want:    KindRequestNotYetValid,
		},
		{
			// Within the skew, but the URL would outlive a week from now.
			name: "ahead and valid a week", signed: time.Minute,
			expires: week, want: KindRequestNotYetValid,
		},
		{
			name:    "a week ago, valid a week less a second",
			signed:  -week,
			expires: week - time.Second,
			want:    KindExpired,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := presignAt(t, now.Add(tt.signed), tt.expires)
			err := s3Verifier(t, WithClock(fixedClock(now))).Verify(r)
			if tt.want == 0 {
				if err != nil {
					t.Fatalf("Verify: %v", err)
				}
				return
			}
			if e := asKind(t, err, tt.want); !e.Presigned {
				t.Fatalf("Presigned = false")
			}
		})
	}
}

func TestPresignWindowFollowsTheOptions(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	v := s3Verifier(t, WithClock(fixedClock(now)),
		WithMaxClockSkew(time.Minute), WithMaxPresignExpiry(time.Hour))

	if err := v.Verify(presignAt(t, now.Add(time.Minute), 30*time.Minute)); err != nil {
		t.Fatalf("a minute ahead: %v", err)
	}
	wantKind(t, v.Verify(presignAt(t, now.Add(2*time.Minute), 30*time.Minute)),
		KindRequestNotYetValid)
	wantKind(t, v.Verify(presignAt(t, now.Add(time.Minute), time.Hour)), KindRequestNotYetValid)
}

func TestPresignNotYetValidWire(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	r := presignAt(t, now.Add(time.Hour), time.Hour)
	err := s3Verifier(t, WithClock(fixedClock(now)), WithErrorMap(s3Map)).Verify(r)
	wantWire(t, err, wire{
		status: http.StatusForbidden, code: "AccessDenied", message: "Request is not yet valid",
	})
}
