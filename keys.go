package sigv4

import (
	"context"
	"errors"
)

// ErrUnknownAccessKey is what a KeySource returns, or wraps, for an access
// key ID it does not know. The verifier reports it as KindUnknownAccessKey.
var ErrUnknownAccessKey = errors.New("sigv4: unknown access key ID")

// Scope is what a request's credential names: the access key and the
// date, region and service the signing key is derived for.
type Scope struct {
	AccessKeyID string
	// Date is the credential's day, as it appears in it: YYYYMMDD.
	Date    string
	Region  string
	Service string
}

// KeySource hands the verifier the signing key for a credential scope.
//
// It returns the derived key, not the secret it comes from, so an
// implementation can keep secrets to itself and hand out keys scoped to a
// day, region and service. It returns ErrUnknownAccessKey, or an error
// wrapping it, for an access key ID it does not know; any other error fails
// verification with KindKeyLookupFailed. It must be safe for concurrent use.
type KeySource interface {
	SigningKey(ctx context.Context, scope Scope) ([]byte, error)
}

// StaticKey is a KeySource over one access key ID and its secret.
type StaticKey struct {
	accessKeyID     string
	secretAccessKey string
}

// NewStaticKey returns a KeySource that knows only accessKeyID, signed for
// with secretAccessKey, in any region and for any service.
func NewStaticKey(accessKeyID, secretAccessKey string) *StaticKey {
	return &StaticKey{accessKeyID: accessKeyID, secretAccessKey: secretAccessKey}
}

// SigningKey returns the key scope signs with, or ErrUnknownAccessKey when
// scope names another access key ID.
func (k *StaticKey) SigningKey(_ context.Context, scope Scope) ([]byte, error) {
	if scope.AccessKeyID != k.accessKeyID {
		return nil, ErrUnknownAccessKey
	}
	return DeriveSigningKey(k.secretAccessKey, scope.Date, scope.Region, scope.Service), nil
}

// DeriveSigningKey derives the SigV4 signing key for secretAccessKey on date
// (YYYYMMDD), in region, for service.
func DeriveSigningKey(secretAccessKey, date, region, service string) []byte {
	key := hmacSHA256([]byte("AWS4"+secretAccessKey), date)
	key = hmacSHA256(key, region)
	key = hmacSHA256(key, service)
	return hmacSHA256(key, scopeSuffix)
}
