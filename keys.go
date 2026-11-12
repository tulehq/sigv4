package sigv4

import (
	"context"
	"errors"
)

// The errors a KeySource returns, or wraps, to say why it has no key for a
// scope. The verifier reports each as its own Kind; any other error is
// KindKeyLookupFailed.
var (
	// ErrUnknownAccessKey: the access key ID is not known. A temporary
	// access key ID sent without its session token is reported this way
	// too, as AWS does. Reported as KindUnknownAccessKey.
	ErrUnknownAccessKey = errors.New("sigv4: unknown access key ID")

	// ErrInvalidSessionToken: the session token is not the access key's, or
	// the access key takes no session token. Reported as
	// KindInvalidSessionToken.
	ErrInvalidSessionToken = errors.New("sigv4: invalid session token")

	// ErrExpiredSessionToken: the session token has expired. Reported as
	// KindExpiredSessionToken.
	ErrExpiredSessionToken = errors.New("sigv4: expired session token")
)

// Scope is what a request's credential names: the access key, its session
// token, and the date, region and service the signing key is derived for.
type Scope struct {
	AccessKeyID string
	// SessionToken is X-Amz-Security-Token, the token of temporary
	// credentials, or empty when the request carries none. The verifier
	// has checked that the signature covers it.
	SessionToken string
	// Date is the credential's day, as it appears in it: YYYYMMDD.
	Date    string
	Region  string
	Service string
}

// Principal is who signed a request.
type Principal struct {
	AccountID   string
	ARN         string
	AccessKeyID string
}

// Key is what a KeySource hands the verifier for a scope.
type Key struct {
	// Principal is who the access key belongs to. Verify puts it in the
	// request's context. Its AccountID must be set: a key without one fails
	// verification with KindKeyLookupFailed.
	Principal Principal
	// Signing is the derived signing key; see DeriveSigningKey.
	Signing []byte
}

// KeySource hands the verifier the signing key for a credential scope.
//
// It returns the derived key, not the secret it comes from, so an
// implementation can keep secrets to itself and hand out keys scoped to a
// day, region and service. It validates the scope's session token against
// the access key ID, and returns one of ErrUnknownAccessKey,
// ErrInvalidSessionToken and ErrExpiredSessionToken, or an error wrapping
// one, when it has no key; any other error fails verification with
// KindKeyLookupFailed. It must be safe for concurrent use.
type KeySource interface {
	SigningKey(ctx context.Context, scope Scope) (Key, error)
}

// DefaultAccountID is the account a StaticKey belongs to when its
// configuration names none, the account the Tule services use in ARNs.
const DefaultAccountID = "000000000000"

// StaticKeyConfig configures a StaticKey.
type StaticKeyConfig struct {
	AccessKeyID     string
	SecretAccessKey string
	// AccountID is the principal's account. It defaults to
	// DefaultAccountID.
	AccountID string
	// ARN is the principal's ARN. It defaults to the account's root user,
	// arn:aws:iam::<AccountID>:root.
	ARN string
}

// StaticKey is a KeySource over one long-term access key and its secret.
type StaticKey struct {
	secretAccessKey string
	principal       Principal
}

// NewStaticKey returns a KeySource that knows only cfg's access key, in any
// region and for any service. The key is long-term, so a request that
// carries a session token is refused with ErrInvalidSessionToken. It fails
// when the access key ID or the secret is empty: a request signed with an
// empty key is one any client can produce.
func NewStaticKey(cfg StaticKeyConfig) (*StaticKey, error) {
	if cfg.AccessKeyID == "" || cfg.SecretAccessKey == "" {
		return nil, errors.New("sigv4: a static key needs an access key ID and a secret")
	}
	if cfg.AccountID == "" {
		cfg.AccountID = DefaultAccountID
	}
	if cfg.ARN == "" {
		cfg.ARN = "arn:aws:iam::" + cfg.AccountID + ":root"
	}
	return &StaticKey{
		secretAccessKey: cfg.SecretAccessKey,
		principal: Principal{
			AccountID:   cfg.AccountID,
			ARN:         cfg.ARN,
			AccessKeyID: cfg.AccessKeyID,
		},
	}, nil
}

// SigningKey returns the key scope signs with, ErrUnknownAccessKey when scope
// names another access key ID, and ErrInvalidSessionToken when it carries a
// session token.
func (k *StaticKey) SigningKey(_ context.Context, scope Scope) (Key, error) {
	if scope.AccessKeyID != k.principal.AccessKeyID {
		return Key{}, ErrUnknownAccessKey
	}
	if scope.SessionToken != "" {
		return Key{}, ErrInvalidSessionToken
	}
	return Key{
		Principal: k.principal,
		Signing:   DeriveSigningKey(k.secretAccessKey, scope.Date, scope.Region, scope.Service),
	}, nil
}

// DeriveSigningKey derives the SigV4 signing key for secretAccessKey on date
// (YYYYMMDD), in region, for service.
func DeriveSigningKey(secretAccessKey, date, region, service string) []byte {
	key := hmacSHA256([]byte("AWS4"+secretAccessKey), date)
	key = hmacSHA256(key, region)
	key = hmacSHA256(key, service)
	return hmacSHA256(key, scopeSuffix)
}

type principalKey struct{}

// NewContext returns ctx carrying p, as Verify does for the request it
// returns. Handler tests use it to stand in for a verified request.
func NewContext(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFrom returns the Principal of the request ctx belongs to, and
// false when ctx carries none: the request was not verified.
func PrincipalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}
