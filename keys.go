package sigv4

import (
	"context"
	"encoding/json"
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

// PrincipalType is the kind of principal that signed a request, the value
// AWS gives the aws:PrincipalType condition key.
type PrincipalType string

// The principal types a KeySource reports, as AWS spells them for
// aws:PrincipalType.
const (
	// PrincipalTypeAccount is an account's root user.
	PrincipalTypeAccount PrincipalType = "Account"
	// PrincipalTypeUser is an IAM user.
	PrincipalTypeUser PrincipalType = "User"
	// PrincipalTypeAssumedRole is a role session: a principal signing with
	// the temporary credentials of an assumed role.
	PrincipalTypeAssumedRole PrincipalType = "AssumedRole"
)

// Principal is who signed a request.
//
// Besides ARN, a Principal carries the values AWS puts in the request
// context for the principal's condition keys, as its KeySource supplies
// them; sigv4 does not interpret them, and Verify passes them through
// unchanged. A field the KeySource does not supply is its zero value.
//
// Matching a resource-based policy's Principal element takes these fields
// together. An account principal (the account ID, or
// arn:aws:iam::<account>:root) names AccountID. A user ARN names
// PrincipalARN, which for a user is also ARN. A role ARN names a session of
// that role through PrincipalARN, since a session's ARN is the
// assumed-role ARN. An assumed-role ARN names ARN. A unique ID names
// UserID for a user, and the role ID that UserID starts with for a session.
type Principal struct {
	// Tags are the principal's tags, the values of aws:PrincipalTag/<key>:
	// an IAM user's tags, or, for a role session, the role's tags merged
	// with the session's tags, a session tag replacing the role tag with
	// the same key. Tag keys are unique regardless of case, and keep the
	// case they were set with; aws:PrincipalTag/<key> names a key
	// regardless of case. Nil when the principal has none.
	Tags map[string]string

	AccountID string
	// ARN is the ARN of the identity that signed: its own ARN for an IAM
	// user, arn:aws:iam::<account>:root for the root user, and the
	// assumed-role ARN, arn:aws:sts::<account>:assumed-role/<role
	// name>/<session name>, for a role session. The assumed-role ARN names
	// the role without its path.
	ARN string
	// PrincipalARN is the value of aws:PrincipalArn: ARN for an IAM user or
	// the root user, and, for a role session, the ARN of the role,
	// arn:aws:iam::<account>:role/<path><role name>, path included.
	PrincipalARN string
	// UserID is the value of aws:userid: an IAM user's unique ID
	// (AIDA...), the account ID for the root user, and <role ID>:<session
	// name> for a role session, where the role ID is the role's unique ID
	// (AROA...).
	UserID      string
	AccessKeyID string
	// Type is the value of aws:PrincipalType.
	Type PrincipalType
	// Policies are the identity policy documents in effect for the
	// principal, as its KeySource supplies them. They are opaque JSON for a
	// policy evaluator; sigv4 does not interpret them, and Verify passes
	// them through unchanged.
	Policies []json.RawMessage
	// Root marks a principal with full access to its account, such as the
	// account's root user. A root principal is never evaluated against
	// policies. A StaticKey's principal is Root.
	Root bool
}

// Key is what a KeySource hands the verifier for a scope.
type Key struct {
	// Signing is the derived signing key; see DeriveSigningKey.
	Signing []byte
	// Principal is who the access key belongs to. Verify puts it in the
	// request's context. Its AccountID must be set: a key without one fails
	// verification with KindKeyLookupFailed.
	Principal Principal
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
//
// The scope is unauthenticated when SigningKey is called: the signature is
// checked after, with the key it returns. So the access key ID, Date,
// Region, Service and SessionToken are whatever the request claims, and
// anyone can call SigningKey with any of them. An implementation must not
// cache per scope without a bound, since each request can name a new one,
// and should not reveal more about a token than AWS does: an error that
// tells an unknown key from a known one, or a valid token from an invalid
// one, through anything but these sentinels, lets a caller probe them.
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
// Its principal is Root, with no policies.
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
			Root:        true,
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

type scopeKey struct{}

// ScopeFrom returns the credential Scope the request ctx belongs to was
// verified under, and false when ctx carries none: the request was not
// verified. Unlike the Scope a KeySource is asked for, it is authenticated:
// the signature covers the credential, so a service can route on its
// Service and Region. It includes the session token, if any.
func ScopeFrom(ctx context.Context) (Scope, bool) {
	s, ok := ctx.Value(scopeKey{}).(Scope)
	return s, ok
}
