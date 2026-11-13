package sigv4

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// answering is a KeySource that gives one answer and counts its calls.
type answering struct {
	err   error
	calls *int
	key   Key
}

func (a answering) SigningKey(context.Context, Scope) (Key, error) {
	*a.calls++
	return a.key, a.err
}

func answer(key Key, err error) (answering, *int) {
	calls := new(int)
	return answering{key: key, err: err, calls: calls}, calls
}

var chainKey = Key{
	Principal: Principal{AccountID: "111122223333", AccessKeyID: "AKID"},
	Signing:   []byte("signing key"),
}

func TestChainOrder(t *testing.T) {
	first, firstCalls := answer(chainKey, nil)
	second, secondCalls := answer(Key{}, errors.New("not asked"))

	key, err := Chain(first, second).SigningKey(context.Background(), Scope{AccessKeyID: "AKID"})
	if err != nil || key.Principal != chainKey.Principal {
		t.Fatalf("SigningKey = %+v, %v", key, err)
	}
	if *firstCalls != 1 || *secondCalls != 0 {
		t.Fatalf("calls = %d, %d; want the first only", *firstCalls, *secondCalls)
	}
}

func TestChainFallsThroughUnknownKeys(t *testing.T) {
	for _, unknown := range []error{
		ErrUnknownAccessKey,
		fmt.Errorf("identity: %w", ErrUnknownAccessKey),
		errors.Join(errors.New("revoked"), ErrUnknownAccessKey),
	} {
		t.Run(unknown.Error(), func(t *testing.T) {
			first, firstCalls := answer(Key{}, unknown)
			second, secondCalls := answer(chainKey, nil)
			key, err := Chain(first, second).SigningKey(context.Background(), Scope{})
			if err != nil || key.Principal != chainKey.Principal {
				t.Fatalf("SigningKey = %+v, %v", key, err)
			}
			if *firstCalls != 1 || *secondCalls != 1 {
				t.Fatalf("calls = %d, %d", *firstCalls, *secondCalls)
			}
		})
	}
}

func TestChainStopsAtTheFirstOtherAnswer(t *testing.T) {
	lookup := errors.New("identity unavailable")
	for _, final := range []error{ErrInvalidSessionToken, ErrExpiredSessionToken, lookup} {
		t.Run(final.Error(), func(t *testing.T) {
			first, _ := answer(Key{}, final)
			second, secondCalls := answer(chainKey, nil)
			_, err := Chain(first, second).SigningKey(context.Background(), Scope{})
			if !errors.Is(err, final) {
				t.Fatalf("err = %v, want %v", err, final)
			}
			if *secondCalls != 0 {
				t.Fatal("a final answer fell through to the next source")
			}
		})
	}
}

func TestChainWithEveryKeyUnknown(t *testing.T) {
	first, _ := answer(Key{}, ErrUnknownAccessKey)
	second, _ := answer(Key{}, fmt.Errorf("wrapped: %w", ErrUnknownAccessKey))
	for name, c := range map[string]KeySource{"two sources": Chain(first, second), "empty": Chain()} {
		if _, err := c.SigningKey(
			context.Background(),
			Scope{},
		); !errors.Is(
			err,
			ErrUnknownAccessKey,
		) {
			t.Fatalf("%s: err = %v, want ErrUnknownAccessKey", name, err)
		}
	}
}

func TestChainRefusesANilSource(t *testing.T) {
	var noStatic *StaticKey // what NewStaticKey returns with its error
	for name, sources := range map[string][]KeySource{
		"nil interface": {mustStatic(t, StaticKeyConfig{AccessKeyID: "A", SecretAccessKey: "s"}), nil},
		"nil pointer":   {noStatic},
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if p := recover(); p == nil || !strings.Contains(fmt.Sprint(p), "nil") {
					t.Fatalf("recovered %v, want a panic naming the nil source", p)
				}
			}()
			Chain(sources...)
		})
	}
}

func TestChainKeepsItsOwnSources(t *testing.T) {
	first, _ := answer(Key{}, ErrUnknownAccessKey)
	second, _ := answer(chainKey, nil)
	sources := []KeySource{first, second}
	c := Chain(sources...)
	sources[1] = first // the caller's slice changing does not change the chain
	if key, err := c.SigningKey(context.Background(), Scope{}); err != nil || key.Signing == nil {
		t.Fatalf("SigningKey = %+v, %v", key, err)
	}
}

func TestStaticKeyInAChain(t *testing.T) {
	// A token on another key ID is not the static key's to refuse: it falls
	// through to the source that issued it. Only a token on the static key's
	// own ID is refused there, and that answer is final.
	ctx := context.Background()
	static := mustStatic(t, StaticKeyConfig{AccessKeyID: "AKIDROOT", SecretAccessKey: "s"})
	if _, err := static.SigningKey(
		ctx,
		Scope{AccessKeyID: "ASIATEMP", SessionToken: "t"},
	); !errors.Is(
		err,
		ErrUnknownAccessKey,
	) {
		t.Fatalf("another key with a token: %v, want ErrUnknownAccessKey", err)
	}

	identity, identityCalls := answer(chainKey, nil)
	c := Chain(static, identity)
	if _, err := c.SigningKey(ctx, Scope{AccessKeyID: "ASIATEMP", SessionToken: "t"}); err != nil {
		t.Fatalf("temporary key: %v", err)
	}
	if *identityCalls != 1 {
		t.Fatalf("identity asked %d times", *identityCalls)
	}
	_, err := c.SigningKey(ctx, Scope{AccessKeyID: "AKIDROOT", SessionToken: "t"})
	if !errors.Is(err, ErrInvalidSessionToken) || *identityCalls != 1 {
		t.Fatalf("root key with a token: %v, identity asked %d times", err, *identityCalls)
	}
}

func TestVerifyThroughAChain(t *testing.T) {
	// The root key and a temporary key issued elsewhere both verify, each
	// as its own principal.
	root := mustStatic(t, StaticKeyConfig{AccessKeyID: sdkAccessKey, SecretAccessKey: sdkSecretKey})
	keys := Chain(root, tempKeys{})
	for _, svc := range sdkServices() {
		for _, presign := range []bool{false, true} {
			t.Run(svc.name+"/"+modeName(presign), func(t *testing.T) {
				v := svc.tempVerifier(t, keys)

				got, err := v.Verify(svc.sign(t, presign, sdkAccessKey, sdkSecretKey))
				if err != nil {
					t.Fatalf("root key: %v", err)
				}
				if p, _ := PrincipalFrom(got.Context()); p.AccessKeyID != sdkAccessKey {
					t.Fatalf("root principal = %+v", p)
				}

				got, err = v.Verify(svc.signAt(t, presign, tempCreds, sdkTime))
				if err != nil {
					t.Fatalf("temporary key: %v", err)
				}
				if p, _ := PrincipalFrom(got.Context()); p.ARN != tempARN {
					t.Fatalf("temporary principal = %+v", p)
				}

				wantKind(t, v.check(svc.sign(t, presign, "AKIDNOBODY", sdkSecretKey)),
					KindUnknownAccessKey)
			})
		}
	}
}
