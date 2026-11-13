package sigv4

import (
	"context"
	"errors"
	"reflect"
	"strconv"
)

// chain is a KeySource that asks several in turn.
type chain []KeySource

// Chain returns a KeySource that asks sources in order. A source that
// answers ErrUnknownAccessKey, or an error wrapping it, passes the scope to
// the next; the first other answer, a key or any other error, is final.
// When every source answers unknown, as an empty chain does, Chain answers
// ErrUnknownAccessKey.
//
// A service accepts its configured root key and any key the identity
// service issued with Chain(rootKey, identityClient). Each source must
// answer ErrUnknownAccessKey for a key ID it does not hold, whatever else
// the scope carries: a StaticKey does so even when the scope has a session
// token, and answers ErrInvalidSessionToken only for a token on its own key
// ID, so a temporary key falls through to the source that issued it.
//
// A source earlier in the chain answers faster than a later one, so the
// time an answer takes can tell which source holds a key ID. Put the
// cheapest source first.
//
// Chain panics when a source is nil, including a nil pointer of a concrete
// type, such as the *StaticKey NewStaticKey returns with an error: a
// missing source is a startup mistake, not a key to skip.
func Chain(sources ...KeySource) KeySource {
	for i, s := range sources {
		if isNil(s) {
			panic("sigv4: Chain source " + strconv.Itoa(i) + " is nil")
		}
	}
	return chain(append([]KeySource(nil), sources...))
}

// SigningKey asks each source in turn; see Chain.
func (c chain) SigningKey(ctx context.Context, scope Scope) (Key, error) {
	for _, s := range c {
		key, err := s.SigningKey(ctx, scope)
		if !errors.Is(err, ErrUnknownAccessKey) {
			return key, err //nolint:wrapcheck // a source's answer is the chain's, sentinel included
		}
	}
	return Key{}, ErrUnknownAccessKey
}

func isNil(s KeySource) bool {
	if s == nil {
		return true
	}
	v := reflect.ValueOf(s)
	switch v.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.Interface:
		return v.IsNil()
	default:
		return false
	}
}
