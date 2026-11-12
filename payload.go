package sigv4

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"net/http"
	"strings"
)

const (
	unsignedPayload  = "UNSIGNED-PAYLOAD"
	streamingPrefix  = "STREAMING-"
	hashMismatchText = "The provided 'x-amz-content-sha256' header does not match what was computed."
)

// bufferPayload reads the body, checks the declared payload hash against it
// and, when none was declared, signs the body's own hash. It returns the body
// for the handler to read in place of r.Body.
func (v *Verifier) bufferPayload(r *http.Request, s *signed) ([]byte, *Error) {
	body, err := v.readBody(r, s.presigned)
	if err != nil {
		return nil, err
	}

	sum := sha256.Sum256(body)
	bodyHash := hex.EncodeToString(sum[:])
	switch {
	case s.payloadHash == "":
		// The SDKs sign the hash without sending it, which is the usual case:
		// the body's own hash goes into the canonical request, so a body that
		// was changed in flight fails the signature.
		s.payloadHash = bodyHash
	case !isHexSHA256(s.payloadHash):
		if err = v.checkOpaqueHash(s); err != nil {
			return nil, err
		}
	case !strings.EqualFold(s.payloadHash, bodyHash):
		return nil, newError(KindPayloadHashMismatch, s.presigned, hashMismatchText)
	}
	return body, nil
}

// readBody reads up to the body limit of r's body, rejecting anything longer
// rather than verifying a signature over a truncated body.
func (v *Verifier) readBody(r *http.Request, presigned bool) ([]byte, *Error) {
	if r.Body == nil {
		return nil, nil
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, v.maxBody+1))
	if err != nil {
		e := newError(KindBodyUnreadable, presigned, "The request body could not be read.")
		e.Err = err
		return nil, e
	}
	if int64(len(body)) > v.maxBody {
		return nil, newError(KindBodyTooLarge, presigned,
			"The request body is larger than this service accepts.")
	}
	return body, nil
}

// checkOpaqueHash refuses a declared payload hash that is not a hex SHA-256
// unless the verifier accepts it. Accepting UNSIGNED-PAYLOAD asks for a
// signature that covers no part of the body, which lets whoever relays a
// signed request swap the body for another operation's.
func (v *Verifier) checkOpaqueHash(s *signed) *Error {
	const prefix = "x-amz-content-sha256 must be the hex SHA-256 of the request body"

	streaming := strings.HasPrefix(s.payloadHash, streamingPrefix)
	switch {
	case v.allowAnyHash,
		s.payloadHash == unsignedPayload && v.allowUnsigned,
		streaming && v.allowStreaming:
		return nil
	case !v.allowUnsigned:
		return newError(KindPayloadHashNotAccepted, s.presigned,
			prefix+"; "+unsignedPayload+" is not accepted.")
	case streaming:
		return newError(KindPayloadHashNotAccepted, s.presigned,
			prefix+" or "+unsignedPayload+"; "+streamingPrefix+"* payloads are not accepted.")
	default:
		return newError(KindPayloadHashNotAccepted, s.presigned,
			prefix+" or "+unsignedPayload+".")
	}
}

// replaceBody hands the handler the body the signature covers: the buffered
// bytes, or with a streamed payload and a hex hash, a reader that checks the
// body against it.
func (v *Verifier) replaceBody(r *http.Request, s *signed, buffered []byte) {
	switch {
	case !v.streamed:
		r.Body = io.NopCloser(bytes.NewReader(buffered))
	case isHexSHA256(s.payloadHash) && r.Body != nil:
		r.Body = &payloadVerifier{
			body:      r.Body,
			h:         sha256.New(),
			want:      s.payloadHash,
			mapErr:    v.mapError,
			length:    r.ContentLength,
			presigned: s.presigned,
		}
	}
}

// payloadVerifier checks a streamed body against its declared SHA-256 and
// fails the read where the body is found not to match it, so an upload
// reading it is not committed.
//
// With a known Content-Length the hash is checked on the read that reaches
// that many bytes, so a handler that reads exactly Content-Length bytes and
// stops, as io.ReadFull, io.LimitReader and http.MaxBytesReader do, still
// sees the failure. A read past Content-Length fails, and so does an EOF
// short of it. With an unknown length, the read that reaches EOF is checked.
//
// A failing read returns no bytes: io.ReadFull drops an error that comes
// with a full buffer, so a read that filled it would hide the failure.
type payloadVerifier struct {
	body      io.ReadCloser
	h         hash.Hash
	mapErr    func(*Error) error
	want      string
	length    int64 // Content-Length, or -1 when unknown
	n         int64 // bytes read so far
	checked   bool  // the hash was checked at Content-Length and matched
	presigned bool
}

func (p *payloadVerifier) Read(b []byte) (int, error) {
	n, err := p.body.Read(b)
	if p.length >= 0 && p.n+int64(n) > p.length {
		// The body runs past Content-Length, which the hash does not cover.
		p.n = p.length
		return 0, p.mismatch()
	}
	p.h.Write(b[:n])
	p.n += int64(n)
	if !p.valid(errors.Is(err, io.EOF)) {
		return 0, p.mismatch()
	}
	return n, err //nolint:wrapcheck // io.Reader contract: EOF must pass through unwrapped
}

// valid reports whether the body read so far may be handed over: it is
// checked once it reaches Content-Length, or at EOF when its length is
// unknown, and an EOF short of a known length fails.
func (p *payloadVerifier) valid(eof bool) bool {
	known := p.length >= 0
	switch {
	case p.checked:
		return true
	case known && p.n == p.length:
		p.checked = p.matches()
		return p.checked
	case eof:
		return !known && p.matches()
	default:
		return true
	}
}

func (p *payloadVerifier) matches() bool {
	return strings.EqualFold(hex.EncodeToString(p.h.Sum(nil)), p.want)
}

func (p *payloadVerifier) mismatch() error {
	return p.mapErr(newError(KindPayloadHashMismatch, p.presigned, hashMismatchText))
}

func (p *payloadVerifier) Close() error {
	return p.body.Close() //nolint:wrapcheck // passes the body's close error through
}
