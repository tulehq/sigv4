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
			presigned: s.presigned,
		}
	}
}

// payloadVerifier fails the read that reaches EOF when the body's SHA-256 does
// not match the declared one, so an upload reading it is not committed.
type payloadVerifier struct {
	body      io.ReadCloser
	h         hash.Hash
	mapErr    func(*Error) error
	want      string
	presigned bool
}

func (p *payloadVerifier) Read(b []byte) (int, error) {
	n, err := p.body.Read(b)
	p.h.Write(b[:n])
	if errors.Is(err, io.EOF) && !strings.EqualFold(hex.EncodeToString(p.h.Sum(nil)), p.want) {
		return n, p.mapErr(newError(KindPayloadHashMismatch, p.presigned, hashMismatchText))
	}
	return n, err //nolint:wrapcheck // io.Reader contract: EOF must pass through unwrapped
}

func (p *payloadVerifier) Close() error {
	return p.body.Close() //nolint:wrapcheck // passes the body's close error through
}
