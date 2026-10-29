// Package lmbp is the Go reference implementation of the Avora
// LMBP (Local Model Bridge Protocol) wire format: envelope and message types, error codes,
// and the JOSE profile (EdDSA JWS/JWT, RFC 7638 thumbprints, key-bound proof
// JWTs). The normative spec is docs/lmbp-spec.md; schemas live in spec/.
package lmbp

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Subprotocol is the WebSocket subprotocol name. It carries no version: the
// major version is the envelope v (Version), checked on hello (spec §11).
const (
	Subprotocol = "lmbp"
	Version     = 2
)

// ProtocolVersions lists the "major.minor" versions this implementation
// speaks (gateway metadata protocol_versions, spec §18.2).
var ProtocolVersions = []string{"2.0"}

// Conformance profiles (spec §13). A gateway lists the profiles it
// implements in its metadata (profiles); core is mandatory.
const (
	ProfileCore       = "core"
	ProfileReliable   = "reliable"
	ProfileTools      = "tools"
	ProfileMultimodal = "multimodal"
	ProfileE2EE       = "e2ee"
	ProfileOpenAI     = "openai"
	ProfileAnthropic  = "anthropic"
)

// Profiles this implementation implements, in spec order.
var Profiles = []string{ProfileCore, ProfileReliable, ProfileTools, ProfileMultimodal, ProfileE2EE, ProfileOpenAI, ProfileAnthropic}

// CoreProfiles are the profiles of a Core-only gateway: core plus the OpenAI
// surface callers use to submit tasks.
var CoreProfiles = []string{ProfileCore, ProfileOpenAI}

// Concurrency bounds for hello/models.update max_concurrency (spec §7.4).
// Out-of-range values are rejected, never clamped.
const (
	MinConcurrency = 1
	MaxConcurrency = 16
)

// Limits on the model list of hello and models.update (defs.json modelId,
// hello.json models): at most MaxModels unique IDs of 1..MaxModelIDChars code
// points without whitespace.
const (
	MaxModels       = 500
	MaxModelIDChars = 256
)

// Unique returns xs without repeated entries, first occurrence kept, and the
// entries that were dropped. Announced lists (models, model_capabilities)
// carry uniqueItems in hello.json/models.update.json.
func Unique(xs []string) (out, dups []string) {
	out = make([]string, 0, len(xs)) // never nil: models is required
	seen := make(map[string]bool, len(xs))
	for _, x := range xs {
		if seen[x] {
			dups = append(dups, x)
			continue
		}
		seen[x] = true
		out = append(out, x)
	}
	return out, dups
}

// ValidModelID checks one advertised model ID against defs.json modelId.
func ValidModelID(s string) error {
	if s == "" || !utf8.ValidString(s) {
		return errors.New("model ID must be non-empty UTF-8")
	}
	if n := CharLen(s); n > MaxModelIDChars {
		return fmt.Errorf("model ID %q has %d characters (maximum %d)", s, n, MaxModelIDChars)
	}
	if strings.IndexFunc(s, func(r rune) bool { return unicode.IsSpace(r) || r == '\uFEFF' }) >= 0 {
		return fmt.Errorf("model ID %q contains whitespace", s)
	}
	return nil
}

// CharLen is the length unit of every string limit in the spec (§4.1):
// Unicode code points, the same unit as JSON Schema maxLength.
func CharLen(s string) int { return utf8.RuneCountInString(s) }

// MaxDeviceNameChars bounds device_name in code points (spec §6.2).
const MaxDeviceNameChars = 100

// ValidDeviceName reports whether a device-reported name is acceptable
// (spec §6.2): valid UTF-8, at most 100 code points, and none of the
// characters that can disguise text: C0/C1 controls (U+0000-U+001F,
// U+007F-U+009F), soft hyphen U+00AD, U+061C, U+180E, zero-width and
// directional marks U+200B-U+200F, line/paragraph separators and embedding
// controls U+2028-U+202E, U+2060-U+206F, U+FEFF and U+FFF9-U+FFFB.
// The name is still untrusted text chosen by the device.
func ValidDeviceName(s string) bool {
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) > MaxDeviceNameChars {
		return false
	}
	for _, r := range s {
		switch {
		case r <= 0x1F, r >= 0x7F && r <= 0x9F, r == 0xAD, r == 0x61C, r == 0x180E,
			r >= 0x200B && r <= 0x200F, r >= 0x2028 && r <= 0x202E, r >= 0x2060 && r <= 0x206F,
			r == 0xFEFF, r >= 0xFFF9 && r <= 0xFFFB:
			return false
		}
	}
	return true
}

// ValidHeaderValue reports whether s is 1..max printable ASCII characters
// (0x20-0x7E), the rule for X-End-User and Idempotency-Key (spec §4.1).
func ValidHeaderValue(s string, max int) bool {
	if s == "" || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// Message types. Data frames (sequenced, flow-controlled, resumable):
// gateway→device task.run, blob.chunk; device→gateway task.delta, task.done,
// task.error. Everything else is a control frame.
const (
	TypeHello        = "hello"
	TypeWelcome      = "welcome"
	TypeTaskRun      = "task.run"
	TypeBlobChunk    = "blob.chunk"
	TypeTaskDelta    = "task.delta"
	TypeTaskDone     = "task.done"
	TypeTaskError    = "task.error"
	TypeTaskAck      = "task.ack"
	TypeTaskCancel   = "task.cancel"
	TypePing         = "ping"
	TypePong         = "pong"
	TypeError        = "error"
	TypeSessionToken = "session.token"
	TypeModelsUpdate = "models.update"
)

// IsDataFrame reports whether frames of this type carry a per-task seq, count
// against flow-control windows and are retransmitted on resume.
func IsDataFrame(t string) bool {
	switch t {
	case TypeTaskRun, TypeBlobChunk, TypeTaskDelta, TypeTaskDone, TypeTaskError:
		return true
	}
	return false
}

// Capability names negotiated in hello/welcome.
const (
	CapSessionToken = "session.token"
	CapModelsUpdate = "models.update"
	CapResume       = "resume"
	CapFlow         = "flow"
	CapTools        = "tools"
	CapMultimodal   = "multimodal"
	CapE2EE         = "e2ee"
)

// Capabilities this implementation understands.
var Capabilities = []string{CapSessionToken, CapModelsUpdate, CapResume, CapFlow, CapTools, CapMultimodal, CapE2EE}

// CoreCapabilities are the capabilities of a Core-only implementation (spec
// §13.1): data-frame numbering and task.ack are Core and need no capability.
var CoreCapabilities = []string{CapSessionToken, CapModelsUpdate}

// Per-model capability flags (hello/models.update model_capabilities).
const (
	ModelCapTools  = "tools"
	ModelCapVision = "vision"
	ModelCapAudio  = "audio"

	// Request-parameter support (§16.4). "params" declares that the model's
	// parameter support is listed: then each of temperature, top_p, stop and
	// max_tokens is honoured only if its flag is present, and a gateway MUST
	// reject the others with CAPABILITY_UNSUPPORTED. Without "params" the
	// support is undeclared (legacy devices) and the device enforces it.
	ModelCapParams      = "params"
	ModelCapTemperature = "temperature"
	ModelCapTopP        = "top_p"
	ModelCapStop        = "stop"
	ModelCapMaxTokens   = "max_tokens"
)

// ParamCaps maps each request parameter to its model capability flag.
var ParamCaps = []string{ModelCapTemperature, ModelCapTopP, ModelCapStop, ModelCapMaxTokens}

// Protocol defaults (docs/lmbp-spec.md §10).
const (
	DefaultMaxFrameBytes = 256 << 10 // = MaxFrameBytes; the welcome value
	// MaxFrameBytes is the normative frame limit in UTF-8 bytes of the
	// encoded WebSocket text frame, both directions (spec §10). Flow windows
	// MUST be >= MaxFrameBytes so any admissible frame fits a window.
	MaxFrameBytes        = 256 << 10
	MaxMessages          = 200 // messages per request (spec §10)
	DefaultTaskWindow    = 1 << 20
	DefaultConnWindow    = 4 << 20
	DefaultResumeSeconds = 30
	BlobChunkBytes       = 96 << 10 // raw bytes per blob.chunk (base64url ≈128 KiB)
	MaxBlobBytes         = 20 << 20
	MaxTaskBlobBytes     = 32 << 20
	// MaxToolCallIndex is the largest task.delta tool_calls[].index (§16.1).
	MaxToolCallIndex = 127
	// MaxTaskOutputBytes bounds the encoded task.delta bodies one task may
	// send, cleartext or sealed (§10); beyond it the gateway cancels the task.
	MaxTaskOutputBytes = 64 << 20
	InlineDataURIBytes = 16 << 10 // data: URIs above this are moved to blobs
	BlobScheme         = "lmbp-blob:"
)

// SessionToken carries a refreshed token plus a key proof over its jti.
type SessionToken struct {
	AccessToken string `json:"access_token,omitempty"`
	Proof       string `json:"proof,omitempty"`
	ExpiresAt   int64  `json:"token_expires_at,omitempty"`
}

type ModelsUpdate struct {
	Models            []string            `json:"models"`
	ModelCapabilities map[string][]string `json:"model_capabilities,omitempty"`
	// ModelNames optionally maps a model id to a human-readable display name
	// (e.g. the desktop scheme name). Display only; requests use the id.
	ModelNames     map[string]string `json:"model_names,omitempty"`
	MaxConcurrency int               `json:"max_concurrency,omitempty"`
	E2EEKey        string            `json:"e2ee_key,omitempty"`
}

// Envelope is the single frame shape on the wire. task.run carries no Data;
// its payload travels inside JWS (compact, EdDSA) so no JSON canonicalization
// is ever needed.
type Envelope struct {
	V      int             `json:"v"`
	Type   string          `json:"type"`
	ID     string          `json:"id,omitempty"`
	TaskID string          `json:"task_id,omitempty"`
	Seq    int64           `json:"seq,omitempty"`
	Data   json.RawMessage `json:"data,omitempty"`
	JWS    string          `json:"jws,omitempty"`
}

// Flow advertises the sender's receive windows (bytes of unacknowledged data
// frames the peer may have outstanding).
type Flow struct {
	TaskWindow int `json:"task_window"`
	ConnWindow int `json:"conn_window"`
}

// ResumeTask is one task's position in a resume exchange: RecvSeq is the
// highest contiguous seq received from the peer for that task.
type ResumeTask struct {
	TaskID  string `json:"task_id"`
	RecvSeq int64  `json:"recv_seq"`
}

type HelloResume struct {
	Token string       `json:"token"`
	Tasks []ResumeTask `json:"tasks"`
}

type Hello struct {
	DeviceID          string              `json:"device_id"`
	Client            string              `json:"client"`
	Models            []string            `json:"models"`
	ModelCapabilities map[string][]string `json:"model_capabilities,omitempty"`
	// ModelNames optionally maps a model id to a human-readable display name
	// (e.g. the desktop scheme name). Display only; requests use the id.
	ModelNames     map[string]string `json:"model_names,omitempty"`
	MaxConcurrency int               `json:"max_concurrency"`
	Capabilities   []string          `json:"capabilities,omitempty"`
	Flow           *Flow             `json:"flow,omitempty"`
	Resume         *HelloResume      `json:"resume,omitempty"`
	E2EEKey        string            `json:"e2ee_key,omitempty"`
	// Proof is a proof JWT (aud "lmbp:hello", ath = hash of the access token).
	Proof string `json:"proof"`
}

type WelcomeResume struct {
	Resumed bool         `json:"resumed"`
	Tasks   []ResumeTask `json:"tasks"`
}

type Welcome struct {
	SessionID        string         `json:"session_id"`
	HeartbeatSeconds int            `json:"heartbeat_seconds"`
	MaxFrameBytes    int            `json:"max_frame_bytes"`
	TokenExpiresAt   int64          `json:"token_expires_at"`
	Capabilities     []string       `json:"capabilities"`
	MaxConcurrency   int            `json:"max_concurrency"` // required (welcome.json)
	Flow             *Flow          `json:"flow,omitempty"`
	ResumeToken      string         `json:"resume_token,omitempty"`
	ResumeSeconds    int            `json:"resume_window_seconds,omitempty"`
	Resume           *WelcomeResume `json:"resume,omitempty"`
}

// Message is an OpenAI Chat Completions message (text, content parts, tool calls).
type Message struct {
	Role       string     `json:"role"`
	Content    Content    `json:"content"`
	Name       string     `json:"name,omitempty"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
}

// Content is either a plain string, an array of content parts, or null.
type Content struct {
	Text  string
	Parts []ContentPart
	Null  bool
}

func Text(s string) Content { return Content{Text: s} }

func (c Content) MarshalJSON() ([]byte, error) {
	switch {
	case c.Parts != nil:
		return json.Marshal(c.Parts)
	case c.Null:
		return []byte("null"), nil
	}
	return json.Marshal(c.Text)
}

func (c *Content) UnmarshalJSON(b []byte) error {
	*c = Content{}
	t := strings.TrimSpace(string(b))
	switch {
	case t == "null":
		c.Null = true
		return nil
	case strings.HasPrefix(t, "["):
		c.Parts = []ContentPart{}
		return json.Unmarshal(b, &c.Parts)
	}
	return json.Unmarshal(b, &c.Text)
}

// PlainText concatenates text content (parts of other types are skipped).
func (c Content) PlainText() string {
	if c.Parts == nil {
		return c.Text
	}
	var b strings.Builder
	for _, p := range c.Parts {
		if p.Type == "text" {
			b.WriteString(p.Text)
		}
	}
	return b.String()
}

type ContentPart struct {
	Type       string      `json:"type"` // text | image_url | input_audio
	Text       string      `json:"text,omitempty"`
	ImageURL   *ImageURL   `json:"image_url,omitempty"`
	InputAudio *InputAudio `json:"input_audio,omitempty"`
}

type ImageURL struct {
	URL    string `json:"url"` // https://, data:<mime>;base64,..., or lmbp-blob:<id> on the tunnel
	Detail string `json:"detail,omitempty"`
}

type InputAudio struct {
	Data   string `json:"data"` // base64 (or lmbp-blob:<id> on the tunnel)
	Format string `json:"format"`
}

type Tool struct {
	Type     string      `json:"type"` // function
	Function FunctionDef `json:"function"`
}

type FunctionDef struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
	Strict      *bool           `json:"strict,omitempty"`
}

// ToolCall is used both in assistant messages and (with Index) in stream deltas.
type ToolCall struct {
	Index    *int         `json:"index,omitempty"`
	ID       string       `json:"id,omitempty"`
	Type     string       `json:"type,omitempty"`
	Function FunctionCall `json:"function"`
}

type FunctionCall struct {
	Name      string `json:"name,omitempty"`
	Arguments string `json:"arguments,omitempty"`
}

// BlobRef describes binary data delivered by blob.chunk frames; it is part of
// the signed task.run payload so the device can verify integrity.
type BlobRef struct {
	ID        string `json:"id"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"` // base64url
	MediaType string `json:"media_type"`
}

// E2EERef points at the sealed request (a JWE compact serialization carried
// as blob media type application/jose).
type E2EERef struct {
	Blob string `json:"blob"`
}

// TaskRun is the JWS payload of task.run.
type TaskRun struct {
	TaskID      string          `json:"task_id"`
	Iat         int64           `json:"iat"`
	DeviceID    string          `json:"device_id"`
	Model       string          `json:"model"`
	Messages    []Message       `json:"messages,omitempty"`
	Tools       []Tool          `json:"tools,omitempty"`
	ToolChoice  json.RawMessage `json:"tool_choice,omitempty"`
	MaxTokens   int             `json:"max_tokens,omitempty"`
	Temperature *float64        `json:"temperature,omitempty"`
	TopP        *float64        `json:"top_p,omitempty"`
	Stop        []string        `json:"stop,omitempty"`
	Blobs       []BlobRef       `json:"blobs,omitempty"`
	E2EE        *E2EERef        `json:"e2ee,omitempty"`
	// Sealed is set locally once an E2EE request was decrypted (E2EE is
	// cleared then); it is never sent.
	Sealed bool   `json:"-"`
	Exp    int64  `json:"exp"`
	Nonce  string `json:"nonce"`
}

// BlobChunk (gateway→device data frame).
type BlobChunk struct {
	BlobID string `json:"blob_id"`
	Offset int64  `json:"offset"`
	Data   string `json:"data"` // base64url
	Last   bool   `json:"last,omitempty"`
}

// TaskAck acknowledges every data frame of the task with seq <= Seq.
type TaskAck struct {
	Seq int64 `json:"seq"`
}

type TaskCancel struct {
	Reason string `json:"reason,omitempty"`
}

type TaskDelta struct {
	Text      string     `json:"text,omitempty"`
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`
	E2EE      string     `json:"e2ee,omitempty"` // sealed TaskDelta (E2EE mode)
}

type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
}

type TaskDone struct {
	FinishReason string `json:"finish_reason"`
	Usage        *Usage `json:"usage,omitempty"`
	E2EE         string `json:"e2ee,omitempty"` // sealed {"finish_reason":...} (E2EE mode)
}

type ErrorBody struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

// Error codes (string codes, stable across transports).
const (
	ErrUnauthenticated = "UNAUTHENTICATED"
	ErrForbidden       = "FORBIDDEN"
	ErrDeviceOffline   = "DEVICE_OFFLINE"
	ErrDeviceBusy      = "DEVICE_BUSY"
	ErrModelNotFound   = "MODEL_NOT_FOUND"
	ErrBadRequest      = "BAD_REQUEST"
	ErrUpstream        = "UPSTREAM_ERROR"
	ErrTimeout         = "TIMEOUT"
	ErrCancelled       = "CANCELLED"
	ErrBadSignature    = "BAD_SIGNATURE"
	ErrVersion         = "VERSION_UNSUPPORTED"
	ErrInternal        = "INTERNAL"
	ErrRateLimited     = "RATE_LIMITED"
	// Extensions (resume, flow control, tools/multimodal, E2EE, idempotency).
	ErrFlowControl     = "FLOW_CONTROL"
	ErrUnsupported     = "CAPABILITY_UNSUPPORTED"
	ErrPayloadTooLarge = "PAYLOAD_TOO_LARGE"
	ErrIdempotency     = "IDEMPOTENCY_KEY_REUSED"
	ErrOutcomeUnknown  = "OUTCOME_UNKNOWN"
	ErrDecrypt         = "E2EE_DECRYPT_FAILED"
	ErrSlowConsumer    = "SLOW_CONSUMER"
)

func B64(b []byte) string            { return base64.RawURLEncoding.EncodeToString(b) }
func UnB64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

func RandomID(prefix string) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

// Thumbprint is the RFC 7638 JWK thumbprint (SHA-256, base64url) of an
// Ed25519 public key, used as cnf.jkt (RFC 7800 / RFC 9449) and as kid.
func Thumbprint(pub ed25519.PublicKey) string {
	h := sha256.Sum256([]byte(`{"crv":"Ed25519","kty":"OKP","x":"` + B64(pub) + `"}`))
	return B64(h[:])
}

// JWK is the RFC 8037 OKP public key representation.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
}

func PublicJWK(pub ed25519.PublicKey) JWK {
	return JWK{Kty: "OKP", Crv: "Ed25519", X: B64(pub), Kid: Thumbprint(pub), Alg: "EdDSA", Use: "sig"}
}

// JWS typ values (explicit typing, RFC 8725 §3.11).
const (
	TypAccessToken = "at+jwt"         // RFC 9068
	TypAssertion   = "JWT"            // RFC 7523 client assertion
	TypProof       = "lmbp-proof+jwt" // device key proof (DPoP-style)
	TypTask        = "lmbp-task+jws"  // gateway-signed task.run payload
)

// Proof audiences.
const (
	ProofToken        = "lmbp:token"
	ProofHello        = "lmbp:hello"
	ProofSessionToken = "lmbp:session.token"
)

// SignJWS produces a compact JWS (RFC 7515) with alg EdDSA over payload bytes.
func SignJWS(key ed25519.PrivateKey, typ, kid string, payload []byte) string {
	h := map[string]string{"alg": "EdDSA", "typ": typ}
	if kid != "" {
		h["kid"] = kid
	}
	hb, _ := json.Marshal(h)
	in := B64(hb) + "." + B64(payload)
	return in + "." + B64(ed25519.Sign(key, []byte(in)))
}

// VerifyJWS checks a compact EdDSA JWS with the expected typ and returns its
// payload, which MUST be a JSON object. The protected header MUST be exactly
// {alg: "EdDSA", typ, kid?}: any other member (crit, b64, jku, jwk, x5u, ...)
// is rejected, and kid, when present, MUST be the RFC 7638 thumbprint of the
// verifying key (spec §5.2).
func VerifyJWS(pub ed25519.PublicKey, jws, typ string) ([]byte, error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed JWS")
	}
	var h map[string]json.RawMessage
	hb, err := UnB64(parts[0])
	if err != nil || json.Unmarshal(hb, &h) != nil || h == nil {
		return nil, errors.New("bad JWS header")
	}
	for k := range h {
		if k != "alg" && k != "typ" && k != "kid" {
			return nil, fmt.Errorf("forbidden JWS header %q", k)
		}
	}
	var alg, gotTyp string
	if json.Unmarshal(h["alg"], &alg) != nil || alg != "EdDSA" {
		return nil, errors.New("JWS alg must be EdDSA")
	}
	if json.Unmarshal(h["typ"], &gotTyp) != nil || gotTyp != typ {
		return nil, fmt.Errorf("JWS typ must be %s", typ)
	}
	if raw, ok := h["kid"]; ok {
		var kid string
		if json.Unmarshal(raw, &kid) != nil || len(pub) != ed25519.PublicKeySize || kid != Thumbprint(pub) {
			return nil, errors.New("JWS kid does not match the verifying key")
		}
	}
	sig, err := UnB64(parts[2])
	if err != nil || len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		return nil, errors.New("bad JWS signature")
	}
	p, err := UnB64(parts[1])
	if err != nil {
		return nil, errors.New("bad JWS payload")
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(p, &obj) != nil || obj == nil {
		return nil, errors.New("JWS payload must be a JSON object")
	}
	return p, nil
}

// claimSet is a decoded JWS payload for strict claim type checks.
type claimSet map[string]json.RawMessage

func claimsOf(p []byte) claimSet {
	var c claimSet
	_ = json.Unmarshal(p, &c)
	return c
}

// require checks that every name in ints is a NumericDate (a JSON integer in
// 0..2^53-1, no fraction or exponent) and every name in strs a non-empty
// string; names in opt are strings that may be empty.
func (c claimSet) require(ints, strs, opt []string) error {
	for _, k := range ints {
		if _, err := c.numericDate(k); err != nil {
			return err
		}
	}
	for _, k := range strs {
		if s, ok := c.str(k); !ok || s == "" {
			return fmt.Errorf("claim %s must be a non-empty string", k)
		}
	}
	for _, k := range opt {
		if _, ok := c.str(k); !ok {
			return fmt.Errorf("claim %s must be a string", k)
		}
	}
	return nil
}

func (c claimSet) numericDate(k string) (int64, error) {
	return jsonUint(c[k], "claim "+k)
}

// jsonUint parses a raw JSON value that MUST be an integer 0..2^53-1.
func jsonUint(raw json.RawMessage, what string) (int64, error) {
	s := string(raw)
	if s == "" || len(s) > 16 {
		return 0, fmt.Errorf("%s must be an integer", what)
	}
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0, fmt.Errorf("%s must be a non-negative integer", what)
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n > 1<<53-1 {
		return 0, fmt.Errorf("%s out of range", what)
	}
	return n, nil
}

func (c claimSet) str(k string) (string, bool) {
	raw, ok := c[k]
	if !ok {
		return "", false
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

// timeRange requires iat and exp NumericDates with exp >= iat.
func (c claimSet) timeRange() (int64, int64, error) {
	iat, err := c.numericDate("iat")
	if err != nil {
		return 0, 0, err
	}
	exp, err := c.numericDate("exp")
	if err != nil {
		return 0, 0, err
	}
	if exp < iat {
		return 0, 0, errors.New("exp before iat")
	}
	return iat, exp, nil
}

// SignTaskRun signs a task.run payload; the envelope carries the result in jws.
func SignTaskRun(key ed25519.PrivateKey, kid string, run TaskRun) string {
	b, _ := json.Marshal(run)
	return SignJWS(key, TypTask, kid, b)
}

// VerifyTaskRun verifies the gateway signature and binds it to the envelope task_id.
func VerifyTaskRun(pub ed25519.PublicKey, envTaskID, jws string) (TaskRun, error) {
	var run TaskRun
	p, err := VerifyJWS(pub, jws, TypTask)
	if err != nil {
		return run, err
	}
	c := claimsOf(p)
	if err := c.require(nil, []string{"task_id", "device_id", "model", "nonce"}, nil); err != nil {
		return run, err
	}
	if _, _, err := c.timeRange(); err != nil {
		return run, err
	}
	if err := checkBlobRefs(c["blobs"]); err != nil {
		return run, err
	}
	if json.Unmarshal(p, &run) != nil || run.TaskID == "" || run.TaskID != envTaskID {
		return run, errors.New("task.run payload/task_id mismatch")
	}
	return run, nil
}

// checkBlobRefs validates the signed blob references strictly.
func checkBlobRefs(raw json.RawMessage) error {
	if raw == nil {
		return nil
	}
	var refs []claimSet
	if json.Unmarshal(raw, &refs) != nil {
		return errors.New("blobs must be an array of objects")
	}
	for _, r := range refs {
		if r == nil {
			return errors.New("blob ref must be an object")
		}
		if err := r.require(nil, []string{"id", "media_type", "sha256"}, nil); err != nil {
			return fmt.Errorf("blob ref: %w", err)
		}
		if _, err := jsonUint(r["size"], "blob size"); err != nil {
			return err
		}
		h, _ := r.str("sha256")
		if d, err := UnB64(h); err != nil || len(d) != 32 {
			return errors.New("blob sha256 must be 32 bytes base64url")
		}
	}
	return nil
}

// ProofClaims are the claims of a device key proof JWT.
type ProofClaims struct {
	Iss string `json:"iss"` // device_id ("" before pairing completes)
	Aud string `json:"aud"`
	Iat int64  `json:"iat"`
	Jti string `json:"jti"`
	Ath string `json:"ath"` // base64url(SHA-256(bound credential)), as in RFC 9449
}

func Ath(credential string) string { h := sha256.Sum256([]byte(credential)); return B64(h[:]) }

func SignProof(key ed25519.PrivateKey, deviceID, aud, credential string, now time.Time) string {
	b, _ := json.Marshal(ProofClaims{Iss: deviceID, Aud: aud, Iat: now.Unix(), Jti: RandomID("p_"), Ath: Ath(credential)})
	return SignJWS(key, TypProof, "", b)
}

// VerifyProof checks a proof JWT: signature by pub, aud, iss, ath and |iat-now| <= 60s.
func VerifyProof(pub ed25519.PublicKey, proof, deviceID, aud, credential string, now time.Time) (ProofClaims, error) {
	var c ProofClaims
	p, err := VerifyJWS(pub, proof, TypProof)
	if err != nil {
		return c, err
	}
	if err := claimsOf(p).require([]string{"iat"}, []string{"aud", "jti", "ath"}, []string{"iss"}); err != nil {
		return c, fmt.Errorf("proof claims invalid: %w", err)
	}
	if json.Unmarshal(p, &c) != nil || c.Aud != aud || c.Iss != deviceID || c.Jti == "" || c.Ath != Ath(credential) {
		return c, errors.New("proof claims invalid")
	}
	if d := now.Unix() - c.Iat; d > 60 || d < -60 {
		return c, errors.New("proof iat outside allowed skew")
	}
	return c, nil
}

// ---- Minimal EdDSA JWT (RFC 7519 / RFC 8037) ----

type Claims struct {
	Iss    string            `json:"iss"`
	Sub    string            `json:"sub"`
	Aud    string            `json:"aud"`
	Tenant string            `json:"tenant,omitempty"`
	Iat    int64             `json:"iat"`
	Exp    int64             `json:"exp"`
	Jti    string            `json:"jti"`
	Cnf    map[string]string `json:"cnf,omitempty"`
}

func SignJWT(key ed25519.PrivateKey, typ, kid string, c Claims) string {
	p, _ := json.Marshal(c)
	return SignJWS(key, typ, kid, p)
}

// VerifyJWT checks signature, typ, aud and time; leeway 30s.
func VerifyJWT(pub ed25519.PublicKey, tok, typ, aud string, now time.Time) (Claims, error) {
	var c Claims
	pb, err := VerifyJWS(pub, tok, typ)
	if err != nil {
		return c, err
	}
	cs := claimsOf(pb)
	if err := cs.require(nil, []string{"iss", "sub", "aud", "jti"}, nil); err != nil {
		return c, err
	}
	if _, _, err := cs.timeRange(); err != nil {
		return c, err
	}
	if json.Unmarshal(pb, &c) != nil {
		return c, errors.New("bad token payload")
	}
	if c.Aud != aud {
		return c, errors.New("wrong audience")
	}
	if now.Unix() > c.Exp+30 || now.Unix()+30 < c.Iat {
		return c, errors.New("token expired")
	}
	return c, nil
}

// UnverifiedClaims reads claims without checking the signature (used only to
// find which device key should verify a client assertion).
func UnverifiedClaims(tok string) (Claims, error) {
	var c Claims
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return c, errors.New("malformed token")
	}
	pb, err := UnB64(parts[1])
	if err != nil {
		return c, err
	}
	return c, json.Unmarshal(pb, &c)
}

// VerifyTaskRunAt is VerifyTaskRun plus the expiry check (now > exp rejects).
func VerifyTaskRunAt(pub ed25519.PublicKey, envTaskID, jws string, now time.Time) (TaskRun, error) {
	run, err := VerifyTaskRun(pub, envTaskID, jws)
	if err == nil && now.Unix() > run.Exp {
		return run, errors.New("task.run expired")
	}
	return run, err
}

// TaskRunFrameSize is the encoded size in bytes of the task.run frame that
// carries jws (with a worst-case seq), for the max_frame_bytes check.
func TaskRunFrameSize(jws, taskID string) int {
	b, _ := json.Marshal(Envelope{V: Version, Type: TypeTaskRun, TaskID: taskID, Seq: 1 << 53, JWS: jws})
	return len(b)
}

// ValidFlow reports whether offered receive windows are acceptable: both
// windows >= MaxFrameBytes (so every admissible frame fits) and conn >= task.
func ValidFlow(f *Flow) bool {
	return f != nil && f.TaskWindow >= MaxFrameBytes && f.ConnWindow >= f.TaskWindow && f.ConnWindow <= 1<<31
}
