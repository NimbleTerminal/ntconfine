// Copyright (c) 2026 Neomantra Corp. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only WITH LicenseRef-NimbleTerminal-Linking-Exception OR LicenseRef-Neomantra-Commercial

package ntconfine

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"
)

// LicenseEnvVar is the environment variable holding a signed Neomantra Corp.
// commercial OEM or enterprise runtime license key.
//
// Open-source local CLI/desktop execution under the AGPL-3.0-only + NimbleTerminal
// Section 7 Linking Exception never requires NIMBLE_LICENSE_KEY; in open-source
// builds this verifier is a signed-claim inspection and honor gate for
// enterprise, cloud-hosted, and closed-source OEM deployments, not DRM enforcement.
const LicenseEnvVar = "NIMBLE_LICENSE_KEY"

// LicenseTokenPrefix identifies a v1 Ed25519-signed Neomantra license key.
const LicenseTokenPrefix = "ntlic_v1."

// DefaultLicensePublicKeyHex is Neomantra Corp.'s default Ed25519 verifying key
// (32 bytes, hex-encoded). Callers and tests may also pass a custom key to
// VerifyLicenseKeyWithKey.
const DefaultLicensePublicKeyHex = "6e42289e8ca4fddf4a6181efe8563085bba6fcaf9cc39652eae2ff1159141787"

var (
	// ErrNoLicenseKey indicates NIMBLE_LICENSE_KEY is not set in the environment.
	ErrNoLicenseKey = errors.New("ntconfine: NIMBLE_LICENSE_KEY is not set")
	// ErrInvalidLicenseKey indicates a malformed or tampered license token.
	ErrInvalidLicenseKey = errors.New("ntconfine: invalid license key")
	// ErrExpiredLicenseKey indicates a valid signature whose expiration time has passed.
	ErrExpiredLicenseKey = errors.New("ntconfine: license key has expired")
	// ErrLicenseScope indicates the license key does not cover the requested module.
	ErrLicenseScope = errors.New("ntconfine: license key does not cover module")
)

// LicenseClaims holds the verified payload of a signed NIMBLE_LICENSE_KEY.
type LicenseClaims struct {
	Licensee  string    `json:"licensee"`
	Tier      string    `json:"tier"`          // e.g. "enterprise", "oem", "cloud"
	Scope     []string  `json:"scope"`         // required: e.g. ["ntmediabox", "ntbrowser", "gloss"] or ["*"]
	IssuedAt  time.Time `json:"iat"`           // issuance time
	NotBefore time.Time `json:"nbf,omitempty"` // optional not-before time
	ExpiresAt time.Time `json:"exp"`           // expiration time
	KeyID     string    `json:"kid,omitempty"`
}

// ValidAt checks whether the claims are well-formed, active, and unexpired at now.
// An empty Scope or zero ExpiresAt fails closed.
func (c LicenseClaims) ValidAt(now time.Time) error {
	if strings.TrimSpace(c.Licensee) == "" || strings.TrimSpace(c.Tier) == "" {
		return fmt.Errorf("%w: missing licensee or tier", ErrInvalidLicenseKey)
	}
	if len(c.Scope) == 0 {
		return fmt.Errorf("%w: empty scope", ErrInvalidLicenseKey)
	}
	for _, s := range c.Scope {
		if strings.TrimSpace(s) == "" {
			return fmt.Errorf("%w: blank scope entry", ErrInvalidLicenseKey)
		}
	}
	if c.ExpiresAt.IsZero() {
		return fmt.Errorf("%w: missing exp", ErrInvalidLicenseKey)
	}
	if !c.NotBefore.IsZero() && now.Before(c.NotBefore) {
		return fmt.Errorf("%w: not valid before %s", ErrInvalidLicenseKey, c.NotBefore.UTC().Format(time.RFC3339))
	}
	if now.After(c.ExpiresAt) {
		return fmt.Errorf("%w (expired %s)", ErrExpiredLicenseKey, c.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if !c.IssuedAt.IsZero() && c.ExpiresAt.Before(c.IssuedAt) {
		return fmt.Errorf("%w: exp before iat", ErrInvalidLicenseKey)
	}
	if !c.NotBefore.IsZero() && c.ExpiresAt.Before(c.NotBefore) {
		return fmt.Errorf("%w: exp before nbf", ErrInvalidLicenseKey)
	}
	return nil
}

// AllowsModule reports whether c covers the named module (e.g. "ntmediabox",
// "ntbrowser", "gloss"). An empty Scope or empty module name fails closed;
// "*" covers all Neomantra modules.
func (c LicenseClaims) AllowsModule(module string) bool {
	if len(c.Scope) == 0 || strings.TrimSpace(module) == "" {
		return false
	}
	return slices.Contains(c.Scope, "*") || slices.Contains(c.Scope, module)
}

// DefaultLicensePublicKey returns the built-in Neomantra Corp. Ed25519 public key.
func DefaultLicensePublicKey() ed25519.PublicKey {
	b, err := hex.DecodeString(DefaultLicensePublicKeyHex)
	if err != nil || len(b) != ed25519.PublicKeySize {
		panic("ntconfine: invalid DefaultLicensePublicKeyHex")
	}
	return ed25519.PublicKey(b)
}

// SignLicenseKey serializes claims as JSON and signs them with priv using the
// "ntlic_v1.<base64url-payload>.<base64url-signature>" format.
func SignLicenseKey(claims LicenseClaims, priv ed25519.PrivateKey) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("%w: bad ed25519 private key length", ErrInvalidLicenseKey)
	}
	if strings.TrimSpace(claims.Licensee) == "" || strings.TrimSpace(claims.Tier) == "" || len(claims.Scope) == 0 || claims.ExpiresAt.IsZero() {
		return "", fmt.Errorf("%w: missing licensee, tier, scope, or exp", ErrInvalidLicenseKey)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	sig := ed25519.Sign(priv, []byte(LicenseTokenPrefix+payloadB64))
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	return LicenseTokenPrefix + payloadB64 + "." + sigB64, nil
}

// VerifyLicenseKey verifies token against DefaultLicensePublicKey at the current time.
func VerifyLicenseKey(token string) (*LicenseClaims, error) {
	return VerifyLicenseKeyWithKey(token, DefaultLicensePublicKey(), time.Now())
}

// VerifyLicenseKeyWithKey verifies token against pub at now.
func VerifyLicenseKeyWithKey(token string, pub ed25519.PublicKey, now time.Time) (*LicenseClaims, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: bad ed25519 public key length", ErrInvalidLicenseKey)
	}
	token = strings.TrimSpace(token)
	if !strings.HasPrefix(token, LicenseTokenPrefix) {
		return nil, fmt.Errorf("%w: missing %q prefix", ErrInvalidLicenseKey, LicenseTokenPrefix)
	}
	rest := strings.TrimPrefix(token, LicenseTokenPrefix)
	payloadB64, sigB64, ok := strings.Cut(rest, ".")
	if !ok || payloadB64 == "" || sigB64 == "" || strings.Contains(sigB64, ".") {
		return nil, fmt.Errorf("%w: malformed token segments", ErrInvalidLicenseKey)
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: malformed signature", ErrInvalidLicenseKey)
	}
	signedMsg := []byte(LicenseTokenPrefix + payloadB64)
	if !ed25519.Verify(pub, signedMsg, sig) {
		return nil, fmt.Errorf("%w: signature verification failed", ErrInvalidLicenseKey)
	}
	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil || len(payload) == 0 || len(payload) > 64<<10 {
		return nil, fmt.Errorf("%w: malformed payload", ErrInvalidLicenseKey)
	}
	var claims LicenseClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidLicenseKey, err)
	}
	if err := claims.ValidAt(now); err != nil {
		return nil, err
	}
	return &claims, nil
}

// CheckCommercialLicense reads NIMBLE_LICENSE_KEY from the process environment,
// verifies its Ed25519 signature and expiration, and checks that module (if
// non-empty) is within the license's scope.
func CheckCommercialLicense(module string) (*LicenseClaims, error) {
	return CheckCommercialLicenseWithKey(module, DefaultLicensePublicKey(), time.Now())
}

// CheckCommercialLicenseWithKey is CheckCommercialLicense with an explicit
// verifying key and clock.
func CheckCommercialLicenseWithKey(module string, pub ed25519.PublicKey, now time.Time) (*LicenseClaims, error) {
	raw := strings.TrimSpace(os.Getenv(LicenseEnvVar))
	if raw == "" {
		return nil, ErrNoLicenseKey
	}
	claims, err := VerifyLicenseKeyWithKey(raw, pub, now)
	if err != nil {
		return nil, err
	}
	if !claims.AllowsModule(module) {
		return nil, fmt.Errorf("%w: %q not in %v", ErrLicenseScope, module, claims.Scope)
	}
	return claims, nil
}

// HasCommercialLicense reports whether a valid, unexpired NIMBLE_LICENSE_KEY
// covering module is present in the environment.
func HasCommercialLicense(module string) bool {
	_, err := CheckCommercialLicense(module)
	return err == nil
}
