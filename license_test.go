// Copyright (c) 2026 Neomantra Corp. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only WITH LicenseRef-NimbleTerminal-Linking-Exception OR LicenseRef-Neomantra-Commercial

package ntconfine

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestLicenseSignAndVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	want := LicenseClaims{
		Licensee:  "Acme Quant Fund LP",
		Tier:      "enterprise",
		Scope:     []string{"ntmediabox", "ntbrowser", "gloss"},
		IssuedAt:  now.Add(-24 * time.Hour),
		ExpiresAt: now.Add(365 * 24 * time.Hour),
		KeyID:     "2026-q4",
	}

	token, err := SignLicenseKey(want, priv)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(token, LicenseTokenPrefix) {
		t.Fatalf("token %q missing prefix %q", token, LicenseTokenPrefix)
	}

	got, err := VerifyLicenseKeyWithKey(token, pub, now)
	if err != nil {
		t.Fatal(err)
	}
	if got.Licensee != want.Licensee || got.Tier != want.Tier || got.KeyID != want.KeyID {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	if !got.AllowsModule("ntmediabox") || !got.AllowsModule("ntbrowser") || got.AllowsModule("other-mod") {
		t.Fatalf("unexpected module scope behavior for %+v", got.Scope)
	}

	// Expired check.
	_, err = VerifyLicenseKeyWithKey(token, pub, now.Add(400*24*time.Hour))
	if !errors.Is(err, ErrExpiredLicenseKey) {
		t.Fatalf("expected ErrExpiredLicenseKey, got %v", err)
	}

	// Tampered signature check.
	tampered := token[:len(token)-2] + "AA"
	if tampered == token {
		tampered = token[:len(token)-2] + "BB"
	}
	if _, err := VerifyLicenseKeyWithKey(tampered, pub, now); !errors.Is(err, ErrInvalidLicenseKey) {
		t.Fatalf("expected ErrInvalidLicenseKey for tampered signature, got %v", err)
	}

	// Wrong public key check.
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyLicenseKeyWithKey(token, otherPub, now); !errors.Is(err, ErrInvalidLicenseKey) {
		t.Fatalf("expected ErrInvalidLicenseKey for wrong public key, got %v", err)
	}

	// Environment variable check.
	t.Setenv(LicenseEnvVar, token)
	envClaims, err := CheckCommercialLicenseWithKey("ntmediabox", pub, now)
	if err != nil || envClaims.Licensee != want.Licensee {
		t.Fatalf("CheckCommercialLicenseWithKey failed: %v (%+v)", err, envClaims)
	}
	if _, err := CheckCommercialLicenseWithKey("unlisted", pub, now); !errors.Is(err, ErrLicenseScope) {
		t.Fatalf("expected ErrLicenseScope, got %v", err)
	}

	t.Setenv(LicenseEnvVar, "")
	if _, err := CheckCommercialLicenseWithKey("ntmediabox", pub, now); !errors.Is(err, ErrNoLicenseKey) {
		t.Fatalf("expected ErrNoLicenseKey, got %v", err)
	}

	// Empty Scope must fail closed in SignLicenseKey, ValidAt, and AllowsModule.
	emptyScope := want
	emptyScope.Scope = nil
	if _, err := SignLicenseKey(emptyScope, priv); !errors.Is(err, ErrInvalidLicenseKey) {
		t.Fatalf("expected ErrInvalidLicenseKey when signing empty Scope, got %v", err)
	}
	if emptyScope.ValidAt(now) == nil || emptyScope.AllowsModule("ntmediabox") {
		t.Fatal("empty Scope must fail closed in ValidAt and AllowsModule")
	}

	// Zero ExpiresAt must fail closed in SignLicenseKey and ValidAt.
	noExp := want
	noExp.ExpiresAt = time.Time{}
	if _, err := SignLicenseKey(noExp, priv); !errors.Is(err, ErrInvalidLicenseKey) {
		t.Fatalf("expected ErrInvalidLicenseKey when signing zero ExpiresAt, got %v", err)
	}
	if !errors.Is(noExp.ValidAt(now), ErrInvalidLicenseKey) {
		t.Fatalf("expected ErrInvalidLicenseKey for zero ExpiresAt in ValidAt, got %v", noExp.ValidAt(now))
	}

	// NotBefore (nbf) must reject verification prior to NotBefore.
	futureClaims := want
	futureClaims.NotBefore = now.Add(2 * time.Hour)
	nbfToken, err := SignLicenseKey(futureClaims, priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyLicenseKeyWithKey(nbfToken, pub, now); !errors.Is(err, ErrInvalidLicenseKey) {
		t.Fatalf("expected ErrInvalidLicenseKey before NotBefore, got %v", err)
	}
	if _, err := VerifyLicenseKeyWithKey(nbfToken, pub, now.Add(3*time.Hour)); err != nil {
		t.Fatalf("expected valid token after NotBefore, got %v", err)
	}

	// Unknown JSON fields in a signed future payload must be tolerated.
	rawFutureJSON := []byte(`{"licensee":"Acme","tier":"enterprise","scope":["*"],"iat":"2026-10-31T12:00:00Z","exp":"2027-11-01T12:00:00Z","seats":50,"features":["hdr"]}`)
	futurePayloadB64 := base64.RawURLEncoding.EncodeToString(rawFutureJSON)
	sig := ed25519.Sign(priv, []byte(LicenseTokenPrefix+futurePayloadB64))
	futureToken := LicenseTokenPrefix + futurePayloadB64 + "." + base64.RawURLEncoding.EncodeToString(sig)
	gotFuture, err := VerifyLicenseKeyWithKey(futureToken, pub, now)
	if err != nil || !gotFuture.AllowsModule("ntmediabox") {
		t.Fatalf("VerifyLicenseKeyWithKey rejected forward-compatible fields: %v (%+v)", err, gotFuture)
	}
}

func FuzzVerifyLicenseKey(f *testing.F) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	validToken, err := SignLicenseKey(LicenseClaims{
		Licensee:  "Acme Corp",
		Tier:      "enterprise",
		Scope:     []string{"ntmediabox", "gloss"},
		IssuedAt:  now.Add(-time.Hour),
		ExpiresAt: now.Add(time.Hour),
	}, priv)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(validToken)
	f.Add("ntlic_v1.bad.sig")
	f.Add("ntlic_v1..")
	f.Add("")

	f.Fuzz(func(t *testing.T, token string) {
		claims, err := VerifyLicenseKeyWithKey(token, pub, now)
		if err == nil {
			if claims == nil || len(claims.Scope) == 0 || claims.ValidAt(now) != nil {
				t.Fatalf("VerifyLicenseKeyWithKey returned invalid claims without error: %+v", claims)
			}
		}
	})
}
