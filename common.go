// Copyright 2018 by David A. Golden. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

package scram

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"strings"
)

// NonceGeneratorFcn defines a function that returns a string of high-quality
// random printable ASCII characters EXCLUDING the comma (',') character.  The
// default nonce generator provides Base64 encoding of 24 bytes from
// crypto/rand.
type NonceGeneratorFcn func() string

// derivedKeys collects the three cryptographically derived values
// into one struct for caching.
type derivedKeys struct {
	ClientKey []byte
	StoredKey []byte
	ServerKey []byte
}

// KeyFactors represent the two server-provided factors needed to compute
// client credentials for authentication.  Salt is decoded bytes (i.e. not
// base64), but in string form so that KeyFactors can be used as a map key for
// cached credentials.
type KeyFactors struct {
	Salt  string
	Iters int
}

// StoredCredentials are the values that a server must store for a given
// username to allow authentication.  They include the salt and iteration
// count, plus the derived values to authenticate a client and for the server
// to authenticate itself back to the client.
//
// NOTE: these are specific to a given hash function.  To allow a user to
// authenticate with either SCRAM-SHA-1 or SCRAM-SHA-256, two sets of
// StoredCredentials must be created and stored, one for each hash function.
type StoredCredentials struct {
	KeyFactors
	StoredKey []byte
	ServerKey []byte
}

// CredentialLookup is a callback to provide StoredCredentials for a given
// username.  This is used to configure Server objects.
//
// NOTE: these are specific to a given hash function.  The callback provided
// to a Server with a given hash function must provide the corresponding
// StoredCredentials.
type CredentialLookup func(string) (StoredCredentials, error)

// ChannelBindingType represents the type of channel binding to use with
// SCRAM-PLUS authentication variants.  The type must match one of the
// channel binding types defined in RFC 5056, RFC 5929, or RFC 9266.
type ChannelBindingType string

const (
	// ChannelBindingNone indicates no channel binding is used.
	ChannelBindingNone ChannelBindingType = ""

	// ChannelBindingTLSUnique uses the TLS Finished message from the first
	// TLS handshake (RFC 5929).  This is not safe for TLS 1.3 and should
	// generally be avoided.
	ChannelBindingTLSUnique ChannelBindingType = "tls-unique"

	// ChannelBindingTLSServerEndpoint uses a hash of the server's certificate
	// (RFC 5929).  This works with all TLS versions including TLS 1.3.
	ChannelBindingTLSServerEndpoint ChannelBindingType = "tls-server-end-point"

	// ChannelBindingTLSExporter uses TLS Exported Keying Material with the
	// label "EXPORTER-Channel-Binding" (RFC 9266).  This is the recommended
	// channel binding type for TLS 1.3.
	ChannelBindingTLSExporter ChannelBindingType = "tls-exporter"
)

// ChannelBinding holds the channel binding type and data for SCRAM-PLUS
// authentication.  The Data field should contain the channel binding data
// obtained from the TLS connection.  Applications are responsible for
// extracting this data from their TLS implementation.
//
// For tls-exporter (recommended for TLS 1.3), the data should be obtained
// using ExportKeyingMaterial with the label "EXPORTER-Channel-Binding" and
// an empty context.
//
// For tls-server-end-point, the data should be a hash of the server's
// certificate using an appropriate hash function based on the certificate's
// signature algorithm.
//
// For tls-unique (deprecated), the data should be the TLS Finished message
// from the first handshake.
type ChannelBinding struct {
	Type ChannelBindingType
	Data []byte
}

// IsSupported returns true if the channel binding is configured with a
// non-empty type and data.
func (cb ChannelBinding) IsSupported() bool {
	return cb.Type != ChannelBindingNone && len(cb.Data) > 0
}

// Matches returns true if this channel binding matches another channel
// binding in both type and data.
func (cb ChannelBinding) Matches(other ChannelBinding) bool {
	if cb.Type != other.Type {
		return false
	}
	return hmac.Equal(cb.Data, other.Data)
}

func defaultNonceGenerator() string {
	raw := make([]byte, 24)
	nonce := make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
	rand.Read(raw)
	base64.StdEncoding.Encode(nonce, raw)
	return string(nonce)
}

func encodeName(s string) string {
	return strings.Replace(strings.Replace(s, "=", "=3D", -1), ",", "=2C", -1)
}

func decodeName(s string) (string, error) {
	// TODO Check for = not followed by 2C or 3D
	return strings.Replace(strings.Replace(s, "=2C", ",", -1), "=3D", "=", -1), nil
}

func computeHash(hg HashGeneratorFcn, b []byte) []byte {
	h := hg()
	h.Write(b)
	return h.Sum(nil)
}

func computeHMAC(hg HashGeneratorFcn, key, data []byte) []byte {
	mac := hmac.New(hg, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func xorBytes(a, b []byte) []byte {
	// TODO check a & b are same length, or just xor to smallest
	xor := make([]byte, len(a))
	for i := range a {
		xor[i] = a[i] ^ b[i]
	}
	return xor
}
