// Copyright 2018 by David A. Golden. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

package scram

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestChannelBindingTypes(t *testing.T) {
	tests := []struct {
		name     string
		cbType   ChannelBindingType
		expected string
	}{
		{"None", ChannelBindingNone, ""},
		{"TLS Unique", ChannelBindingTLSUnique, "tls-unique"},
		{"TLS Server Endpoint", ChannelBindingTLSServerEndpoint, "tls-server-end-point"},
		{"TLS Exporter", ChannelBindingTLSExporter, "tls-exporter"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.cbType) != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, string(tt.cbType))
			}
		})
	}
}

func TestChannelBindingIsSupported(t *testing.T) {
	tests := []struct {
		name     string
		cb       ChannelBinding
		expected bool
	}{
		{
			name:     "Empty binding",
			cb:       ChannelBinding{},
			expected: false,
		},
		{
			name:     "Type but no data",
			cb:       ChannelBinding{Type: ChannelBindingTLSExporter, Data: nil},
			expected: false,
		},
		{
			name:     "Data but no type",
			cb:       ChannelBinding{Type: ChannelBindingNone, Data: []byte("test")},
			expected: false,
		},
		{
			name:     "Type and data",
			cb:       ChannelBinding{Type: ChannelBindingTLSExporter, Data: []byte("test")},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.cb.IsSupported() != tt.expected {
				t.Errorf("Expected IsSupported=%v, got %v", tt.expected, tt.cb.IsSupported())
			}
		})
	}
}

func TestChannelBindingMatches(t *testing.T) {
	cb1 := ChannelBinding{Type: ChannelBindingTLSExporter, Data: []byte("test-data")}
	cb2 := ChannelBinding{Type: ChannelBindingTLSExporter, Data: []byte("test-data")}
	cb3 := ChannelBinding{Type: ChannelBindingTLSExporter, Data: []byte("different")}
	cb4 := ChannelBinding{Type: ChannelBindingTLSServerEndpoint, Data: []byte("test-data")}

	tests := []struct {
		name     string
		cb1      ChannelBinding
		cb2      ChannelBinding
		expected bool
	}{
		{"Same type and data", cb1, cb2, true},
		{"Same type, different data", cb1, cb3, false},
		{"Different type, same data", cb1, cb4, false},
		{"Different type and data", cb1, cb3, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.cb1.Matches(tt.cb2) != tt.expected {
				t.Errorf("Expected Matches=%v, got %v", tt.expected, tt.cb1.Matches(tt.cb2))
			}
		})
	}
}

func TestClientChannelBinding(t *testing.T) {
	client, _ := SHA256.NewClient("user", "pencil", "")

	// Test without channel binding
	conv1 := client.NewConversation()
	msg1, _ := conv1.Step("")
	if !strings.HasPrefix(msg1, "n,,") {
		t.Errorf("Expected gs2-header to start with 'n,,', got %q", msg1[:10])
	}

	// Test with tls-exporter channel binding
	cbData := []byte("test-channel-binding-data")
	conv2 := client.NewConversationWithChannelBinding(ChannelBinding{
		Type: ChannelBindingTLSExporter,
		Data: cbData,
	})

	msg2, _ := conv2.Step("")
	if !strings.HasPrefix(msg2, "p=tls-exporter,,") {
		t.Errorf("Expected gs2-header to start with 'p=tls-exporter,,', got %q", msg2[:20])
	}

	// Verify conversation has channel binding
	if !conv2.channelBinding.IsSupported() {
		t.Error("Expected conversation to have channel binding")
	}
	if conv2.channelBinding.Type != ChannelBindingTLSExporter {
		t.Errorf("Expected type %q, got %q", ChannelBindingTLSExporter, conv2.channelBinding.Type)
	}
}

func TestClientServerChannelBindingIntegration(t *testing.T) {
	username := "user"
	password := "pencil"
	cbData := []byte("test-channel-binding-data")

	// Setup client
	client, _ := SHA256.NewClient(username, password, "")

	// Setup server
	credLookup := func(username string) (StoredCredentials, error) {
		client, _ := SHA256.NewClient(username, password, "")
		salt := []byte("QSXCR+Q6sek8bf92")
		return client.GetStoredCredentials(KeyFactors{Salt: string(salt), Iters: 4096}), nil
	}
	server, _ := SHA256.NewServer(credLookup)

	// Run authentication conversation with channel binding
	clientConv := client.NewConversationWithChannelBinding(ChannelBinding{
		Type: ChannelBindingTLSExporter,
		Data: cbData,
	})
	serverConv := server.NewConversationWithChannelBinding(ChannelBinding{
		Type: ChannelBindingTLSExporter,
		Data: cbData,
	})

	// Client first message
	clientFirst, err := clientConv.Step("")
	if err != nil {
		t.Fatalf("Client first step failed: %v", err)
	}

	// Server first message
	serverFirst, err := serverConv.Step(clientFirst)
	if err != nil {
		t.Fatalf("Server first step failed: %v", err)
	}

	// Client final message
	clientFinal, err := clientConv.Step(serverFirst)
	if err != nil {
		t.Fatalf("Client final step failed: %v", err)
	}

	// Server final message
	serverFinal, err := serverConv.Step(clientFinal)
	if err != nil {
		t.Fatalf("Server final step failed: %v", err)
	}

	// Client validation
	_, err = clientConv.Step(serverFinal)
	if err != nil {
		t.Fatalf("Client validation failed: %v", err)
	}

	// Verify both sides are valid
	if !clientConv.Valid() {
		t.Error("Client conversation should be valid")
	}
	if !serverConv.Valid() {
		t.Error("Server conversation should be valid")
	}
}

func TestClientServerChannelBindingMismatch(t *testing.T) {
	username := "user"
	password := "pencil"

	// Setup client
	client, _ := SHA256.NewClient(username, password, "")

	// Setup server
	credLookup := func(username string) (StoredCredentials, error) {
		client, _ := SHA256.NewClient(username, password, "")
		salt := []byte("QSXCR+Q6sek8bf92")
		return client.GetStoredCredentials(KeyFactors{Salt: string(salt), Iters: 4096}), nil
	}
	server, _ := SHA256.NewServer(credLookup)

	// Run authentication conversation with mismatched channel binding
	clientConv := client.NewConversationWithChannelBinding(ChannelBinding{
		Type: ChannelBindingTLSExporter,
		Data: []byte("client-data"),
	})
	serverConv := server.NewConversationWithChannelBinding(ChannelBinding{
		Type: ChannelBindingTLSExporter,
		Data: []byte("server-data"),
	})

	// Client first message
	clientFirst, _ := clientConv.Step("")

	// Server first message
	serverFirst, _ := serverConv.Step(clientFirst)

	// Client final message
	clientFinal, _ := clientConv.Step(serverFirst)

	// Server final message should fail due to channel binding mismatch
	_, err := serverConv.Step(clientFinal)
	if err == nil {
		t.Fatal("Expected error due to channel binding mismatch, got nil")
	}
	if !strings.Contains(err.Error(), "channel binding mismatch") {
		t.Errorf("Expected 'channel binding mismatch' error, got: %v", err)
	}

	// Server should not be valid
	if serverConv.Valid() {
		t.Error("Server conversation should not be valid")
	}
}

func TestServerRejectsChannelBindingWhenNotConfigured(t *testing.T) {
	username := "user"
	password := "pencil"

	// Setup client
	client, _ := SHA256.NewClient(username, password, "")

	// Setup server
	credLookup := func(username string) (StoredCredentials, error) {
		client, _ := SHA256.NewClient(username, password, "")
		salt := []byte("QSXCR+Q6sek8bf92")
		return client.GetStoredCredentials(KeyFactors{Salt: string(salt), Iters: 4096}), nil
	}
	server, _ := SHA256.NewServer(credLookup)

	// Run authentication conversation - client with channel binding, server without
	clientConv := client.NewConversationWithChannelBinding(ChannelBinding{
		Type: ChannelBindingTLSExporter,
		Data: []byte("test-data"),
	})
	serverConv := server.NewConversation()
	// No channel binding configured on server

	// Client first message
	clientFirst, _ := clientConv.Step("")

	// Server should reject the client's channel binding request
	_, err := serverConv.Step(clientFirst)
	if err == nil {
		t.Fatal("Expected error when server doesn't support channel binding, got nil")
	}
	if !strings.Contains(err.Error(), "channel binding") {
		t.Errorf("Expected channel binding error, got: %v", err)
	}
}

func TestServerRejectsUnsupportedChannelBindingType(t *testing.T) {
	username := "user"
	password := "pencil"

	// Setup client
	client, _ := SHA256.NewClient(username, password, "")

	// Setup server
	credLookup := func(username string) (StoredCredentials, error) {
		client, _ := SHA256.NewClient(username, password, "")
		salt := []byte("QSXCR+Q6sek8bf92")
		return client.GetStoredCredentials(KeyFactors{Salt: string(salt), Iters: 4096}), nil
	}
	server, _ := SHA256.NewServer(credLookup)

	// Run authentication conversation - client with tls-exporter, server with tls-server-end-point
	clientConv := client.NewConversationWithChannelBinding(ChannelBinding{
		Type: ChannelBindingTLSExporter,
		Data: []byte("test-data"),
	})
	serverConv := server.NewConversationWithChannelBinding(ChannelBinding{
		Type: ChannelBindingTLSServerEndpoint,
		Data: []byte("test-data"),
	})

	// Client first message
	clientFirst, _ := clientConv.Step("")

	// Server should reject the unsupported channel binding type
	_, err := serverConv.Step(clientFirst)
	if err == nil {
		t.Fatal("Expected error for unsupported channel binding type, got nil")
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, "tls-exporter") || !strings.Contains(errMsg, "tls-server-end-point") {
		t.Errorf("Expected error about channel binding type mismatch, got: %v", err)
	}
}

func TestClientWithoutChannelBindingWorksWithServerWithChannelBinding(t *testing.T) {
	username := "user"
	password := "pencil"

	// Setup client
	client, _ := SHA256.NewClient(username, password, "")

	// Setup server
	credLookup := func(username string) (StoredCredentials, error) {
		client, _ := SHA256.NewClient(username, password, "")
		salt := []byte("QSXCR+Q6sek8bf92")
		return client.GetStoredCredentials(KeyFactors{Salt: string(salt), Iters: 4096}), nil
	}
	server, _ := SHA256.NewServer(credLookup)

	// Run authentication conversation - client without channel binding, server with
	clientConv := client.NewConversation()
	serverConv := server.NewConversationWithChannelBinding(ChannelBinding{
		Type: ChannelBindingTLSExporter,
		Data: []byte("test-data"),
	})

	// Client first message
	clientFirst, err := clientConv.Step("")
	if err != nil {
		t.Fatalf("Client first step failed: %v", err)
	}

	// Server first message (should accept client without channel binding)
	serverFirst, err := serverConv.Step(clientFirst)
	if err != nil {
		t.Fatalf("Server first step failed: %v", err)
	}

	// Client final message
	clientFinal, err := clientConv.Step(serverFirst)
	if err != nil {
		t.Fatalf("Client final step failed: %v", err)
	}

	// Server final message
	serverFinal, err := serverConv.Step(clientFinal)
	if err != nil {
		t.Fatalf("Server final step failed: %v", err)
	}

	// Client validation
	_, err = clientConv.Step(serverFinal)
	if err != nil {
		t.Fatalf("Client validation failed: %v", err)
	}

	// Verify both sides are valid
	if !clientConv.Valid() {
		t.Error("Client conversation should be valid")
	}
	if !serverConv.Valid() {
		t.Error("Server conversation should be valid")
	}
}

func TestAllChannelBindingTypes(t *testing.T) {
	username := "user"
	password := "pencil"

	bindingTypes := []ChannelBindingType{
		ChannelBindingTLSUnique,
		ChannelBindingTLSServerEndpoint,
		ChannelBindingTLSExporter,
	}

	for _, cbType := range bindingTypes {
		t.Run(string(cbType), func(t *testing.T) {
			cbData := []byte("test-data-for-" + string(cbType))

			// Setup client
			client, _ := SHA256.NewClient(username, password, "")

			// Setup server
			credLookup := func(username string) (StoredCredentials, error) {
				client, _ := SHA256.NewClient(username, password, "")
				salt := []byte("QSXCR+Q6sek8bf92")
				return client.GetStoredCredentials(KeyFactors{Salt: string(salt), Iters: 4096}), nil
			}
			server, _ := SHA256.NewServer(credLookup)

			// Run full authentication with channel binding
			clientConv := client.NewConversationWithChannelBinding(ChannelBinding{
				Type: cbType,
				Data: cbData,
			})
			serverConv := server.NewConversationWithChannelBinding(ChannelBinding{
				Type: cbType,
				Data: cbData,
			})

			clientFirst, _ := clientConv.Step("")
			serverFirst, _ := serverConv.Step(clientFirst)
			clientFinal, _ := clientConv.Step(serverFirst)
			serverFinal, _ := serverConv.Step(clientFinal)
			_, err := clientConv.Step(serverFinal)

			if err != nil {
				t.Fatalf("Authentication failed for %s: %v", cbType, err)
			}

			if !clientConv.Valid() || !serverConv.Valid() {
				t.Errorf("Authentication not valid for %s", cbType)
			}
		})
	}
}

func TestServerWithChannelBindingRequired_RejectsClientWithoutChannelBinding(t *testing.T) {
	username := "user"
	password := "pencil"

	// Setup client
	client, _ := SHA256.NewClient(username, password, "")

	// Setup server
	credLookup := func(username string) (StoredCredentials, error) {
		client, _ := SHA256.NewClient(username, password, "")
		salt := []byte("QSXCR+Q6sek8bf92")
		return client.GetStoredCredentials(KeyFactors{Salt: string(salt), Iters: 4096}), nil
	}
	server, _ := SHA256.NewServer(credLookup)

	// Run authentication conversation - client without channel binding, server requires it
	clientConv := client.NewConversation()
	serverConv := server.NewConversationWithChannelBindingRequired(ChannelBinding{
		Type: ChannelBindingTLSExporter,
		Data: []byte("test-data"),
	})

	// Client first message (will use "n" flag since no channel binding configured)
	clientFirst, _ := clientConv.Step("")

	// Server should reject due to channel binding being required
	_, err := serverConv.Step(clientFirst)
	if err == nil {
		t.Fatal("Expected error when server requires channel binding but client doesn't support it, got nil")
	}
	if !strings.Contains(err.Error(), "channel binding") && !strings.Contains(err.Error(), "requires") {
		t.Errorf("Expected 'channel binding required' error, got: %v", err)
	}
}

func TestServerWithChannelBindingRequired_RejectsDowngradeAttack(t *testing.T) {
	password := "pencil"

	// Setup server
	credLookup := func(username string) (StoredCredentials, error) {
		client, _ := SHA256.NewClient(username, password, "")
		salt := []byte("QSXCR+Q6sek8bf92")
		return client.GetStoredCredentials(KeyFactors{Salt: string(salt), Iters: 4096}), nil
	}
	server, _ := SHA256.NewServer(credLookup)

	serverConv := server.NewConversationWithChannelBindingRequired(ChannelBinding{
		Type: ChannelBindingTLSExporter,
		Data: []byte("test-data"),
	})

	// Craft a client-first message with "y" flag (client supports channel binding
	// but thinks server doesn't advertise PLUS variant)
	// Format: gs2-header "," [ authzid ] "," username "," nonce
	// gs2-header: "y" "," [ authzid ]
	clientFirst := "y,,n=user,r=clientnonce123"

	// Server should reject this as a downgrade attack
	_, err := serverConv.Step(clientFirst)
	if err == nil {
		t.Fatal("Expected error for downgrade attack (y flag when server advertised PLUS), got nil")
	}
	if !strings.Contains(err.Error(), "downgrade") || !strings.Contains(err.Error(), "y") {
		t.Errorf("Expected 'downgrade attack' error, got: %v", err)
	}
}

func TestServerWithChannelBindingRequired_AcceptsClientWithChannelBinding(t *testing.T) {
	username := "user"
	password := "pencil"
	cbData := []byte("test-data")

	// Setup client
	client, _ := SHA256.NewClient(username, password, "")

	// Setup server
	credLookup := func(username string) (StoredCredentials, error) {
		client, _ := SHA256.NewClient(username, password, "")
		salt := []byte("QSXCR+Q6sek8bf92")
		return client.GetStoredCredentials(KeyFactors{Salt: string(salt), Iters: 4096}), nil
	}
	server, _ := SHA256.NewServer(credLookup)

	// Run full authentication with channel binding required - should succeed
	clientConv := client.NewConversationWithChannelBinding(ChannelBinding{
		Type: ChannelBindingTLSExporter,
		Data: cbData,
	})
	serverConv := server.NewConversationWithChannelBindingRequired(ChannelBinding{
		Type: ChannelBindingTLSExporter,
		Data: cbData,
	})

	clientFirst, _ := clientConv.Step("")
	serverFirst, _ := serverConv.Step(clientFirst)
	clientFinal, _ := clientConv.Step(serverFirst)
	serverFinal, err := serverConv.Step(clientFinal)
	if err != nil {
		t.Fatalf("Server step failed: %v", err)
	}

	_, err = clientConv.Step(serverFinal)
	if err != nil {
		t.Fatalf("Client validation failed: %v", err)
	}

	if !clientConv.Valid() || !serverConv.Valid() {
		t.Error("Authentication should be valid when both client and server use matching channel binding")
	}
}

func TestServerWithOptionalChannelBinding_AcceptsClientWithoutChannelBinding(t *testing.T) {
	username := "user"
	password := "pencil"

	// Setup client
	client, _ := SHA256.NewClient(username, password, "")

	// Setup server
	credLookup := func(username string) (StoredCredentials, error) {
		client, _ := SHA256.NewClient(username, password, "")
		salt := []byte("QSXCR+Q6sek8bf92")
		return client.GetStoredCredentials(KeyFactors{Salt: string(salt), Iters: 4096}), nil
	}
	server, _ := SHA256.NewServer(credLookup)

	// Run full authentication - server with optional channel binding, client without
	clientConv := client.NewConversation()
	serverConv := server.NewConversationWithChannelBinding(ChannelBinding{
		Type: ChannelBindingTLSExporter,
		Data: []byte("test-data"),
	})

	clientFirst, _ := clientConv.Step("")
	serverFirst, _ := serverConv.Step(clientFirst)
	clientFinal, _ := clientConv.Step(serverFirst)
	serverFinal, err := serverConv.Step(clientFinal)
	if err != nil {
		t.Fatalf("Server step failed: %v", err)
	}

	_, err = clientConv.Step(serverFinal)
	if err != nil {
		t.Fatalf("Client validation failed: %v", err)
	}

	if !clientConv.Valid() || !serverConv.Valid() {
		t.Error("Authentication should be valid - server has optional channel binding")
	}
}

func TestServerWithOptionalChannelBinding_RejectsDowngradeAttack(t *testing.T) {
	password := "pencil"

	// Setup server
	credLookup := func(username string) (StoredCredentials, error) {
		client, _ := SHA256.NewClient(username, password, "")
		salt := []byte("QSXCR+Q6sek8bf92")
		return client.GetStoredCredentials(KeyFactors{Salt: string(salt), Iters: 4096}), nil
	}
	server, _ := SHA256.NewServer(credLookup)

	serverConv := server.NewConversationWithChannelBinding(ChannelBinding{
		Type: ChannelBindingTLSExporter,
		Data: []byte("test-data"),
	})

	// Craft a client-first message with "y" flag (client supports channel binding
	// but thinks server doesn't advertise PLUS variant)
	// This is a downgrade attack even when channel binding is optional
	clientFirst := "y,,n=user,r=clientnonce123"

	// Server should reject this as a downgrade attack
	_, err := serverConv.Step(clientFirst)
	if err == nil {
		t.Fatal("Expected error for downgrade attack (y flag when server advertised PLUS), got nil")
	}
	if !strings.Contains(err.Error(), "downgrade") || !strings.Contains(err.Error(), "y") {
		t.Errorf("Expected 'downgrade attack' error, got: %v", err)
	}
}

// Helper function to create a test certificate
func createTestCert(t *testing.T, sigAlg x509.SignatureAlgorithm) *x509.Certificate {
	t.Helper()

	// Use ECDSA for all signature algorithms for simplicity in testing
	// What matters for channel binding is the certificate's Raw bytes and
	// the SignatureAlgorithm field, not the actual key type match
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("Failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		// Use ECDSA signature for actual signing
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Override the signature algorithm in the parsed cert to test different hash behaviors
	cert.SignatureAlgorithm = sigAlg

	return cert
}

// Helper function to create a mock TLS connection state with a certificate
func createMockConnState(t *testing.T, cert *x509.Certificate) *tls.ConnectionState {
	t.Helper()

	return &tls.ConnectionState{
		Version:           tls.VersionTLS13,
		HandshakeComplete: true,
		PeerCertificates:  []*x509.Certificate{cert},
	}
}

func TestNewTLSUniqueBinding(t *testing.T) {
	testData := []byte("test-tls-unique-data")

	cb := NewTLSUniqueBinding(testData)

	if cb.Type != ChannelBindingTLSUnique {
		t.Errorf("Expected type %q, got %q", ChannelBindingTLSUnique, cb.Type)
	}

	if string(cb.Data) != string(testData) {
		t.Errorf("Expected data %q, got %q", testData, cb.Data)
	}

	if !cb.IsSupported() {
		t.Error("Expected channel binding to be supported")
	}
}

func TestNewTLSServerEndpointBinding(t *testing.T) {
	tests := []struct {
		name   string
		sigAlg x509.SignatureAlgorithm
	}{
		{"SHA256WithRSA", x509.SHA256WithRSA},
		{"SHA256WithRSAPSS", x509.SHA256WithRSAPSS},
		{"ECDSAWithSHA256", x509.ECDSAWithSHA256},
		{"ECDSAWithSHA384", x509.ECDSAWithSHA384},
		{"ECDSAWithSHA512", x509.ECDSAWithSHA512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := createTestCert(t, tt.sigAlg)
			connState := createMockConnState(t, cert)

			cb, err := NewTLSServerEndpointBinding(connState)
			if err != nil {
				t.Fatalf("NewTLSServerEndpointBinding failed: %v", err)
			}

			if cb.Type != ChannelBindingTLSServerEndpoint {
				t.Errorf("Expected type %q, got %q", ChannelBindingTLSServerEndpoint, cb.Type)
			}

			if len(cb.Data) == 0 {
				t.Error("Expected non-empty channel binding data")
			}

			if !cb.IsSupported() {
				t.Error("Expected channel binding to be supported")
			}
		})
	}
}

func TestNewTLSServerEndpointBinding_NilConnectionState(t *testing.T) {
	_, err := NewTLSServerEndpointBinding(nil)
	if err == nil {
		t.Fatal("Expected error for nil connection state, got nil")
	}
	if !strings.Contains(err.Error(), "nil") {
		t.Errorf("Expected 'nil' in error message, got: %v", err)
	}
}

func TestNewTLSServerEndpointBinding_NoPeerCertificates(t *testing.T) {
	connState := &tls.ConnectionState{
		Version:           tls.VersionTLS13,
		HandshakeComplete: true,
		PeerCertificates:  []*x509.Certificate{},
	}

	_, err := NewTLSServerEndpointBinding(connState)
	if err == nil {
		t.Fatal("Expected error for no peer certificates, got nil")
	}
	if !strings.Contains(err.Error(), "no peer certificates") {
		t.Errorf("Expected 'no peer certificates' in error message, got: %v", err)
	}
}

func TestNewTLSServerEndpointBinding_ConsistentHashing(t *testing.T) {
	// Create a certificate and verify that hashing is deterministic
	cert := createTestCert(t, x509.ECDSAWithSHA256)
	connState := createMockConnState(t, cert)

	cb1, err1 := NewTLSServerEndpointBinding(connState)
	if err1 != nil {
		t.Fatalf("First call failed: %v", err1)
	}

	cb2, err2 := NewTLSServerEndpointBinding(connState)
	if err2 != nil {
		t.Fatalf("Second call failed: %v", err2)
	}

	if !cb1.Matches(cb2) {
		t.Error("Expected consistent hashing for the same certificate")
	}
}

func TestNewTLSServerEndpointBinding_SHA1UpgradedToSHA256(t *testing.T) {
	// SHA-1 and MD5 signatures should be upgraded to SHA-256
	cert := createTestCert(t, x509.SHA1WithRSA)
	connState := createMockConnState(t, cert)

	cb, err := NewTLSServerEndpointBinding(connState)
	if err != nil {
		t.Fatalf("NewTLSServerEndpointBinding failed: %v", err)
	}

	// The hash should be SHA-256 (32 bytes)
	if len(cb.Data) != sha256.Size {
		t.Errorf("Expected SHA-256 hash length of %d bytes, got %d bytes", sha256.Size, len(cb.Data))
	}
}

func TestNewTLSExporterBinding(t *testing.T) {
	// Note: We can't fully test ExportKeyingMaterial without a real TLS connection,
	// but we can test that the constructor handles the connection state properly.

	t.Run("NilConnectionState", func(t *testing.T) {
		_, err := NewTLSExporterBinding(nil)
		if err == nil {
			t.Fatal("Expected error for nil connection state, got nil")
		}
		if !strings.Contains(err.Error(), "nil") {
			t.Errorf("Expected 'nil' in error message, got: %v", err)
		}
	})
}

func TestChannelBindingConstructors_Integration(t *testing.T) {
	// Test that constructors create ChannelBinding structs that work
	// with the existing authentication flow

	username := "user"
	password := "pencil"

	t.Run("TLSUnique", func(t *testing.T) {
		cbData := []byte("test-tls-unique-data")
		cb := NewTLSUniqueBinding(cbData)

		client, _ := SHA256.NewClient(username, password, "")

		conv := client.NewConversationWithChannelBinding(cb)
		msg, err := conv.Step("")
		if err != nil {
			t.Fatalf("Client step failed: %v", err)
		}

		if !strings.HasPrefix(msg, "p=tls-unique,,") {
			t.Errorf("Expected message to start with 'p=tls-unique,,', got %q", msg[:20])
		}
	})

	t.Run("TLSServerEndpoint", func(t *testing.T) {
		cert := createTestCert(t, x509.ECDSAWithSHA256)
		connState := createMockConnState(t, cert)

		cb, err := NewTLSServerEndpointBinding(connState)
		if err != nil {
			t.Fatalf("NewTLSServerEndpointBinding failed: %v", err)
		}

		client, _ := SHA256.NewClient(username, password, "")

		conv := client.NewConversationWithChannelBinding(cb)
		msg, err := conv.Step("")
		if err != nil {
			t.Fatalf("Client step failed: %v", err)
		}

		if !strings.HasPrefix(msg, "p=tls-server-end-point,,") {
			t.Errorf("Expected message to start with 'p=tls-server-end-point,,', got %q", msg[:30])
		}
	})
}
