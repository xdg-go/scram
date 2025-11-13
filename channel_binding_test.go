// Copyright 2018 by David A. Golden. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

package scram

import (
	"strings"
	"testing"
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
	client.WithChannelBinding(ChannelBinding{
		Type: ChannelBindingTLSExporter,
		Data: cbData,
	})

	conv2 := client.NewConversation()
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

	// Setup client with channel binding
	client, _ := SHA256.NewClient(username, password, "")
	client.WithChannelBinding(ChannelBinding{
		Type: ChannelBindingTLSExporter,
		Data: cbData,
	})

	// Setup server with matching channel binding
	credLookup := func(username string) (StoredCredentials, error) {
		client, _ := SHA256.NewClient(username, password, "")
		salt := []byte("QSXCR+Q6sek8bf92")
		return client.GetStoredCredentials(KeyFactors{Salt: string(salt), Iters: 4096}), nil
	}
	server, _ := SHA256.NewServer(credLookup)
	server.WithChannelBinding(ChannelBinding{
		Type: ChannelBindingTLSExporter,
		Data: cbData,
	})

	// Run authentication conversation
	clientConv := client.NewConversation()
	serverConv := server.NewConversation()

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

	// Setup client with one channel binding
	client, _ := SHA256.NewClient(username, password, "")
	client.WithChannelBinding(ChannelBinding{
		Type: ChannelBindingTLSExporter,
		Data: []byte("client-data"),
	})

	// Setup server with different channel binding
	credLookup := func(username string) (StoredCredentials, error) {
		client, _ := SHA256.NewClient(username, password, "")
		salt := []byte("QSXCR+Q6sek8bf92")
		return client.GetStoredCredentials(KeyFactors{Salt: string(salt), Iters: 4096}), nil
	}
	server, _ := SHA256.NewServer(credLookup)
	server.WithChannelBinding(ChannelBinding{
		Type: ChannelBindingTLSExporter,
		Data: []byte("server-data"),
	})

	// Run authentication conversation
	clientConv := client.NewConversation()
	serverConv := server.NewConversation()

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

	// Setup client with channel binding
	client, _ := SHA256.NewClient(username, password, "")
	client.WithChannelBinding(ChannelBinding{
		Type: ChannelBindingTLSExporter,
		Data: []byte("test-data"),
	})

	// Setup server WITHOUT channel binding
	credLookup := func(username string) (StoredCredentials, error) {
		client, _ := SHA256.NewClient(username, password, "")
		salt := []byte("QSXCR+Q6sek8bf92")
		return client.GetStoredCredentials(KeyFactors{Salt: string(salt), Iters: 4096}), nil
	}
	server, _ := SHA256.NewServer(credLookup)
	// No channel binding configured

	// Run authentication conversation
	clientConv := client.NewConversation()
	serverConv := server.NewConversation()

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

	// Setup client with tls-exporter
	client, _ := SHA256.NewClient(username, password, "")
	client.WithChannelBinding(ChannelBinding{
		Type: ChannelBindingTLSExporter,
		Data: []byte("test-data"),
	})

	// Setup server with tls-server-end-point
	credLookup := func(username string) (StoredCredentials, error) {
		client, _ := SHA256.NewClient(username, password, "")
		salt := []byte("QSXCR+Q6sek8bf92")
		return client.GetStoredCredentials(KeyFactors{Salt: string(salt), Iters: 4096}), nil
	}
	server, _ := SHA256.NewServer(credLookup)
	server.WithChannelBinding(ChannelBinding{
		Type: ChannelBindingTLSServerEndpoint,
		Data: []byte("test-data"),
	})

	// Run authentication conversation
	clientConv := client.NewConversation()
	serverConv := server.NewConversation()

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

	// Setup client WITHOUT channel binding
	client, _ := SHA256.NewClient(username, password, "")

	// Setup server WITH channel binding
	credLookup := func(username string) (StoredCredentials, error) {
		client, _ := SHA256.NewClient(username, password, "")
		salt := []byte("QSXCR+Q6sek8bf92")
		return client.GetStoredCredentials(KeyFactors{Salt: string(salt), Iters: 4096}), nil
	}
	server, _ := SHA256.NewServer(credLookup)
	server.WithChannelBinding(ChannelBinding{
		Type: ChannelBindingTLSExporter,
		Data: []byte("test-data"),
	})

	// Run authentication conversation
	clientConv := client.NewConversation()
	serverConv := server.NewConversation()

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

			// Setup client with channel binding
			client, _ := SHA256.NewClient(username, password, "")
			client.WithChannelBinding(ChannelBinding{
				Type: cbType,
				Data: cbData,
			})

			// Setup server with matching channel binding
			credLookup := func(username string) (StoredCredentials, error) {
				client, _ := SHA256.NewClient(username, password, "")
				salt := []byte("QSXCR+Q6sek8bf92")
				return client.GetStoredCredentials(KeyFactors{Salt: string(salt), Iters: 4096}), nil
			}
			server, _ := SHA256.NewServer(credLookup)
			server.WithChannelBinding(ChannelBinding{
				Type: cbType,
				Data: cbData,
			})

			// Run full authentication
			clientConv := client.NewConversation()
			serverConv := server.NewConversation()

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
