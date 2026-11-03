// Copyright 2018 by David A. Golden. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

package scram

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"testing"

	"github.com/xdg-go/stringprep"
)

func TestServerConv(t *testing.T) {
	cases, err := getTestData("good", "bad-client")
	if err != nil {
		t.Fatal(err)
	}

	for _, v := range cases {
		t.Run(v.Label, genServerSubTest(v))
	}
}

// Prep user credential callback for the case from Client
func genServerCallback(c TestCase) (CredentialLookup, error) {
	salt, err := base64.StdEncoding.DecodeString(c.Salt64)
	if err != nil {
		return nil, fmt.Errorf("error decoding salt: %v", err)
	}

	hgf, err := getHGF(c.Digest)
	if err != nil {
		return nil, fmt.Errorf("error getting digest for credential callback: %v", err)
	}

	kf := KeyFactors{Salt: string(salt), Iters: c.Iters}

	var client *Client
	var userprep string
	if c.SkipSASLprep {
		client, err = hgf.NewClientUnprepped(c.User, c.Pass, c.AuthzID)
		userprep = c.User
	} else {
		client, err = hgf.NewClient(c.User, c.Pass, c.AuthzID)
		if err != nil {
			return nil, fmt.Errorf("error creating client for credential callback: %v", err)
		}
		if userprep, err = stringprep.SASLprep.Prepare(c.User); err != nil {
			return nil, fmt.Errorf("Error SASLprepping username '%s': %v", c.User, err)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("error generating client for credential callback: %v", err)
	}

	stored, err := client.GetStoredCredentialsWithError(kf)
	if err != nil {
		return nil, fmt.Errorf("error getting stored credentials: %w", err)
	}

	cbFcn := func(s string) (StoredCredentials, error) {
		if s == userprep {
			return stored, nil
		}
		return StoredCredentials{}, fmt.Errorf("Unknown user %s", s)
	}

	return cbFcn, nil
}

func genServerSubTest(c TestCase) func(t *testing.T) {
	return func(t *testing.T) {
		hgf, err := getHGF(c.Digest)
		if err != nil {
			t.Fatal(err)
		}

		cbFcn, err := genServerCallback(c)
		if err != nil {
			t.Fatal(err)
		}

		server, err := hgf.NewServer(cbFcn)
		if err != nil {
			t.Fatalf("%s: expected no error from NewServer, but got '%v'", c.Label, err)
		}
		if c.ServerNonce != "" {
			server = server.WithNonceGenerator(func() string { return c.ServerNonce })
		}
		conv := server.NewConversation()

		for i, s := range serverSteps(c) {
			if conv.Done() {
				t.Errorf("%s: Premature end of conversation before step %d", c.Label, i+1)
				return
			}
			got, err := conv.Step(s.Input)
			if s.IsError && err == nil {
				t.Errorf("%s: step %d: expected error but didn't get one", c.Label, i+1)
				return
			} else if !s.IsError && err != nil {
				t.Errorf("%s: step %d: expected no error but got '%v'", c.Label, i+1, err)
				return
			}
			if got != s.Expect {
				t.Errorf("%s: step %d: incorrect step message; got %s, expected %s",
					c.Label,
					i+1,
					strconv.QuoteToASCII(got),
					strconv.QuoteToASCII(s.Expect),
				)
				return
			}
		}

		if c.Valid != conv.Valid() {
			t.Errorf("%s: Conversation Valid() incorrect: got '%v', expected '%v'", c.Label, conv.Valid(), c.Valid)
			return
		}

		if !conv.Done() {
			t.Errorf("%s: Conversation not marked done after last step", c.Label)
		}

		var expectedUser string
		if c.SkipSASLprep {
			expectedUser = c.User
		} else {
			if expectedUser, err = stringprep.SASLprep.Prepare(c.User); err != nil {
				t.Errorf("Error SASLprepping username '%s': %v", c.User, err)
			}
		}

		if conv.Valid() && conv.Username() != expectedUser {
			t.Errorf("%s: Conversation didn't record proper username: got '%s', expected '%s'", c.Label, conv.Username(), expectedUser)
		}
	}
}

// RFC 5802 §5.1: the server must decode "=2C" and "=3D" in the username and
// authzid before the credential lookup.
func TestServerDecodesEscapedNames(t *testing.T) {
	cases := []struct {
		label       string
		c1          string
		wantUser    string
		wantAuthzID string
	}{
		{label: "plain", c1: "n,,n=user,r=nonce", wantUser: "user"},
		{label: "equals", c1: "n,,n=user=3Dx,r=nonce", wantUser: "user=x"},
		{label: "comma", c1: "n,,n=a=2Cb,r=nonce", wantUser: "a,b"},
		{label: "literal escape text", c1: "n,,n=x=3D2C,r=nonce", wantUser: "x=2C"},
		{label: "authzid", c1: "n,a=a=3Dx=2Cy,n=user,r=nonce", wantUser: "user", wantAuthzID: "a=x,y"},
	}

	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			var lookedUp string
			server, err := SHA256.NewServer(func(name string) (StoredCredentials, error) {
				lookedUp = name
				return StoredCredentials{KeyFactors: KeyFactors{Salt: "salt", Iters: 4096}}, nil
			})
			if err != nil {
				t.Fatal(err)
			}

			conv := server.NewConversation()
			if _, err := conv.Step(c.c1); err != nil {
				t.Fatalf("Step(%q): %v", c.c1, err)
			}

			if lookedUp != c.wantUser {
				t.Errorf("lookup got %q, want %q", lookedUp, c.wantUser)
			}
			if got := conv.Username(); got != c.wantUser {
				t.Errorf("Username() = %q, want %q", got, c.wantUser)
			}
			if got := conv.AuthzID(); got != c.wantAuthzID {
				t.Errorf("AuthzID() = %q, want %q", got, c.wantAuthzID)
			}
		})
	}
}

// RFC 5802 §5.1: a username with '=' not followed by "2C" or "3D" MUST fail.
// The server must reject it before the credential lookup.
func TestServerRejectsMalformedNameEscapes(t *testing.T) {
	names := []string{"=", "=3", "a=", "a=b", "=2c", "=3d", "=41", "==3D", "=3D="}

	cases := []struct {
		field     string
		c1        func(name string) string
		wantReply string
	}{
		{
			field:     "username",
			c1:        func(name string) string { return "n,,n=" + name + ",r=nonce" },
			wantReply: ErrInvalidUsernameEncoding,
		},
		{
			field:     "authzid",
			c1:        func(name string) string { return "n,a=" + name + ",n=user,r=nonce" },
			wantReply: ErrInvalidEncoding,
		},
	}

	for _, c := range cases {
		for _, name := range names {
			t.Run(c.field+"/"+name, func(t *testing.T) {
				lookupCalled := false
				server, err := SHA256.NewServer(func(string) (StoredCredentials, error) {
					lookupCalled = true
					return StoredCredentials{KeyFactors: KeyFactors{Salt: "salt", Iters: 4096}}, nil
				})
				if err != nil {
					t.Fatal(err)
				}

				conv := server.NewConversation()
				c1 := c.c1(name)
				reply, err := conv.Step(c1)
				if err == nil {
					t.Fatalf("Step(%q): expected error", c1)
				}
				if reply != c.wantReply {
					t.Errorf("Step(%q) reply = %q, want %q", c1, reply, c.wantReply)
				}
				if lookupCalled {
					t.Errorf("Step(%q): credential lookup was called", c1)
				}
				if !conv.Done() || conv.Valid() {
					t.Errorf("Step(%q): conversation should be done and invalid", c1)
				}
			})
		}
	}
}

// Full client-server conversations with names that need escaping. The server's
// lookup must receive the SASLprepped, decoded username, and proofs must still
// verify because the AuthMessage uses the escaped wire form.
func TestInteropEscapedNames(t *testing.T) {
	cases := []struct {
		label       string
		username    string
		authzID     string
		wantUser    string
		wantAuthzID string
	}{
		{label: "plain", username: "user", wantUser: "user"},
		{label: "equals", username: "user=x", wantUser: "user=x"},
		{label: "comma", username: "a,b", wantUser: "a,b"},
		{label: "both", username: "u=x,y", wantUser: "u=x,y"},
		{label: "literal escape text", username: "x=3D2C", wantUser: "x=3D2C"},
		{label: "authzid", username: "user", authzID: "a=x,y", wantUser: "user", wantAuthzID: "a=x,y"},
		// SASLprep (NFKC) maps fullwidth U+FF1D/U+FF0C to '=' and ',' before
		// the client escapes them.
		{label: "fullwidth equals", username: "a＝b", wantUser: "a=b"},
		{label: "fullwidth comma", username: "a，b", wantUser: "a,b"},
		{label: "fullwidth authzid", username: "user", authzID: "a＝b，c", wantUser: "user", wantAuthzID: "a=b,c"},
	}

	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			client, err := SHA256.NewClient(c.username, "pencil", c.authzID)
			if err != nil {
				t.Fatal(err)
			}
			stored, err := client.GetStoredCredentialsWithError(KeyFactors{Salt: "salt", Iters: 4096})
			if err != nil {
				t.Fatal(err)
			}
			server, err := SHA256.NewServer(func(name string) (StoredCredentials, error) {
				if name != c.wantUser {
					return StoredCredentials{}, fmt.Errorf("lookup got %q, want %q", name, c.wantUser)
				}
				return stored, nil
			})
			if err != nil {
				t.Fatal(err)
			}

			cc, sc := client.NewConversation(), server.NewConversation()
			step, err := runFullAuthFlow(cc, sc)
			assertFinishedSuccessfully(t, step, err)

			if got := sc.Username(); got != c.wantUser {
				t.Errorf("Username() = %q, want %q", got, c.wantUser)
			}
			if got := sc.AuthzID(); got != c.wantAuthzID {
				t.Errorf("AuthzID() = %q, want %q", got, c.wantAuthzID)
			}
		})
	}
}
