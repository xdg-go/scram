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

// A full client-server conversation must succeed for usernames and authzIDs
// that the client escapes per RFC 5802 section 5.1 ("=" as "=3D" and "," as
// "=2C"): the server must unescape them before the credential lookup and
// when reporting Username()/AuthzID().
func TestInteropEscapedUsername(t *testing.T) {
	for _, tc := range []struct {
		username string
		authzID  string
	}{
		{"user", ""},    // control: no escapes
		{"user=x", ""},  // '=' is escaped as =3D on the wire
		{"a,b", ""},     // ',' is escaped as =2C on the wire
		{"u=x,y", ""},   // both
		{"user", "a=x"}, // escaped authzID
	} {
		client, err := SHA1.NewClient(tc.username, "pencil", tc.authzID)
		if err != nil {
			t.Fatalf("username %q: NewClient error: %v", tc.username, err)
		}

		stored, err := client.GetStoredCredentialsWithError(KeyFactors{Salt: "salt", Iters: 4096})
		if err != nil {
			t.Fatalf("username %q: GetStoredCredentialsWithError error: %v", tc.username, err)
		}

		server, err := SHA1.NewServer(func(s string) (StoredCredentials, error) {
			if s == tc.username {
				return stored, nil
			}
			return StoredCredentials{}, fmt.Errorf("Unknown user %q", s)
		})
		if err != nil {
			t.Fatalf("username %q: NewServer error: %v", tc.username, err)
		}

		sc := server.NewConversation()
		cc := client.NewConversation()

		c1, err := cc.Step("")
		if err != nil {
			t.Fatalf("username %q: client first step error: %v", tc.username, err)
		}
		s1, err := sc.Step(c1)
		if err != nil {
			t.Errorf("username %q: server rejected client-first (%s): %v", tc.username, s1, err)
			continue
		}
		c2, err := cc.Step(s1)
		if err != nil {
			t.Errorf("username %q: client rejected server-first: %v", tc.username, err)
			continue
		}
		s2, err := sc.Step(c2)
		if err != nil {
			t.Errorf("username %q: server rejected client-final (%s): %v", tc.username, s2, err)
			continue
		}
		if _, err := cc.Step(s2); err != nil {
			t.Errorf("username %q: client rejected server-final: %v", tc.username, err)
			continue
		}
		if !sc.Valid() || !cc.Valid() {
			t.Errorf("username %q: expected valid conversation, got server=%v client=%v", tc.username, sc.Valid(), cc.Valid())
		}
		if sc.Username() != tc.username {
			t.Errorf("Username() = %q, want %q", sc.Username(), tc.username)
		}
		if sc.AuthzID() != tc.authzID {
			t.Errorf("AuthzID() = %q, want %q", sc.AuthzID(), tc.authzID)
		}
	}
}
