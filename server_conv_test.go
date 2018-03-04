package scram

import (
	"encoding/base64"
	"fmt"
	"testing"
)

//    This is a simple example of a SCRAM-SHA-1 authentication exchange
//    when the client doesn't support channel bindings (username 'user' and
//    password 'pencil' are used):
//
//    C: n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL
//    S: r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,
//       i=4096
//    C: c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,
//       p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=
//    S: v=rmF9pqV8S7suAoZWja4dJRkFsKQ=

func TestServerConversation(t *testing.T) {
	type step struct {
		in     string
		out    string
		hasErr bool
	}

	cases := []struct {
		label  string
		hgf    HashGeneratorFcn
		user   string
		pass   string
		salt64 string
		iters  int
		auth   string
		nonce  string
		steps  []step
	}{
		{
			label:  "RFC 5802 example",
			hgf:    SHA1,
			user:   "user",
			pass:   "pencil",
			salt64: "QSXCR+Q6sek8bf92",
			iters:  4096,
			nonce:  "3rfcNHYJY1ZVvWVs7j",
			steps: []step{
				{"n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL", "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096", false},
				{
					"c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=",
					"v=rmF9pqV8S7suAoZWja4dJRkFsKQ=",
					false,
				},
			},
		},
		{
			label:  "RFC 5802 example with bad proof",
			hgf:    SHA1,
			user:   "user",
			pass:   "pencil",
			salt64: "QSXCR+Q6sek8bf92",
			iters:  4096,
			nonce:  "3rfcNHYJY1ZVvWVs7j",
			steps: []step{
				{"n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL", "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096", false},
				{
					"c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=AAAAAAAAAAAAAAAAAAAAAAAAAAA=",
					"e=invalid-proof",
					true,
				},
			},
		},
		{
			label:  "RFC 7677 example",
			hgf:    SHA256,
			user:   "user",
			pass:   "pencil",
			salt64: "W22ZaJ0SNY7soEsUEjb6gQ==",
			iters:  4096,
			nonce:  "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0",
			steps: []step{
				{
					"n,,n=user,r=rOprNGfwEbeRWgbNEkqO",
					"r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
					false,
				},
				{
					"c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=",
					"v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=",
					false,
				},
			},
		},
		{
			label:  "RFC 7677 example with bad proof",
			hgf:    SHA256,
			user:   "user",
			pass:   "pencil",
			salt64: "W22ZaJ0SNY7soEsUEjb6gQ==",
			iters:  4096,
			nonce:  "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0",
			steps: []step{
				{
					"n,,n=user,r=rOprNGfwEbeRWgbNEkqO",
					"r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
					false,
				},
				{
					"c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
					"e=invalid-proof",
					true,
				},
			},
		},
	}

	for _, c := range cases {
		// Prep user credentials for the case from Client
		salt, err := base64.StdEncoding.DecodeString(c.salt64)
		if err != nil {
			t.Fatalf("error decoding salt: '%s'", c.salt64)
		}

		kf := KeyFactors{Salt: string(salt), Iters: c.iters}
		client, _ := c.hgf.NewClient(c.user, c.pass, "")
		stored := client.GetStoredCredentials(kf)

		cbFcn := func(s string) (StoredCredentials, error) {
			if s == c.user {
				return stored, nil
			}
			return StoredCredentials{}, fmt.Errorf("Unknown user %s", s)
		}

		// TODO check error response from NewServer
		server, _ := c.hgf.NewServer(cbFcn)
		if c.nonce != "" {
			server = server.WithNonceGenerator(func() string { return c.nonce })
		}
		conv := server.NewConversation()

		for i, s := range c.steps {
			if conv.Done() {
				t.Errorf("%s: Premature end of conversation before step %d", c.label, i+1)
			}
			got, err := conv.Step(s.in)
			if s.hasErr && err == nil {
				t.Errorf("%s: step %d: expected error but didn't get one", c.label, i+1)
			} else if !s.hasErr && err != nil {
				t.Errorf("%s: step %d: expected no error but got '%v'", c.label, i+1, err)
			}
			if got != s.out {
				t.Errorf("%s: step %d: incorrect step message; got '%s', expected '%s'", c.label, i+1, got, s.out)
			}
		}

		if !conv.Done() {
			t.Errorf("%s: Conversation not marked done after last step", c.label)
		}

		if conv.Username() != c.user {
			t.Errorf("%s: Conversation didn't record proper username: got '%s', expected '%s'", c.label, conv.username, c.user)
		}
	}
}
