package scram

import "testing"

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

func TestClientConversation(t *testing.T) {
	type step struct {
		in     string
		out    string
		hasErr bool
	}

	cases := []struct {
		label string
		hgf   HashGeneratorFcn
		user  string
		pass  string
		auth  string
		nonce string
		valid bool
		steps []step
	}{
		{
			label: "RFC 5802 example",
			hgf:   SHA1,
			user:  "user",
			pass:  "pencil",
			nonce: "fyko+d2lbbFgONRv9qkxdawL",
			valid: true,
			steps: []step{
				{"", "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL", false},
				{
					"r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096",
					"c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=",
					false,
				},
				{"v=rmF9pqV8S7suAoZWja4dJRkFsKQ=", "", false},
			},
		},
		{
			label: "RFC 5802 with bad server validation",
			hgf:   SHA1,
			user:  "user",
			pass:  "pencil",
			nonce: "fyko+d2lbbFgONRv9qkxdawL",
			valid: false,
			steps: []step{
				{"", "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL", false},
				{
					"r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096",
					"c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=",
					false,
				},
				{"v=AAAAAAAAAAAAAAAAAAAAAAAAAAA=", "", true},
			},
		},
		{
			label: "RFC 7677 example",
			hgf:   SHA256,
			user:  "user",
			pass:  "pencil",
			nonce: "rOprNGfwEbeRWgbNEkqO",
			valid: true,
			steps: []step{
				{"", "n,,n=user,r=rOprNGfwEbeRWgbNEkqO", false},
				{
					"r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
					"c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=",
					false,
				},
				{"v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=", "", false},
			},
		},
		{
			label: "RFC 7677 example with bad server validation",
			hgf:   SHA256,
			user:  "user",
			pass:  "pencil",
			nonce: "rOprNGfwEbeRWgbNEkqO",
			valid: false,
			steps: []step{
				{"", "n,,n=user,r=rOprNGfwEbeRWgbNEkqO", false},
				{
					"r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
					"c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=",
					false,
				},
				{"v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "", true},
			},
		},
	}

	for _, c := range cases {
		// TODO check error response from NewClient
		client, _ := c.hgf.NewClient(c.user, c.pass, c.auth)
		if c.nonce != "" {
			client = client.WithNonceGenerator(func() string { return c.nonce })
		}
		conv := client.NewConversation()

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

		if c.valid != conv.Valid() {
			t.Errorf("%s: Conversation Valid() incorrect: got '%v', expected '%v'", c.label, conv.Valid(), c.valid)
		}

		if !conv.Done() {
			t.Errorf("%s: Conversation not marked done after last step", c.label)
		}

	}
}
