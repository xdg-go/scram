package scram

import "testing"

func TestEncodeName(t *testing.T) {
	cases := []struct {
		input  string
		expect string
	}{
		{input: "arthur", expect: "arthur"},
		{input: "doe,jane", expect: "doe=2Cjane"},
		{input: "a,b,c,d", expect: "a=2Cb=2Cc=2Cd"},
		{input: "a,b=c,d=", expect: "a=2Cb=3Dc=2Cd=3D"},
	}

	for _, c := range cases {
		if got := encodeName(c.input); got != c.expect {
			t.Errorf("Failed encoding '%s', got '%s', expected '%s'", c.input, got, c.expect)
		}
	}
}
