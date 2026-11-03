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

func TestDecodeName(t *testing.T) {
	valid := []struct {
		input  string
		expect string
	}{
		{input: "", expect: ""},
		{input: "arthur", expect: "arthur"},
		{input: "doe=2Cjane", expect: "doe,jane"},
		{input: "a=2Cb=3Dc=2Cd=3D", expect: "a,b=c,d="},
		{input: "=3D=3D", expect: "=="},
		{input: "x=3D2C", expect: "x=2C"},
	}
	for _, c := range valid {
		got, ok := decodeName(c.input)
		if !ok {
			t.Errorf("decodeName(%q): unexpected failure", c.input)
			continue
		}
		if got != c.expect {
			t.Errorf("decodeName(%q) = %q, want %q", c.input, got, c.expect)
		}
	}

	for _, input := range []string{"=", "=3", "=2", "a=", "a=b", "=2c", "=3d", "=41", "==3D", "=3D=", "a=3D=2"} {
		if got, ok := decodeName(input); ok {
			t.Errorf("decodeName(%q) = %q, want failure", input, got)
		}
	}
}

func TestDecodeNameNoEscapeDoesNotAllocate(t *testing.T) {
	allocs := testing.AllocsPerRun(100, func() {
		if _, ok := decodeName("arthur"); !ok {
			t.Fatal("decodeName(\"arthur\") failed")
		}
	})
	if allocs != 0 {
		t.Errorf("decodeName allocated %v times for a name without escapes", allocs)
	}
}

// encodeName and decodeName must be exact inverses: every string round-trips,
// and every wire string that decodes successfully re-encodes to itself. Wire
// strings with a bare ',' are skipped: the parser splits fields on commas,
// so decodeName never sees one.
func FuzzNameEncoding(f *testing.F) {
	for _, s := range []string{"", "arthur", "a,b=c", "=3D2C", "=2c", "a=", "=", "日本,=語"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		decoded, ok := decodeName(encodeName(s))
		if !ok || decoded != s {
			t.Errorf("decodeName(encodeName(%q)) = %q, %v", s, decoded, ok)
		}

		if strings.Contains(s, ",") {
			return
		}
		if decoded, ok := decodeName(s); ok {
			if reencoded := encodeName(decoded); reencoded != s {
				t.Errorf("encodeName(decodeName(%q)) = %q", s, reencoded)
			}
		}
	})
}
