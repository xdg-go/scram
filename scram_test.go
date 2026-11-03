// Copyright 2026 by David A. Golden. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

package scram

import (
	"strings"
	"testing"
)

func TestNewClientSASLprepErrorOmitsPassword(t *testing.T) {
	cases := []struct {
		name     string
		password string
		leaks    []string
	}{
		{name: "control char", password: "hunter2\u0007secret", leaks: []string{"hunter2", "secret", "\\u0007"}},
		{name: "emoji", password: "horse\U0001F434", leaks: []string{"horse", "\\u1f434"}},
		{name: "mixed bidi", password: "שלוםabc", leaks: []string{"abc", "\\u0061"}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := SHA256.NewClient("user", c.password, "")
			if err == nil {
				t.Fatal("expected SASLprep error")
			}
			msg := err.Error()
			if !strings.HasPrefix(msg, "Error SASLprepping password: ") {
				t.Errorf("unexpected error format: %q", msg)
			}
			for _, s := range c.leaks {
				if strings.Contains(msg, s) {
					t.Errorf("error leaks %q: %q", s, msg)
				}
			}
		})
	}
}
