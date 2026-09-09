package ir

import "testing"

func TestControlString(t *testing.T) {
	cases := []struct {
		c    Control
		want string
	}{
		{Control{Family: "AC", Base: 6, Enhancement: 1}, "ac-6.1"},
		{Control{Family: "SR", Base: 11}, "sr-11"},
		{Control{Family: "CP", Base: 3}, "cp-3"},
	}
	for _, c := range cases {
		if got := c.c.String(); got != c.want {
			t.Errorf("Control%+v.String() = %q, want %q", c.c, got, c.want)
		}
	}
}

func TestControlHasEnhancement(t *testing.T) {
	if (Control{Family: "AC", Base: 6}).HasEnhancement() {
		t.Error("base control HasEnhancement() = true, want false")
	}
	if !(Control{Family: "AC", Base: 6, Enhancement: 1}).HasEnhancement() {
		t.Error("enhancement HasEnhancement() = false, want true")
	}
}
