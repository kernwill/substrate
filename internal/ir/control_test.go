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

func TestControlValidateAcceptsWellFormedControl(t *testing.T) {
	for _, c := range []Control{
		{Family: "AC", Base: 6},
		{Family: "AC", Base: 6, Enhancement: 1},
	} {
		if err := c.Validate(); err != nil {
			t.Errorf("Control%+v.Validate() = %v, want nil", c, err)
		}
	}
}

func TestControlValidateRejectsMissingFamily(t *testing.T) {
	if err := (Control{Base: 6}).Validate(); err == nil {
		t.Error("Validate() = nil, want error for missing family")
	}
}

func TestControlValidateRejectsNonPositiveBase(t *testing.T) {
	for _, base := range []int{0, -1} {
		if err := (Control{Family: "AC", Base: base}).Validate(); err == nil {
			t.Errorf("Validate() = nil for base %d, want error", base)
		}
	}
}

func TestControlValidateRejectsNegativeEnhancement(t *testing.T) {
	if err := (Control{Family: "AC", Base: 6, Enhancement: -1}).Validate(); err == nil {
		t.Error("Validate() = nil, want error for negative enhancement")
	}
}
