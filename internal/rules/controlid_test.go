package rules

import "testing"

func TestParseCTLKey(t *testing.T) {
	cases := []struct {
		in   string
		want ControlID
	}{
		{"AC-06-01", ControlID{Family: "AC", Base: 6, Enhancement: 1}},
		{"AC-20", ControlID{Family: "AC", Base: 20, Enhancement: 0}},
		{"SR-11", ControlID{Family: "SR", Base: 11, Enhancement: 0}},
	}
	for _, c := range cases {
		got, err := ParseCTLKey(c.in)
		if err != nil {
			t.Errorf("ParseCTLKey(%q) error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseCTLKey(%q) = %+v, want %+v", c.in, got, c.want)
		}
	}
}

func TestParseCTLKeyRejectsOtherForms(t *testing.T) {
	for _, in := range []string{"ac-6.1", "AC-6(1)", "AC-06 (01)", "AC-6", "not-a-control"} {
		if _, err := ParseCTLKey(in); err == nil {
			t.Errorf("ParseCTLKey(%q) succeeded, want error", in)
		}
	}
}

func TestParseOSCAL(t *testing.T) {
	cases := []struct {
		in   string
		want ControlID
	}{
		{"ac-6.1", ControlID{Family: "AC", Base: 6, Enhancement: 1}},
		{"cp-3", ControlID{Family: "CP", Base: 3, Enhancement: 0}},
		{"sr-11.1", ControlID{Family: "SR", Base: 11, Enhancement: 1}},
		{"at-3.5", ControlID{Family: "AT", Base: 3, Enhancement: 5}},
	}
	for _, c := range cases {
		got, err := ParseOSCAL(c.in)
		if err != nil {
			t.Errorf("ParseOSCAL(%q) error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseOSCAL(%q) = %+v, want %+v", c.in, got, c.want)
		}
	}
}

func TestParseOSCALRejectsOtherForms(t *testing.T) {
	for _, in := range []string{"AC-06-01", "AC-6(1)", "AC-06 (01)", "AC-6.1", "6-6"} {
		if _, err := ParseOSCAL(in); err == nil {
			t.Errorf("ParseOSCAL(%q) succeeded, want error", in)
		}
	}
}

func TestParseFedRAMPProse(t *testing.T) {
	cases := []struct {
		in   string
		want ControlID
	}{
		{"AC-6(1)", ControlID{Family: "AC", Base: 6, Enhancement: 1}},
		{"AC-06 (01)", ControlID{Family: "AC", Base: 6, Enhancement: 1}},
		{"AT-02 (02)", ControlID{Family: "AT", Base: 2, Enhancement: 2}},
		{"AC-20", ControlID{Family: "AC", Base: 20, Enhancement: 0}},
	}
	for _, c := range cases {
		got, err := ParseFedRAMPProse(c.in)
		if err != nil {
			t.Errorf("ParseFedRAMPProse(%q) error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseFedRAMPProse(%q) = %+v, want %+v", c.in, got, c.want)
		}
	}
}

func TestParseControlIDAutoDetects(t *testing.T) {
	want := ControlID{Family: "AC", Base: 6, Enhancement: 1}
	for _, in := range []string{"AC-06-01", "ac-6.1", "AC-6(1)", "AC-06 (01)"} {
		got, err := ParseControlID(in)
		if err != nil {
			t.Errorf("ParseControlID(%q) error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseControlID(%q) = %+v, want %+v", in, got, want)
		}
	}
}

func TestParseControlIDRejectsGarbage(t *testing.T) {
	for _, in := range []string{"", "not-a-control", "ACME-1", "AC"} {
		if _, err := ParseControlID(in); err == nil {
			t.Errorf("ParseControlID(%q) succeeded, want error", in)
		}
	}
}

func TestControlIDFormatters(t *testing.T) {
	withEnh := ControlID{Family: "AC", Base: 6, Enhancement: 1}
	if got, want := withEnh.CTLKey(), "AC-06-01"; got != want {
		t.Errorf("CTLKey() = %q, want %q", got, want)
	}
	if got, want := withEnh.OSCAL(), "ac-6.1"; got != want {
		t.Errorf("OSCAL() = %q, want %q", got, want)
	}
	if got, want := withEnh.FedRAMPProse(), "AC-06 (01)"; got != want {
		t.Errorf("FedRAMPProse() = %q, want %q", got, want)
	}
	if got, want := withEnh.String(), "ac-6.1"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}

	base := ControlID{Family: "SR", Base: 11}
	if got, want := base.CTLKey(), "SR-11"; got != want {
		t.Errorf("CTLKey() = %q, want %q", got, want)
	}
	if got, want := base.OSCAL(), "sr-11"; got != want {
		t.Errorf("OSCAL() = %q, want %q", got, want)
	}
	if got, want := base.FedRAMPProse(), "SR-11"; got != want {
		t.Errorf("FedRAMPProse() = %q, want %q", got, want)
	}
	if base.HasEnhancement() {
		t.Errorf("HasEnhancement() = true for base control, want false")
	}
	if !withEnh.HasEnhancement() {
		t.Errorf("HasEnhancement() = false for enhancement, want true")
	}
}

func TestControlIDRoundTripsAcrossAllForms(t *testing.T) {
	id := ControlID{Family: "IA", Base: 5, Enhancement: 1}
	forms := []string{id.CTLKey(), id.OSCAL(), id.FedRAMPProse()}
	for _, s := range forms {
		got, err := ParseControlID(s)
		if err != nil {
			t.Errorf("ParseControlID(%q) error: %v", s, err)
			continue
		}
		if got != id {
			t.Errorf("round trip through %q = %+v, want %+v", s, got, id)
		}
	}
}

func TestControlIDTextMarshaling(t *testing.T) {
	id := ControlID{Family: "AC", Base: 6, Enhancement: 1}
	text, err := id.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText() error: %v", err)
	}
	if got, want := string(text), "ac-6.1"; got != want {
		t.Fatalf("MarshalText() = %q, want %q", got, want)
	}

	var got ControlID
	if err := got.UnmarshalText([]byte("AC-06-01")); err != nil {
		t.Fatalf("UnmarshalText() error: %v", err)
	}
	if got != id {
		t.Fatalf("UnmarshalText() = %+v, want %+v", got, id)
	}
}

func TestParseControlIDs(t *testing.T) {
	got, err := ParseControlIDs([]string{"cp-3", "ir-2", "at-2.2"})
	if err != nil {
		t.Fatalf("ParseControlIDs() error: %v", err)
	}
	want := []ControlID{
		{Family: "CP", Base: 3},
		{Family: "IR", Base: 2},
		{Family: "AT", Base: 2, Enhancement: 2},
	}
	if len(got) != len(want) {
		t.Fatalf("ParseControlIDs() = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("ParseControlIDs()[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestParseControlIDsFailsLoudlyOnBadEntry(t *testing.T) {
	if _, err := ParseControlIDs([]string{"cp-3", "not-a-control"}); err == nil {
		t.Fatal("ParseControlIDs() succeeded on an invalid entry, want error")
	}
}
