package rules

import "testing"

func TestParseClassName(t *testing.T) {
	cases := []struct {
		in   string
		want ClassName
	}{
		{"A", ClassA}, {"a", ClassA},
		{"B", ClassB}, {"C", ClassC}, {"D", ClassD},
	}
	for _, c := range cases {
		got, err := ParseClassName(c.in)
		if err != nil {
			t.Errorf("ParseClassName(%q) error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseClassName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if _, err := ParseClassName("E"); err == nil {
		t.Error(`ParseClassName("E") succeeded, want error`)
	}
}

func TestParseCertificationType(t *testing.T) {
	cases := []struct {
		in   string
		want CertificationType
	}{
		{"20x", Certification20x}, {"20X", Certification20x},
		{"rev5", CertificationRev5}, {"Rev5", CertificationRev5}, {"REV5", CertificationRev5},
	}
	for _, c := range cases {
		got, err := ParseCertificationType(c.in)
		if err != nil {
			t.Errorf("ParseCertificationType(%q) error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseCertificationType(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if _, err := ParseCertificationType("30y"); err == nil {
		t.Error(`ParseCertificationType("30y") succeeded, want error`)
	}
}

func TestParseCertificationPath(t *testing.T) {
	cases := []struct {
		in   string
		want CertificationPath
	}{
		{"Program", PathProgram}, {"program", PathProgram},
		{"Agency", PathAgency}, {"AGENCY", PathAgency},
	}
	for _, c := range cases {
		got, err := ParseCertificationPath(c.in)
		if err != nil {
			t.Errorf("ParseCertificationPath(%q) error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseCertificationPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if _, err := ParseCertificationPath("Nowhere"); err == nil {
		t.Error(`ParseCertificationPath("Nowhere") succeeded, want error`)
	}
}

func TestClassNameIsValid(t *testing.T) {
	for _, c := range []ClassName{"", ClassA, ClassB, ClassC, ClassD} {
		if !c.IsValid() {
			t.Errorf("ClassName(%q).IsValid() = false, want true", c)
		}
	}
	for _, c := range []ClassName{"a", "E", "class-a"} {
		if c.IsValid() {
			t.Errorf("ClassName(%q).IsValid() = true, want false", c)
		}
	}
}

func TestCertificationTypeIsValid(t *testing.T) {
	for _, c := range []CertificationType{"", Certification20x, CertificationRev5} {
		if !c.IsValid() {
			t.Errorf("CertificationType(%q).IsValid() = false, want true", c)
		}
	}
	for _, c := range []CertificationType{"rev5", "20X", "Rev6"} {
		if c.IsValid() {
			t.Errorf("CertificationType(%q).IsValid() = true, want false", c)
		}
	}
}

func TestCertificationPathIsValid(t *testing.T) {
	for _, p := range []CertificationPath{"", PathProgram, PathAgency} {
		if !p.IsValid() {
			t.Errorf("CertificationPath(%q).IsValid() = false, want true", p)
		}
	}
	for _, p := range []CertificationPath{"program", "AGENCY", "Nowhere"} {
		if p.IsValid() {
			t.Errorf("CertificationPath(%q).IsValid() = true, want false", p)
		}
	}
}
