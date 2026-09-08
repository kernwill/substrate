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
