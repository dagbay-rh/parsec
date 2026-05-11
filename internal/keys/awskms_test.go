package keys

import "testing"

func TestSanitizeAliasComponent(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"dots replaced", "parsec.example.com", "parsec_example_com"},
		{"colons replaced", "urn:example:domain", "urn_example_domain"},
		{"dots and colons", "a.b:c.d", "a_b_c_d"},
		{"no special chars", "parsec-test", "parsec-test"},
		{"empty string", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeAliasComponent(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeAliasComponent(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
