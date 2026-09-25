package localuser

import "testing"

func TestNormalizeUsername(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"dan", "dan", true},
		{"Dan.Evans", "dan.evans", true},
		{"  testuser ", "testuser", true},
		{"a_b-c.1", "a_b-c.1", true},
		{"", "", false},
		{"dan evans", "", false},
		{"dan@rostor.org", "", false},
		{"abcdefghijklmnopqrstu", "", false}, // 21 chars
		{"abcdefghijklmnopqrst", "abcdefghijklmnopqrst", true},
		{"..", "", false},
		{"dän", "", false},
		{"dan\x00", "", false},
	}
	for _, c := range cases {
		got, ok := NormalizeUsername(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("NormalizeUsername(%q) = %q,%v want %q,%v", c.in, got, ok, c.want, c.ok)
		}
	}
}
