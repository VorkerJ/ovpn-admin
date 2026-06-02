package main

import "testing"

func TestSplitEnvKV(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in            string
		wantK, wantV  string
		wantOK        bool
	}{
		{"common_name=alice", "common_name", "alice", true},
		{"key=", "key", "", true},
		{"=value", "", "value", true},
		{"no_equals_sign", "", "", false},
		{"", "", "", false},
		{"a=b=c", "a", "b=c", true},
	}
	for _, c := range cases {
		k, v, ok := splitEnvKV(c.in)
		if k != c.wantK || v != c.wantV || ok != c.wantOK {
			t.Errorf("splitEnvKV(%q) = (%q,%q,%v); want (%q,%q,%v)", c.in, k, v, ok, c.wantK, c.wantV, c.wantOK)
		}
	}
}

func TestIsUserAuthorized_RejectsBadCN(t *testing.T) {
	t.Parallel()
	oAdmin := &OvpnAdmin{}
	cases := []struct {
		cn   string
		want string // substring of reason
	}{
		{"", "missing"},
		{"  ", "missing"},
		{"../escape", "invalid"},
		{"with/slash", "invalid"},
		{"-startsdash", "invalid"},
		{"a--b", "invalid"},
	}
	for _, c := range cases {
		ok, reason := oAdmin.isUserAuthorized(c.cn)
		if ok {
			t.Errorf("isUserAuthorized(%q) = allow; want deny", c.cn)
			continue
		}
		if c.want != "" && !contains(reason, c.want) {
			t.Errorf("isUserAuthorized(%q) reason=%q; want substring %q", c.cn, reason, c.want)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
