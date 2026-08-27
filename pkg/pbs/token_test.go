package pbs

import "testing"

func TestNormalizeAPIToken(t *testing.T) {
	cases := map[string]string{
		"backup@pbs!fallbck:0123-4567":                    "backup@pbs!fallbck:0123-4567",
		"backup@pbs!fallbck=0123-4567":                    "backup@pbs!fallbck:0123-4567",
		"PBSAPIToken=backup@pbs!fallbck:0123-4567":        "backup@pbs!fallbck:0123-4567",
		"PBSAPIToken=backup@pbs!fallbck=0123-4567":        "backup@pbs!fallbck:0123-4567",
		"  PBSAPIToken backup@pam!ci:abc  ":               "backup@pam!ci:abc",
		"root@pam!tok:secret=with=equals":                 "root@pam!tok:secret=with=equals",
		"PBSAPIToken=user@ldap.example!t-1:uuid-like-sec": "user@ldap.example!t-1:uuid-like-sec",
	}
	for in, want := range cases {
		got, err := NormalizeAPIToken(in)
		if err != nil || got != want {
			t.Errorf("NormalizeAPIToken(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "secret", "user!tok:secret", "user@pam", "user@pam!tok", "user@pam!tok:", "user@pam!:secret", "user@pam!a=b:c"} {
		if _, err := NormalizeAPIToken(bad); err == nil {
			t.Errorf("NormalizeAPIToken(%q) should fail", bad)
		}
	}
	if h := AuthorizationHeader("backup@pbs!fallbck=abc"); h != "PBSAPIToken=backup@pbs!fallbck:abc" {
		t.Errorf("AuthorizationHeader = %q", h)
	}
	if id := TokenID("PBSAPIToken=backup@pbs!fallbck=abc"); id != "backup@pbs!fallbck" {
		t.Errorf("TokenID = %q", id)
	}
	if authID, secret, err := SplitAPIToken("a@b!c:d"); err != nil || authID != "a@b!c" || secret != "d" {
		t.Errorf("SplitAPIToken = %q %q %v", authID, secret, err)
	}
}
