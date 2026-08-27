package db

import (
	"reflect"
	"testing"
)

func TestValidateBackupPaths(t *testing.T) {
	ok := func(in, want []string) {
		t.Helper()
		got, err := ValidateBackupPaths(in)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("ValidateBackupPaths(%v) = %v, %v; want %v", in, got, err, want)
		}
	}
	bad := func(in []string, fragment string) {
		t.Helper()
		if _, err := ValidateBackupPaths(in); err == nil || !contains(err.Error(), fragment) {
			t.Errorf("ValidateBackupPaths(%v) error = %v; want containing %q", in, err, fragment)
		}
	}
	ok([]string{"/etc"}, []string{"/etc"})
	ok([]string{"/etc/", " /var/www ", "/etc"}, []string{"/etc", "/var/www"})
	ok([]string{"/srv/a/data", "/srv/b/logs"}, []string{"/srv/a/data", "/srv/b/logs"})
	bad(nil, "at least one")
	bad([]string{" ", ""}, "at least one")
	bad([]string{"etc"}, "must be absolute")
	bad([]string{"/etc", "/opt/app/etc"}, `stored as "etc"`)
	bad([]string{"/var/www", "/var/www/html"}, "is inside")
	bad([]string{"/", "/etc"}, "is inside")
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
