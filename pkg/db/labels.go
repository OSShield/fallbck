package db

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Labels are key=value pairs on agents, targets, jobs, tenants, key rings and
// enrollment tokens. Access bindings select objects by them.
type Labels map[string]string

// MaxLabels caps the entries on one object or selector
const MaxLabels = 20

var (
	labelNameRe   = regexp.MustCompile(`^([A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?)?$`)
	labelPrefixRe = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)
)

// ValidateLabels applies the Kubernetes label syntax: key is [prefix/]name with a DNS
// subdomain prefix (at most 253 characters) and a name of at most 63 characters;
// the value is empty or a name. At most MaxLabels entries.
func ValidateLabels(l Labels) error {
	if len(l) > MaxLabels {
		return fmt.Errorf("at most %d labels", MaxLabels)
	}
	for k, v := range l {
		name := k
		if prefix, rest, ok := strings.Cut(k, "/"); ok {
			if prefix == "" || len(prefix) > 253 || !labelPrefixRe.MatchString(prefix) {
				return fmt.Errorf("label key %q: the prefix must be a DNS subdomain", k)
			}
			name = rest
		}
		if name == "" || len(name) > 63 || !labelNameRe.MatchString(name) {
			return fmt.Errorf("label key %q: up to 63 letters, digits, '-', '_' or '.', starting and ending with a letter or digit", k)
		}
		if len(v) > 63 || !labelNameRe.MatchString(v) {
			return fmt.Errorf("label %s: value %q must be up to 63 letters, digits, '-', '_' or '.', starting and ending with a letter or digit", k, v)
		}
	}
	return nil
}

// Contains reports whether every entry of sel is present in l (equality, AND)
func (l Labels) Contains(sel Labels) bool {
	for k, v := range sel {
		if got, ok := l[k]; !ok || got != v {
			return false
		}
	}
	return true
}

// Equal reports whether both hold the same entries (nil equals empty)
func (l Labels) Equal(o Labels) bool {
	return len(l) == len(o) && l.Contains(o)
}

// OrEmpty returns a non-nil map (the columns are NOT NULL)
func (l Labels) OrEmpty() Labels {
	if l == nil {
		return Labels{}
	}
	return l
}

// JSON is the jsonb text of the labels; pgx sends a string parameter to a jsonb
// column as raw JSON
func (l Labels) JSON() string {
	b, _ := json.Marshal(l.OrEmpty())
	return string(b)
}

// String renders key=value pairs sorted by key, comma separated
func (l Labels) String() string {
	keys := make([]string, 0, len(l))
	for k := range l {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + "=" + l[k]
	}
	return strings.Join(parts, ",")
}

// Scope is the set of objects one permission reaches for a principal: everything
// (All), nothing (zero value), or the objects matched by any of the selectors. It is
// the only input to both forms of the access decision: Matches for an object in hand
// and SQL for queries, so the two cannot drift apart.
type Scope struct {
	All       bool
	Selectors []Selector
}

// Unscoped reaches every row. Only for internal callers (workflows, agent endpoints,
// the PBS tunnel); admin requests take their scope from the principal.
var Unscoped = Scope{All: true}

// Matches reports whether an object with these labels is in scope
func (s Scope) Matches(l Labels) bool {
	if s.All {
		return true
	}
	for _, sel := range s.Selectors {
		if sel.Matches(l) {
			return true
		}
	}
	return false
}

// Empty reports whether the scope reaches nothing
func (s Scope) Empty() bool { return !s.All && len(s.Selectors) == 0 }

// SQL renders the scope as a WHERE fragment on a jsonb labels column, appending its
// parameters to args: TRUE, FALSE, or (selector OR selector ...)
func (s Scope) SQL(col string, args []any) (string, []any) {
	if s.All {
		return "TRUE", args
	}
	if len(s.Selectors) == 0 {
		return "FALSE", args
	}
	parts := make([]string, len(s.Selectors))
	for i, sel := range s.Selectors {
		parts[i], args = sel.sql(col, args)
	}
	return "(" + strings.Join(parts, " OR ") + ")", args
}
