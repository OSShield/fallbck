package db

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
)

// Selector picks objects by their labels, Kubernetes style. Every requirement must
// hold (AND); an empty selector matches everything. Written and stored as a string:
//
//	team=web, env in (prod, stage), env!=dev, tier notin (frontend), managed, !legacy
type Selector []Requirement

// Selector operators
const (
	OpIn        = "in"     // key=v, key==v, key in (v1, v2)
	OpNotIn     = "notin"  // key!=v, key notin (v1, v2): also matches when key is absent
	OpExists    = "exists" // key
	OpNotExists = "!"      // !key
)

// Requirement is one clause of a selector
type Requirement struct {
	Key    string   `json:"key"`
	Op     string   `json:"op"`
	Values []string `json:"values,omitempty"`
}

// Matches reports whether labels satisfy the requirement
func (r Requirement) Matches(l Labels) bool {
	v, ok := l[r.Key]
	switch r.Op {
	case OpIn:
		return ok && slices.Contains(r.Values, v)
	case OpNotIn:
		return !ok || !slices.Contains(r.Values, v)
	case OpExists:
		return ok
	case OpNotExists:
		return !ok
	}
	return false
}

func (r Requirement) String() string {
	switch r.Op {
	case OpIn:
		if len(r.Values) == 1 {
			return r.Key + "=" + r.Values[0]
		}
		return r.Key + " in (" + strings.Join(r.Values, ", ") + ")"
	case OpNotIn:
		if len(r.Values) == 1 {
			return r.Key + "!=" + r.Values[0]
		}
		return r.Key + " notin (" + strings.Join(r.Values, ", ") + ")"
	case OpExists:
		return r.Key
	case OpNotExists:
		return "!" + r.Key
	}
	return ""
}

// Matches reports whether labels satisfy every requirement
func (s Selector) Matches(l Labels) bool {
	for _, r := range s {
		if !r.Matches(l) {
			return false
		}
	}
	return true
}

// String is the canonical form: requirements sorted, values sorted and unique. Two
// selectors with the same meaning in the same clauses print the same, which is what
// the database's uniqueness and empty checks compare.
func (s Selector) String() string {
	parts := make([]string, len(s))
	for i, r := range s {
		parts[i] = r.String()
	}
	return strings.Join(parts, ", ")
}

// Equal compares canonical forms
func (s Selector) Equal(o Selector) bool { return s.String() == o.String() }

// SelectorFromLabels is the equality selector for a label set (key=value for each)
func SelectorFromLabels(l Labels) Selector {
	s := Selector{}
	for k, v := range l {
		s = append(s, Requirement{Key: k, Op: OpIn, Values: []string{v}})
	}
	return s.normalize()
}

func (s Selector) normalize() Selector {
	for i := range s {
		vals := slices.Clone(s[i].Values)
		sort.Strings(vals)
		s[i].Values = slices.Compact(vals)
	}
	sort.Slice(s, func(i, j int) bool {
		if s[i].Key != s[j].Key {
			return s[i].Key < s[j].Key
		}
		return s[i].String() < s[j].String()
	})
	return slices.CompactFunc(s, func(a, b Requirement) bool { return a.String() == b.String() })
}

// ParseSelector reads the string form. Keys and values follow the label syntax
// (ValidateLabels); at most MaxLabels requirements.
func ParseSelector(text string) (Selector, error) {
	s := Selector{}
	rest := strings.TrimSpace(text)
	for rest != "" {
		var clause string
		// A clause ends at the first comma outside parentheses
		depth, end := 0, len(rest)
		for i, c := range rest {
			if c == '(' {
				depth++
			} else if c == ')' {
				depth--
			} else if c == ',' && depth == 0 {
				end = i
				break
			}
		}
		clause, rest = strings.TrimSpace(rest[:end]), strings.TrimSpace(strings.TrimPrefix(rest[end:], ","))
		if clause == "" {
			return nil, errors.New("empty clause (two commas in a row?)")
		}
		r, err := parseRequirement(clause)
		if err != nil {
			return nil, err
		}
		s = append(s, r)
	}
	if len(s) > MaxLabels {
		return nil, fmt.Errorf("at most %d requirements", MaxLabels)
	}
	return s.normalize(), nil
}

func parseRequirement(c string) (Requirement, error) {
	checkKey := func(k string) error { return ValidateLabels(Labels{k: ""}) }
	checkVal := func(k, v string) error { return ValidateLabels(Labels{k: v}) }
	setOp := func(key, op, list string) (Requirement, error) {
		list = strings.TrimSpace(list)
		if !strings.HasPrefix(list, "(") || !strings.HasSuffix(list, ")") {
			return Requirement{}, fmt.Errorf("%q: %s needs a parenthesised list, e.g. %s %s (a, b)", c, op, key, op)
		}
		r := Requirement{Key: key, Op: op}
		for _, v := range strings.Split(list[1:len(list)-1], ",") {
			v = strings.TrimSpace(v)
			if err := checkVal(key, v); err != nil || v == "" {
				return Requirement{}, fmt.Errorf("%q: bad value %q", c, v)
			}
			r.Values = append(r.Values, v)
		}
		return r, checkKey(key)
	}
	if strings.HasPrefix(c, "!") && !strings.ContainsAny(c, "=()") {
		key := strings.TrimSpace(c[1:])
		return Requirement{Key: key, Op: OpNotExists}, checkKey(key)
	}
	for _, op := range []struct{ token, op string }{{"!=", OpNotIn}, {"==", OpIn}, {"=", OpIn}} {
		if k, v, ok := strings.Cut(c, op.token); ok {
			k, v = strings.TrimSpace(k), strings.TrimSpace(v)
			if err := checkVal(k, v); err != nil {
				return Requirement{}, err
			}
			return Requirement{Key: k, Op: op.op, Values: []string{v}}, nil
		}
	}
	if key, rest, ok := strings.Cut(c, " "); ok || strings.ContainsRune(c, '(') {
		if !ok { // key in(a) / key notin(a)
			i := strings.IndexRune(c, '(')
			key, rest = c[:i], c[i:]
		}
		rest = strings.TrimSpace(rest)
		for _, op := range []string{OpNotIn, OpIn} {
			if after, found := strings.CutPrefix(strings.ToLower(rest), op); found && strings.HasPrefix(strings.TrimSpace(after), "(") {
				return setOp(key, op, rest[len(op):])
			}
		}
		return Requirement{}, fmt.Errorf("%q: expected key=value, key!=value, key in (...), key notin (...), key or !key", c)
	}
	return Requirement{Key: c, Op: OpExists}, checkKey(c)
}

// MarshalJSON writes the canonical string
func (s Selector) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// UnmarshalJSON accepts the string form, or an object of key: value pairs (the
// equality-only form API clients used before set-based selectors)
func (s *Selector) UnmarshalJSON(b []byte) error {
	var text string
	if err := json.Unmarshal(b, &text); err == nil {
		parsed, err := ParseSelector(text)
		if err != nil {
			return err
		}
		*s = parsed
		return nil
	}
	var l Labels
	if err := json.Unmarshal(b, &l); err != nil {
		return errors.New(`selector must be a string such as "team=web, env in (prod, stage)" or an object of labels`)
	}
	if err := ValidateLabels(l); err != nil {
		return err
	}
	*s = SelectorFromLabels(l)
	return nil
}

// Scan reads the stored canonical string
func (s *Selector) Scan(src any) error {
	var text string
	switch v := src.(type) {
	case string:
		text = v
	case []byte:
		text = string(v)
	case nil:
	default:
		return fmt.Errorf("selector: cannot scan %T", src)
	}
	parsed, err := ParseSelector(text)
	if err != nil {
		return fmt.Errorf("stored selector %q: %w", text, err)
	}
	*s = parsed
	return nil
}

// sql renders the selector as an AND of conditions on a jsonb labels column. Keys and
// values are always parameters. Single-value equality uses @> so the GIN index helps.
// Every condition is strictly TRUE or FALSE, never NULL (a missing key makes ->> NULL),
// so the fragment stays correct if a caller ever negates or combines it.
func (s Selector) sql(col string, args []any) (string, []any) {
	if len(s) == 0 {
		return "TRUE", args
	}
	param := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}
	conds := make([]string, len(s))
	for i, r := range s {
		switch {
		case r.Op == OpIn && len(r.Values) == 1:
			conds[i] = col + " @> " + param(Labels{r.Key: r.Values[0]}.JSON()) + "::jsonb"
		case r.Op == OpIn:
			conds[i] = "COALESCE((" + col + "->>" + param(r.Key) + "::text) = ANY(" + param(r.Values) + "::text[]), FALSE)"
		case r.Op == OpNotIn:
			conds[i] = "NOT COALESCE((" + col + "->>" + param(r.Key) + "::text) = ANY(" + param(r.Values) + "::text[]), FALSE)"
		case r.Op == OpExists:
			conds[i] = "(" + col + "->>" + param(r.Key) + "::text) IS NOT NULL"
		case r.Op == OpNotExists:
			conds[i] = "(" + col + "->>" + param(r.Key) + "::text) IS NULL"
		default:
			conds[i] = "FALSE"
		}
	}
	return "(" + strings.Join(conds, " AND ") + ")", args
}

// Narrows reports whether everything s matches is also matched by wider: every
// requirement of wider is implied by some requirement of s. Sufficient, not
// necessary: an unusual combination that would be narrower can be refused, never the
// other way round.
func (s Selector) Narrows(wider Selector) bool {
	for _, w := range wider {
		if !slices.ContainsFunc(s, func(r Requirement) bool { return r.implies(w) }) {
			return false
		}
	}
	return true
}

func (r Requirement) implies(w Requirement) bool {
	if r.Key != w.Key {
		return false
	}
	subset := func(a, b []string) bool { // a ⊆ b
		for _, v := range a {
			if !slices.Contains(b, v) {
				return false
			}
		}
		return true
	}
	disjoint := func(a, b []string) bool {
		return !slices.ContainsFunc(a, func(v string) bool { return slices.Contains(b, v) })
	}
	switch w.Op {
	case OpIn:
		return r.Op == OpIn && subset(r.Values, w.Values)
	case OpNotIn:
		return (r.Op == OpIn && disjoint(r.Values, w.Values)) || (r.Op == OpNotIn && subset(w.Values, r.Values)) || r.Op == OpNotExists
	case OpExists:
		return r.Op == OpExists || (r.Op == OpIn && len(r.Values) > 0)
	case OpNotExists:
		return r.Op == OpNotExists
	}
	return false
}

// MustSelector parses a selector known to be valid (tests, constants); it panics otherwise
func MustSelector(text string) Selector {
	s, err := ParseSelector(text)
	if err != nil {
		panic(err)
	}
	return s
}
