package util

import (
	"bytes"
	"errors"
	"regexp"
)

// The following code is largely based on https://github.com/kevinburke/ssh_config

// Pattern is a pattern in a Host declaration. Patterns are read-only values;
// create a new one with NewPattern().
type Pattern struct {
	str   string // Its appearance in the file, not the value that gets compiled.
	regex *regexp.Regexp
	not   bool // True if this is a negated match
}

// String prints the string representation of the pattern.
func (p Pattern) String() string {
	return p.str
}

// Copied from regexp.go with * and ? removed.
var specialBytes = []byte(`\.+()|[]{}^$`)

func special(b byte) bool {
	return bytes.IndexByte(specialBytes, b) >= 0
}

// NewPattern creates a new Pattern for matching hosts. NewPattern("*") creates
// a Pattern that matches all hosts.
//
// From the manpage, a pattern consists of zero or more non-whitespace
// characters, `*' (a wildcard that matches zero or more characters), or `?' (a
// wildcard that matches exactly one character). For example, to specify a set
// of declarations for any host in the ".co.uk" set of domains, the following
// pattern could be used:
//
//	Host *.co.uk
//
// The following pattern would match any host in the 192.168.0.[0-9] network range:
//
//	Host 192.168.0.?
func NewPattern(s string) (*Pattern, error) {
	if s == "" {
		return nil, errors.New("ssh_config: empty pattern")
	}
	negated := false
	if s[0] == '!' {
		negated = true
		s = s[1:]
	}
	var buf bytes.Buffer
	buf.WriteByte('^')
	for i := 0; i < len(s); i++ {
		// A byte loop is correct because all metacharacters are ASCII.
		switch b := s[i]; b {
		case '*':
			buf.WriteString(".*")
		case '?':
			buf.WriteString(".?")
		default:
			// borrowing from QuoteMeta here.
			if special(b) {
				buf.WriteByte('\\')
			}
			buf.WriteByte(b)
		}
	}
	buf.WriteByte('$')
	r, err := regexp.Compile(buf.String())
	if err != nil {
		return nil, err
	}
	return &Pattern{str: s, regex: r, not: negated}, nil
}

// MatchPatternList returns true if the input matches any of the patterns in the
// list. Negated patterns are matched first; if a negated pattern matches, the
// function returns false immediately. If no patterns match, the function
func MatchPatternList(patterns []*Pattern, input string) bool {
	found := false
	for i := range patterns {
		if patterns[i].regex.MatchString(input) {
			if patterns[i].not {
				// Negated match. "A pattern entry may be negated by prefixing
				// it with an exclamation mark (`!'). If a negated entry is
				// matched, then the Pattern entry is ignored, regardless of
				// whether any other patterns on the line match. Negated matches
				// are therefore useful to provide exceptions for wildcard
				// matches."
				return false
			}
			found = true
		}
	}
	return found
}
