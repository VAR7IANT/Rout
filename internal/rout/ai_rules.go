package rout

import (
	"regexp"
	"sort"
	"strings"
)

// AIRuleSetCurrent is the newest built-in AI rule set. A saved configuration records the
// version it was applied with (rule_set_version), so a later release can ship version 2
// without silently changing what an already-applied configuration routes.
const AIRuleSetCurrent = 1

// aiService is one AI product and the destination domains that identify it.
//
// Every entry is matched as a sing-box domain_suffix: "example.com" matches example.com and
// every subdomain. Entries are deliberately specific. Whole-company domains (google.com,
// github.com, microsoft.com, googleapis.com) are NEVER listed, because they would send
// unrelated traffic to the AI exit; only hosts that exist for the AI product are.
type aiService struct {
	Name     string
	Suffixes []string
}

var aiRuleSets = map[int][]aiService{
	1: {
		{"OpenAI / ChatGPT", []string{"openai.com", "chatgpt.com", "chat.com", "oaistatic.com", "oaiusercontent.com"}},
		{"Claude / Anthropic", []string{"anthropic.com", "claude.ai", "claude.com", "claudeusercontent.com"}},
		{"Gemini", []string{
			"gemini.google.com", "bard.google.com", "generativelanguage.googleapis.com",
			"alkalimakersuite-pa.clients6.google.com", "proactivebackend-pa.googleapis.com",
		}},
		{"Google AI Studio", []string{"aistudio.google.com", "makersuite.google.com", "ai.google.dev"}},
		{"Hugging Face", []string{"huggingface.co", "hf.co", "hf.space"}},
		{"GitHub Copilot", []string{
			"githubcopilot.com", "copilot-proxy.githubusercontent.com", "copilot-telemetry.githubusercontent.com",
		}},
		{"Cursor", []string{"cursor.com", "cursor.sh", "cursorapi.com"}},
	},
}

// aiServices returns the rule set for a version; an unknown or zero version uses the
// current one.
func aiServices(version int) []aiService {
	if s, ok := aiRuleSets[version]; ok {
		return s
	}
	return aiRuleSets[AIRuleSetCurrent]
}

// AIServices exposes a rule set for display and documentation.
func AIServices(version int) []aiService { return aiServices(version) }

// aiSuffixes is the flat, sorted, de-duplicated suffix list of one rule set.
func aiSuffixes(version int) []string {
	seen := map[string]bool{}
	var out []string
	for _, svc := range aiServices(version) {
		for _, s := range svc.Suffixes {
			s = strings.ToLower(strings.TrimSpace(s))
			if s != "" && !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	sort.Strings(out)
	return out
}

// sing-box's suffix matcher does not normalize all domain spellings received via
// proxy protocols. DNS names are case-insensitive and may end in a root dot.
// Keep the fast suffix match and supplement it with this anchored RE2 expression.
func aiDomainPattern(version int) string {
	suffixes := aiSuffixes(version)
	for i := range suffixes {
		suffixes[i] = regexp.QuoteMeta(suffixes[i])
	}
	return `(?i)(^|\.)(?:` + strings.Join(suffixes, "|") + `)\.?$`
}

// matchAIDomain reports whether host is one of the rule set's destinations, with the same
// semantics as sing-box domain_suffix: the suffix itself or any subdomain of it.
func matchAIDomain(version int, host string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return false
	}
	for _, s := range aiSuffixes(version) {
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}
