package security

import (
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func overlappingBranchesDB() *AdvisoryDB {
	return &AdvisoryDB{Advisories: []Advisory{{
		Title:     "XSS",
		Link:      "https://example.com/xss",
		CVE:       "CVE-2024-0001",
		Reference: "composer://acme/foo",
		Branches: map[string]*Branch{
			"1.x": {Versions: []string{">=1.0.0", "<2.0.0"}},
			"2.x": {Versions: []string{">=1.0.0", "<1.5.0"}},
		},
	}}}
}

func TestAnalyzeDeduplicatesAdvisories(t *testing.T) {
	lock := &Lock{Packages: []Package{{Name: "acme/foo", Version: Version("1.2.0")}}}

	vulns := Analyze(lock, overlappingBranchesDB(), false)

	assert.Equal(t, 1, vulns.CountVulnerablePackages())
	assert.Equal(t, 1, vulns.Count())
	v := vulns.Get("acme/foo")
	require.NotNil(t, v)
	assert.Len(t, v.Advisories, 1)
}

func TestNormalizeDedupesAndSorts(t *testing.T) {
	vulns := Vulnerabilities{
		"acme/foo": {
			Version: "1.2.0",
			Advisories: []SimpleAdvisory{
				{Title: "Second", Link: "https://e/2", CVE: "CVE-2024-0002"},
				{Title: "First", Link: "https://e/1", CVE: "CVE-2024-0001"},
				{Title: "First", Link: "https://e/1", CVE: "CVE-2024-0001"},
				{Title: "No CVE", Link: "https://e/none", CVE: ""},
			},
		},
	}

	normalized := Normalize(&vulns)

	assert.Equal(t, 3, normalized.Count())
	got := normalized.Get("acme/foo").Advisories
	assert.Equal(t, []SimpleAdvisory{
		{Title: "No CVE", Link: "https://e/none", CVE: ""},
		{Title: "First", Link: "https://e/1", CVE: "CVE-2024-0001"},
		{Title: "Second", Link: "https://e/2", CVE: "CVE-2024-0002"},
	}, got)
	assert.Equal(t, normalized, Normalize(normalized))
}

func TestNormalizeNil(t *testing.T) {
	assert.Equal(t, 0, Normalize(nil).Count())
}

type junitSuites struct {
	XMLName    xml.Name `xml:"testsuites"`
	Name       string   `xml:"name,attr"`
	Testsuites []struct {
		Errors    int `xml:"errors,attr"`
		Failures  int `xml:"failures,attr"`
		Tests     int `xml:"tests,attr"`
		Testcases []struct {
			Name    string   `xml:"name,attr"`
			Failure []string `xml:"failure"`
		} `xml:"testcase"`
	} `xml:"testsuite"`
}

func parseJunit(t *testing.T, output []byte) junitSuites {
	t.Helper()
	var suites junitSuites
	require.NoError(t, xml.Unmarshal(output, &suites))
	return suites
}

func TestAllFormatsShareTheSameNormalizedResult(t *testing.T) {
	lock := &Lock{Packages: []Package{
		{Name: "acme/foo", Version: Version("1.2.0")},
		{Name: "acme/bar", Version: Version("2.0.0")},
	}}
	db := &AdvisoryDB{Advisories: []Advisory{
		{
			Title: "XSS", Link: "https://example.com/xss", CVE: "CVE-2024-0001",
			Reference: "composer://acme/foo",
			Branches: map[string]*Branch{
				"1.x": {Versions: []string{">=1.0.0", "<2.0.0"}},
				"2.x": {Versions: []string{">=1.0.0", "<1.5.0"}},
			},
		},
		{
			Title: "RCE", Link: "https://example.com/rce", CVE: "CVE-2024-0002",
			Reference: "composer://acme/bar",
			Branches: map[string]*Branch{
				"2.x": {Versions: []string{">=2.0.0", "<3.0.0"}},
			},
		},
	}}

	vulns := Analyze(lock, db, false)

	jsonOutput, err := Format(vulns, "json")
	require.NoError(t, err)
	var decoded map[string]Vulnerability
	require.NoError(t, json.Unmarshal(jsonOutput, &decoded))
	jsonAdvisories := 0
	for _, v := range decoded {
		jsonAdvisories += len(v.Advisories)
	}

	junitOutput, err := Format(vulns, "junit")
	require.NoError(t, err)
	suites := parseJunit(t, junitOutput)
	require.Len(t, suites.Testsuites, 1)
	suite := suites.Testsuites[0]

	assert.Equal(t, 2, vulns.CountVulnerablePackages())
	assert.Equal(t, 2, vulns.Count())
	assert.Equal(t, vulns.Count(), jsonAdvisories)
	assert.Equal(t, vulns.Count(), suite.Tests)
	assert.Equal(t, vulns.Count(), suite.Failures)
	assert.Len(t, suite.Testcases, vulns.Count())

	yamlOutput, err := Format(vulns, "yaml")
	require.NoError(t, err)
	assert.Contains(t, string(yamlOutput), "CVE-2024-0001")
	assert.Contains(t, string(yamlOutput), "CVE-2024-0002")
}

func TestJunitNoVulnerabilities(t *testing.T) {
	output, err := ToJunit(&Vulnerabilities{})
	require.NoError(t, err)

	suites := parseJunit(t, output)
	require.Len(t, suites.Testsuites, 1)
	assert.Equal(t, 0, suites.Testsuites[0].Tests)
	assert.Equal(t, 0, suites.Testsuites[0].Failures)
	assert.Empty(t, suites.Testsuites[0].Testcases)
}

func TestUnknownLockFieldsAreForwardCompatible(t *testing.T) {
	contents := `{
		"plugin-api-version": "2.6.0",
		"content-hash": "abc123",
		"future-section": {"nested": true},
		"packages": [
			{"name": "acme/foo", "version": "1.2.0", "unknown-package-field": "value"}
		],
		"packages-dev": []
	}`

	lock, err := NewLock(strings.NewReader(contents))
	require.NoError(t, err)
	require.Len(t, lock.Packages, 1)
	assert.Equal(t, "acme/foo", lock.Packages[0].Name)
}

func TestUnknownAdvisoryFieldsAreForwardCompatible(t *testing.T) {
	contents := `
title: XSS
link: https://example.com/xss
cve: CVE-2024-0001
reference: composer://acme/foo
severity: high
new_future_field:
  foo: bar
branches:
  1.x:
    versions: [">=1.0.0", "<2.0.0"]
    time: "2020-01-01 00:00:00"
`
	var advisory Advisory
	require.NoError(t, yaml.Unmarshal([]byte(contents), &advisory))
	assert.Equal(t, "CVE-2024-0001", advisory.CVE)
	require.Contains(t, advisory.Branches, "1.x")

	lock := &Lock{Packages: []Package{{Name: "acme/foo", Version: Version("1.2.0")}}}
	vulns := Analyze(lock, &AdvisoryDB{Advisories: []Advisory{advisory}}, false)
	assert.Equal(t, 1, vulns.Count())
}

func TestUnknownResultFieldsAreForwardCompatible(t *testing.T) {
	contents := `{
		"acme/foo": {
			"version": "1.2.0",
			"future-severity": "critical",
			"advisories": [
				{"title": "XSS", "link": "https://e/x", "cve": "CVE-2024-0001", "future-field": 42}
			]
		}
	}`

	var vulns Vulnerabilities
	require.NoError(t, json.Unmarshal([]byte(contents), &vulns))
	require.Len(t, vulns, 1)
	assert.Equal(t, 1, vulns.Count())

	output, err := ToJSON(&vulns, true)
	require.NoError(t, err)
	assert.Contains(t, string(output), "CVE-2024-0001")
	assert.Contains(t, string(output), "1.2.0")
}
