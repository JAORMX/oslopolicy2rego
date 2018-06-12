package oslopolicy2rego

import (
	"reflect"
	"strings"
	"testing"
)

// parseYamlOrJSON tests

func TestParseYamlOrJSONParsesSimpleYamlCases(t *testing.T) {
	test1yaml := `
---
a: 1
b: 2`
	test1map := map[string]string{"a": "1", "b": "2"}
	cases := []struct {
		input string
		want  map[string]string
	}{
		{test1yaml, test1map},
		{"", map[string]string{}},
	}
	for _, c := range cases {
		got, _ := parseYamlOrJSON(c.input)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("parseYamlOrJSON() with input:\n %s\n didn't match %v. Got %v", c.input, c.want, got)
		}
	}
}

func TestParseYamlOrJSONReturnsErrors(t *testing.T) {
	test1yaml := `
---
a: 1
b: 2
c`
	test2json := `
{
	"a": "1",
	"b": 2,
`
	cases := []struct {
		input string
	}{
		{test1yaml},
		{test2json},
	}
	for _, c := range cases {
		got, err := parseYamlOrJSON(c.input)
		if err == nil {
			t.Errorf("parseYamlOrJSON() should have returned an error for:\n %s\n Instead got: %v", c.input, got)
		}
	}
}

func TestParseYamlOrJSONParsesSimpleJSONCases(t *testing.T) {
	input := `
{
	"a": "1",
	"b": 2,
	"c": null
}`
	want := map[string]string{"a": "1", "b": "2", "c": ""}
	got, _ := parseYamlOrJSON(input)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseYamlOrJSON() with input:\n %s\n didn't match %v. Got %v", input, want, got)
	}
}

// OsloPolicy2Rego tests

func TestOsloPolicy2Rego(t *testing.T) {
	regoPolicyHeader := `
package openstack.policy

import input.credentials as credentials
import input.action_name as action_name
import input.target as target

default allow = false`

	oneRuleOneActionInput := `
{
	"admin": "role:admin",
	"secrets:get": "rule:admin"
}`
	oneRuleOneActionOutput := []string{`admin {
    credentials.roles[_] = "admin"
}`, `allow {
    action_name = "secrets:get"
    admin
}`}

	alwaysFalseInput := `
{
	"secrets:get": "!"
}`
	alwaysFalseOutput := []string{`allow {
    action_name = "secrets:get"
    false
}`}

	alwaysTrueWithEmptyStringInput := `
{
	"secrets:get": ""
}`
	alwaysTrueWithEmptyStringOutput := []string{`allow {
    action_name = "secrets:get"
    true
}`}

	cases := []struct {
		description string
		input       string
		want        []string
	}{
		{"One rule and one action should work", oneRuleOneActionInput, oneRuleOneActionOutput},
		{"Action should always be false", alwaysFalseInput, alwaysFalseOutput},
		{"Action should always be true given an empty string", alwaysTrueWithEmptyStringInput, alwaysTrueWithEmptyStringOutput},
	}
	for _, c := range cases {
		got, _ := OsloPolicy2Rego(c.input)
		if !strings.HasPrefix(got, regoPolicyHeader) {
			t.Errorf("OsloPolicy2Rego() test case \"%s\" with input:\n %s\n\nDidn't render the header:\n%s\nGot:\n%s",
				c.description, c.input, regoPolicyHeader, got)
		}
		for _, wantedOutput := range c.want {
			if !strings.Contains(got, wantedOutput) {
				t.Errorf("OsloPolicy2Rego() test case \"%s\" with input:\n %s\n\nDidn't contain:\n%s\nGot:\n%s",
					c.description, c.input, c.want, got)
			}
		}
	}
}
