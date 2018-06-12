package oslopolicy2rego

import (
	"strings"
	"testing"
)

// parseYamlOrJSON tests

func TestParseYamlOrJSONParsesSimpleYamlCases(t *testing.T) {
	test1yaml := `
---
a: 1
b: 2`
	test1map := map[string]interface{}{"a": 1, "b": 2}
	cases := []struct {
		input string
		want  map[string]interface{}
	}{
		{test1yaml, test1map},
		{"", map[string]interface{}{}},
	}
	for _, c := range cases {
		got, _ := parseYamlOrJSON(c.input)
		for wantedKey, wantedValue := range c.want {
			gottenValue, ok := got[wantedKey]
			if !ok || gottenValue != wantedValue {
				t.Errorf("parseYamlOrJSON() with input:\n %s\n entry {%v -> %v} didn't match {%v -> %v}",
					c.input, wantedKey, wantedValue, wantedKey, gottenValue)
			}
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
	want := map[string]interface{}{"a": "1", "b": 2, "c": nil}
	got, _ := parseYamlOrJSON(input)
	for wantedKey, wantedValue := range want {
		gottenValue, ok := got[wantedKey]
		if !ok || gottenValue != wantedValue {
			t.Errorf("parseYamlOrJSON() with input:\n %s\n entry {%v -> %v} didn't match {%v -> %v}",
				input, wantedKey, wantedValue, wantedKey, gottenValue)
		}
	}
}

// OsloPolicy2Rego tests

func TestOsloPolicy2RegoSuccesses(t *testing.T) {
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
	alwaysTrue := []string{`allow {
    action_name = "secrets:get"
    true
}`}

	alwaysTrueWithEmptyListInput := `
{
	"secrets:get": []
}`

	alwaysTrueWithAtSignInput := `
{
	"secrets:get": "@"
}`

	cases := []struct {
		description string
		input       string
		want        []string
	}{
		{"One rule and one action should work", oneRuleOneActionInput, oneRuleOneActionOutput},
		{"Action should always be false", alwaysFalseInput, alwaysFalseOutput},
		{"Action should always be true given an empty string", alwaysTrueWithEmptyStringInput, alwaysTrue},
		{"Action should always be true given an empty list", alwaysTrueWithEmptyListInput, alwaysTrue},
		{"Action should always be true given an @ sign", alwaysTrueWithAtSignInput, alwaysTrue},
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

func TestOsloPolicy2RegoErrors(t *testing.T) {
	wrongInput := `
{
	"admin": "role:admin",
	"secrets:get": "rule:admin"
`
	listWithItems := `
{
	"secrets:get": [1, 2, 3]
}`

	numericValue := `
{
	"secrets:get": 1
}`

	nestedMap := `
{
	"secrets:get": {
		"this map": "shouldn't work"
	}
}`

	cases := []struct {
		description string
		input       string
	}{
		{"Invalidly formatted input should fail", wrongInput},
		{"List with items should fail", listWithItems},
		{"Numeric value should fail", numericValue},
		{"Nested map should fail", nestedMap},
	}
	for _, c := range cases {
		got, err := OsloPolicy2Rego(c.input)
		if err == nil {
			t.Errorf("parseYamlOrJSON() should have returned an error for:\n %s\n Instead got: %v", c.input, got)
		}
	}
}
