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

func TestValidatePackageName(t *testing.T) {
	cases := []struct {
		input string
		want  bool
	}{
		{"policy", true},
		{"openstack.policy", true},
		{"keystone.policy", true},
		{"key.manager.policy", true},
		{"bad/package", false},
		{".policy", false},
	}
	for _, c := range cases {
		got := validatePackageName(c.input)
		if got != c.want {
			t.Errorf("validatePackageName() with input: %s\nDidn't match %v\nInstead got: %v",
				c.input, c.want, got)
		}
	}
}

// OsloPolicy2Rego tests

func TestOsloPolicy2RegoSuccesses(t *testing.T) {
	regoPolicyHeader := `
package openstack.policy

import input.credentials as credentials
import input.rule as rule
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
    rule = "secrets:get"
    admin
}`}

	alwaysFalseInput := `
{
	"secrets:get": "!"
}`
	alwaysFalseOutput := []string{`allow {
    rule = "secrets:get"
    false
}`}

	notStatementInput := `
{
	"secrets:get": "not rule:admin"
}
`
	notStatementOutput := []string{`allow {
    rule = "secrets:get"
    not admin
}`}

	alwaysTrueWithEmptyStringInput := `
{
	"secrets:get": ""
}`
	alwaysTrue := []string{`allow {
    rule = "secrets:get"
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

	multipleAssertionsWithAndInput := `
{
	"secrets:get": "rule:admin and rule:creator and rule:reader and not rule:audit"
}
`

	multipleAssertionsWithAndOutput := []string{`allow {
    rule = "secrets:get"
    admin
    creator
    reader
    not audit
}`}

	multipleRulesWithOrInput := `
{
	"secrets:get": "rule:admin or rule:creator or rule:reader"
}
`

	multipleRulesWithOrOutput := []string{`allow {
    rule = "secrets:get"
    admin
}`, `allow {
    rule = "secrets:get"
    creator
}`, `allow {
    rule = "secrets:get"
    reader
}`}

	credentialsTargetComparisonInput := `
{
	"secret_project_match": "project:%(target.secret.project_id)s",
}
`
	credentialsTargetComparisonOutput := []string{`secret_project_match {
    credentials.project = target.target.secret.project_id
}`}

	literalStringValueComparisonInput := `
{
	"secret_project_match": "project:asdf",
}
`
	stringValueComparisonOutput := []string{`secret_project_match {
    credentials.project = "asdf"
}`}

	leftSideQuotedStringValueComparisonInput := `
{
	"secret_project_match": "'asdf':project",
}
`
	rightSideQuotedStringValueComparisonInput := `
{
	"secret_project_match": "project:'asdf'",
}
`
	leftSideNumberValueComparisonInput := `
{
	"secret_project_match": "123:project",
}
`
	rightSideNumberValueComparisonInput := `
{
	"secret_project_match": "project:123",
}
`

	numberValueComparisonOutput := []string{`secret_project_match {
    credentials.project = 123
}`}

	leftSideBooleanTrueValueComparisonInput := `
{
	"secret_project_match": "True:project",
}
`
	rightSideBooleanTrueValueComparisonInput := `
{
	"secret_project_match": "project:True",
}
`

	booleanTrueValueComparisonOutput := []string{`secret_project_match {
    credentials.project = true
}`}

	leftSideBooleanFalseValueComparisonInput := `
{
	"secret_project_match": "False:project",
}
`
	rightSideBooleanFalseValueComparisonInput := `
{
	"secret_project_match": "project:False",
}
`

	booleanFalseValueComparisonOutput := []string{`secret_project_match {
    credentials.project = false
}`}

	constantTargetComparisonInput := `
{
	"secret_project_match": "False:%(target.secret.project_id)s",
}
`
	constantTargetComparisonOutput := []string{`secret_project_match {
    false = target.target.secret.project_id
}`}

	simpleParenthesesInput := `
{
	"secrets:get": "False:%(target.secret.project_id)s or (rule:creator and rule:reader)"
}
`

	simpleParenthesesOutput := []string{`allow {
    rule = "secrets:get"
    false = target.target.secret.project_id`, ` {
    creator
    reader
}`}

	multipleParenthesesInput := `
{
	"secrets:get": "rule:admin or (rule:creator and rule:reader) or not (rule:foo and rule:bar)"
}
`

	multipleParenthesesOutput := []string{`allow {
    rule = "secrets:get"
    admin`, ` {
    creator
    reader
}`, ` {
    foo
    bar
}`}

	nestedParenthesesInput1 := `
{
	"secrets:get": "(rule:creator and rule:reader) or not ((rule:foo and rule:bar))"
}
`

	nestedParenthesesOutput1 := []string{`allow {
    rule = "secrets:get"
    openstack_rule`, ` {
    creator
    reader
}`, ` {
    foo
    bar
}`}

	nestedParenthesesInput2 := `
{
	"secrets:get": "((rule:foo and rule:bar))"
}
`

	nestedParenthesesOutput2 := []string{`allow {
    rule = "secrets:get"
    openstack_rule`, ` {
    foo
    bar
}`}

	cases := []struct {
		description string
		input       string
		want        []string
	}{
		{"One rule and one action should work", oneRuleOneActionInput, oneRuleOneActionOutput},
		{"Action should always be false", alwaysFalseInput, alwaysFalseOutput},
		{"Parse 'not' statement correctly", notStatementInput, notStatementOutput},
		{"Action should always be true given an empty string", alwaysTrueWithEmptyStringInput, alwaysTrue},
		{"Action should always be true given an empty list", alwaysTrueWithEmptyListInput, alwaysTrue},
		{"Action should always be true given an @ sign", alwaysTrueWithAtSignInput, alwaysTrue},
		{"Should add multiple assertions with the 'and' keyword", multipleAssertionsWithAndInput, multipleAssertionsWithAndOutput},
		{"Should add multiple rules with the 'or' keyword", multipleRulesWithOrInput, multipleRulesWithOrOutput},
		{"Should render comparison between incoming credentials and target", credentialsTargetComparisonInput, credentialsTargetComparisonOutput},
		{"Should render comparison between incoming credentials and string", literalStringValueComparisonInput, stringValueComparisonOutput},
		{"Should render comparison between incoming credentials and quoted string on the left", leftSideQuotedStringValueComparisonInput, stringValueComparisonOutput},
		{"Should render comparison between incoming credentials and quoted string on the right", rightSideQuotedStringValueComparisonInput, stringValueComparisonOutput},
		{"Should render comparison between incoming credentials and number on the left", leftSideNumberValueComparisonInput, numberValueComparisonOutput},
		{"Should render comparison between incoming credentials and number on the right", rightSideNumberValueComparisonInput, numberValueComparisonOutput},
		{"Should render comparison between incoming credentials and true boolean value on the left", leftSideBooleanTrueValueComparisonInput, booleanTrueValueComparisonOutput},
		{"Should render comparison between incoming credentials and true boolean value on the right", rightSideBooleanTrueValueComparisonInput, booleanTrueValueComparisonOutput},
		{"Should render comparison between incoming credentials and false boolean value on the left", leftSideBooleanFalseValueComparisonInput, booleanFalseValueComparisonOutput},
		{"Should render comparison between incoming credentials and false boolean value on the right", rightSideBooleanFalseValueComparisonInput, booleanFalseValueComparisonOutput},
		{"Should render comparison between constant and target", constantTargetComparisonInput, constantTargetComparisonOutput},
		{"Should render parentheses expression (one level)", simpleParenthesesInput, simpleParenthesesOutput},
		{"Should render multiple parentheses expression", multipleParenthesesInput, multipleParenthesesOutput},
		{"Should render nested parentheses expression #1", nestedParenthesesInput1, nestedParenthesesOutput1},
		{"Should render nested parentheses expression #2", nestedParenthesesInput2, nestedParenthesesOutput2},
	}
	for _, c := range cases {
		got, err := OsloPolicy2Rego("openstack.policy", c.input)
		if err != nil {
			t.Errorf("OsloPolicy2Rego() test case \"%s\" with input:\n %s\n\nFailed with:\n%v",
				c.description, c.input, err)
		} else {
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

	emptyMap := `
{
	"secrets:get": {}
}`

	nestedMap := `
{
	"secrets:get": {
		"this map": "shouldn't work"
	}
}`

	invalidValueShouldFail := `
{
	"secrets:get": "aljksdfklasdf"
}`

	credentialsTargetComparisonInvalidInput := `
{
	"secret_project_match": "project:%(target.secret.project_ids",
}
`

	comparisonWithNoRightOperandInput := `
{
	"secret_project_match": "project:",
}
`

	comparisonWithNoLeftOperandInput := `
{
	"secret_project_match": ":%(project)s",
}
`

	InvalidAssertionInOrStatementInput := `
{
	"secret_project_match": "rule:my_rule or :%(project)s",
}
`

	InvalidAssertionInAndStatementInput := `
{
	"secret_project_match": "rule:my_rule and project:",
}
`

	InvalidAssertionInNotStatementInput := `
{
	"secret_project_match": "not project:%(target.secret.project_ids",
}
`
	unclosedParenthesesInput := `
{
	"secrets:get": "rule:admin or (rule:creator and rule:reader"
}
`

	multipleUnclosedParenthesesInput := `
{
	"secrets:get": "rule:admin or (rule:foo and rule:bar) or (rule:creator and rule:reader"
}
`

	emptyParenthesesInput := `
{
	"secrets:get": "rule:admin or (rule:foo and rule:bar) or (rule:creator and rule:reader"
}
`
	cases := []struct {
		description string
		input       string
	}{
		{"Invalidly formatted input should fail", wrongInput},
		{"List with items should fail", listWithItems},
		{"Numeric value should fail", numericValue},
		{"Empty map should fail", emptyMap},
		{"Nested map should fail", nestedMap},
		{"invalid value should fail", invalidValueShouldFail},
		{"Missing parentheses from credentials target comparison should fail", credentialsTargetComparisonInvalidInput},
		{"No right operand in comparison should fail", comparisonWithNoRightOperandInput},
		{"No left operand in comparison should fail", comparisonWithNoLeftOperandInput},
		{"Invalid assertion in or statement should fail", InvalidAssertionInOrStatementInput},
		{"Invalid assertion in and statement should fail", InvalidAssertionInAndStatementInput},
		{"Invalid assertion in not statement should fail", InvalidAssertionInNotStatementInput},
		{"Unclosed parentheses should fail", unclosedParenthesesInput},
		{"Multiple unclosed parentheses should fail", multipleUnclosedParenthesesInput},
		{"Empty parentheses should fail", emptyParenthesesInput},
	}
	for _, c := range cases {
		got, err := OsloPolicy2Rego("openstack.policy", c.input)
		if err == nil {
			t.Errorf("OsloPolicy2Rego() should have returned an error for:\n %s\n Instead got: %v", c.input, got)
		}
	}
}
