package oslopolicy2rego

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"text/template"

	"gopkg.in/yaml.v2"
)

// This contains the actual list of rules
type regoRules struct {
	rules []string
}

// Wrapper struct to write the template
type parsedRego struct {
	Rules regoRules
	Tmpl  *template.Template
}

func (o regoRules) String() string {
	return strings.Join(o.rules, "\n")
}

const baseTemplate = `
package openstack.policy

import input.credentials as credentials
import input.action_name as action_name
import input.target as target

default allow = false
{{.Rules}}`

const actionTemplate = `allow {
    action_name = "{{.Name}}"
    {{.Rules}}
}`

const aliasTemplate = `{{.Name}} {
    {{.Rules}}
}`

// Initialized the parsedRego object. This involves initializing the template
// objects in order to render the rego rules.
func (o *parsedRego) Init() error {
	tmpl, err := template.New("OpenStackRegoBase").Parse(baseTemplate)
	if err != nil {
		return err
	}

	tmpl, err = tmpl.New("Action").Parse(actionTemplate)
	if err != nil {
		return err
	}

	tmpl, err = tmpl.New("Alias").Parse(aliasTemplate)
	if err != nil {
		return err
	}

	o.Tmpl = tmpl
	return nil
}

// renders the named rego segment related to the templateName. Currently we
// only have three: OpenStackRegoBase, Action, Alias
func (o parsedRego) renderTemplate(templateName string, outputStruct interface{}) string {
	var render bytes.Buffer

	err := o.Tmpl.ExecuteTemplate(&render, templateName, outputStruct)

	if err != nil {
		return ""
	}

	return render.String()
}

// Returns a string for the given ParsedRego object. It should always give out
// something from the default template. If it doesn't, it means an error
// happened.
func (o parsedRego) String() string {
	return o.renderTemplate("OpenStackRegoBase", o)
}

// Renders "not" statements for any given rule
func (o parsedRego) renderNotStatements(value string) ([]string, error) {
	rules, err := o.renderRules(value)
	if err != nil {
		return nil, err
	}
	modifiedRules := rules[:0]
	for _, rule := range rules {
		modifiedRules = append(modifiedRules, "not "+rule)
	}
	return modifiedRules, nil
}

// Renders several assertions based on "and" statements for any given number of
// rules
func (o parsedRego) renderMultipleAssertionsWithAnd(value string) (string, error) {
	var outputRules []string
	unparsedRules := strings.Split(value, " and ")
	for _, unparsedRule := range unparsedRules {
		parsedRule, err := o.renderRules(unparsedRule)
		if err != nil {
			return "", err
		}

		outputRules = append(outputRules, parsedRule...)
	}
	return strings.Join(outputRules, "\n    "), nil
}

// Renders several rules based on "or" statements based on any given number of
// rules
func (o parsedRego) renderMultipleRulesWithOr(value string) ([]string, error) {
	var outputRules []string
	unparsedRules := strings.Split(value, " or ")
	for _, unparsedRule := range unparsedRules {
		parsedRule, err := o.renderRules(unparsedRule)
		if err != nil {
			return nil, err
		}

		outputRules = append(outputRules, parsedRule...)
	}
	return outputRules, nil
}

// Renders value comparisons, which can be:
// * rule assertions
// * role assertions
// * comparing a value coming from the credentials with a value coming from the
//   target
// * Constant value comparison
func (o parsedRego) renderComparison(value string) (string, error) {
	comparedValues := strings.SplitN(value, ":", 2)

	if comparedValues[0] == "" {
		errorMessage := fmt.Sprintf("You need to provide a left operand for the comparison: %v", value)
		return "", errors.New(errorMessage)
	} else if comparedValues[1] == "" {
		errorMessage := fmt.Sprintf("You need to provide a right operand for the comparison: %v", value)
		return "", errors.New(errorMessage)
	} else if comparedValues[0] == "rule" {
		return comparedValues[1], nil
	} else if comparedValues[0] == "role" {
		return "credentials.roles[_] = \"" + comparedValues[1] + "\"", nil
	} else if strings.HasPrefix(comparedValues[1], "%(") {
		targetValue := ""
		if strings.HasSuffix(comparedValues[1], ")s") {
			targetValue = "target." + comparedValues[1][2:len(comparedValues[1])-2]
		} else {
			errorMessage := fmt.Sprintf("Unmatched parentheses in value %v", value)
			return "", errors.New(errorMessage)
		}
		return "credentials." + comparedValues[0] + " = " + targetValue, nil
	}

	return "credentials." + comparedValues[0] + " = \"" + comparedValues[1] + "\"", nil
}

// Actual parsing function that handles the different cases from oslo.policy.
// It'll parse both simple (rules, roles, statements, constants and
// comparisons), as well as composed statements (ands, ors parentheses). This
// will return a list of strings
func (o parsedRego) renderRules(value interface{}) ([]string, error) {
	var outputRules []string
	switch typedValue := value.(type) {
	case string:
		if strings.Contains(typedValue, " and ") {
			assertions, err := o.renderMultipleAssertionsWithAnd(typedValue)
			if err != nil {
				return nil, err
			}
			outputRules = append(outputRules, assertions)
		} else if strings.Contains(typedValue, " or ") {
			rules, err := o.renderMultipleRulesWithOr(typedValue)
			if err != nil {
				return nil, err
			}
			outputRules = append(outputRules, rules...)
		} else if strings.HasPrefix(typedValue, "not ") {
			rules, err := o.renderNotStatements(typedValue[4:])
			if err != nil {
				return nil, err
			}
			outputRules = append(outputRules, rules...)
		} else if strings.Contains(typedValue, ":") {
			rule, err := o.renderComparison(typedValue)
			if err != nil {
				return nil, err
			}
			outputRules = append(outputRules, rule)
		} else if typedValue == "!" {
			outputRules = append(outputRules, "false")
		} else if typedValue == "" || typedValue == "@" {
			outputRules = append(outputRules, "true")
		} else {
			errorMessage := fmt.Sprintf("The value %v is invalid", typedValue)
			return nil, errors.New(errorMessage)
		}
	case []interface{}:
		if len(typedValue) == 0 {
			outputRules = append(outputRules, "true")
		} else {
			return nil, errors.New("Can't give non-empty lists as values")
		}
	default:
		errorMessage := fmt.Sprintf("The value %v is invalid", typedValue)
		return nil, errors.New(errorMessage)
	}
	return outputRules, nil
}

func (o parsedRego) renderEntry(entryType, key string, value interface{}) (string, error) {
	rules, err := o.renderRules(value)
	if err != nil {
		return "", err
	}

	var output string
	for _, rule := range rules {
		entry := struct {
			Name  string
			Rules string
		}{
			key,
			rule,
		}
		output = output + "\n" + o.renderTemplate(entryType, entry)
	}
	return output, nil
}

// parseRules parses the rules from the given map and persists them on to the
// Rules entry of the parsedRego object.
func (o *parsedRego) parseRules(rules map[string]interface{}) error {
	var rulesList []string

	for key, value := range rules {
		entryType := ""
		if strings.Contains(key, ":") {
			entryType = "Action"
		} else {
			entryType = "Alias"
		}

		alias, err := o.renderEntry(entryType, key, value)
		if err != nil {
			return err
		}

		rulesList = append(rulesList, alias)
	}

	o.Rules = regoRules{rulesList}
	return nil
}

// OsloPolicy2Rego takes a yaml or JSON string containing oslo.policy rules and
// converts them into Rego language.
func OsloPolicy2Rego(input string) (string, error) {
	rules, err := parseYamlOrJSON(input)
	if err != nil {
		return "", err
	}

	parsedRules := parsedRego{}
	parsedRules.Init()
	err = parsedRules.parseRules(rules)
	if err != nil {
		return "", err
	}
	return parsedRules.String(), nil
}

// parseYamlOrJSON takes a given string and parses it into a string map of
// interfaces. The given string is meant to be an oslo.policy read as an input.
func parseYamlOrJSON(input string) (map[string]interface{}, error) {
	var output map[string]interface{}
	err := yaml.Unmarshal([]byte(input), &output)
	if err != nil {
		return nil, err
	}
	return output, nil
}
