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
    action_name = "{{.ActionName}}"
    {{.Rules}}
}`

const aliasTemplate = `{{.AliasName}} {
    {{.Rules}}
}`

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

func (o parsedRego) renderRules(value interface{}) ([]string, error) {
	var outputRules []string
	switch typedValue := value.(type) {
	case string:
		if strings.HasPrefix(typedValue, "rule:") {
			outputRules = append(outputRules, typedValue[5:])
		} else if strings.HasPrefix(typedValue, "role:") {
			roleAssertion := "credentials.roles[_] = \"" + typedValue[5:] + "\""
			outputRules = append(outputRules, roleAssertion)
		} else if typedValue == "!" {
			outputRules = append(outputRules, "false")
		} else if typedValue == "" || typedValue == "@" {
			outputRules = append(outputRules, "true")
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

func (o parsedRego) renderAction(key string, value interface{}) (string, error) {
	rules, err := o.renderRules(value)
	if err != nil {
		return "", err
	}

	var output string
	for _, rule := range rules {
		action := struct {
			ActionName string
			Rules      string
		}{
			key,
			rule,
		}
		output = output + "\n" + o.renderTemplate("Action", action)
	}
	return output, nil
}

func (o parsedRego) renderAlias(key string, value interface{}) (string, error) {
	rules, err := o.renderRules(value)
	if err != nil {
		return "", err
	}

	var output string
	for _, actionRule := range rules {
		alias := struct {
			AliasName string
			Rules     string
		}{
			key,
			actionRule,
		}
		output = output + "\n" + o.renderTemplate("Alias", alias)
	}
	return output, nil
}

// parseRules parses the rules from the given map and persists them on to the
// Rules entry of the parsedRego object.
func (o *parsedRego) parseRules(rules map[string]interface{}) error {
	var rulesList []string

	for key, value := range rules {
		if strings.Contains(key, ":") {
			action, err := o.renderAction(key, value)
			if err != nil {
				return err
			}

			rulesList = append(rulesList, action)
		} else {
			alias, err := o.renderAlias(key, value)
			if err != nil {
				return err
			}

			rulesList = append(rulesList, alias)
		}
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
