package oslopolicy2rego

import (
	"bytes"
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

func (o parsedRego) renderRules(value string) []string {
	var outputRules []string
	if strings.HasPrefix(value, "rule:") {
		outputRules = append(outputRules, value[5:])
	} else if strings.HasPrefix(value, "role:") {
		roleAssertion := "credentials.roles[_] = \"" + value[5:] + "\""
		outputRules = append(outputRules, roleAssertion)
	} else if value == "!" {
		outputRules = append(outputRules, "false")
	} else if value == "" {
		outputRules = append(outputRules, "true")
	}
	return outputRules
}

func (o parsedRego) renderAction(key, value string) string {
	rules := o.renderRules(value)
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
	return output
}

func (o parsedRego) renderAlias(key, value string) string {
	rules := o.renderRules(value)
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
	return output
}

// parseRules parses the rules from the given map and persists them on to the
// Rules entry of the parsedRego object.
func (o *parsedRego) parseRules(rules map[string]string) error {
	var rulesList []string

	for key, value := range rules {
		if strings.Contains(key, ":") {
			action := o.renderAction(key, value)
			rulesList = append(rulesList, action)
		} else {
			alias := o.renderAlias(key, value)
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
	parsedRules.parseRules(rules)
	return parsedRules.String(), nil
}

// parseYamlOrJSON takes a given string and parses it into a string map of
// strings. The given string is meant to be an oslo.policy read as an input.
func parseYamlOrJSON(input string) (map[string]string, error) {
	output := map[string]string{}
	err := yaml.Unmarshal([]byte(input), &output)
	if err != nil {
		return nil, err
	}
	return output, nil
}
