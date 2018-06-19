package oslopolicy2rego

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"regexp"
	"strconv"
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
	Rules             regoRules
	Tmpl              *template.Template
	ParenthesesRegexp *regexp.Regexp
}

func (o regoRules) String() string {
	return strings.Join(o.rules, "\n")
}

const parenthesesRegexpString = `(^|\s)\(.*?\)(\s|$)`

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
	tmpl, _ := template.New("OpenStackRegoBase").Parse(baseTemplate)
	tmpl, _ = tmpl.New("Action").Parse(actionTemplate)
	tmpl, _ = tmpl.New("Alias").Parse(aliasTemplate)

	o.Tmpl = tmpl
	o.ParenthesesRegexp = regexp.MustCompile(parenthesesRegexpString)
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
	rules, _, err := o.renderRules(value)
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
		parsedRule, _, err := o.renderRules(unparsedRule)
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
		parsedRule, _, err := o.renderRules(unparsedRule)
		if err != nil {
			return nil, err
		}

		outputRules = append(outputRules, parsedRule...)
	}
	return outputRules, nil
}

func (o parsedRego) valueIsQuotedString(stringValue string) bool {
	if stringValue[0] == '\'' && stringValue[len(stringValue)-1] == '\'' {
		return true
	}
	return false
}

func (o parsedRego) valueIsNumber(stringValue string) bool {
	_, err := strconv.ParseInt(stringValue, 0, 64)
	if err != nil {
		return false
	}
	return true
}

func (o parsedRego) valueIsBoolean(stringValue string) bool {
	if stringValue == "True" || stringValue == "False" {
		return true
	}
	return false
}

// Renders the comparison between two values. If they haven't matched a type,
// they are assumed to come from the credentials, so we render it as such. If
// they matched a type we render the value as was given.
func (o parsedRego) renderComparison(leftValue string, leftMatched bool,
	rightValue string, rightMatched bool) string {
	if leftMatched && rightMatched {
		return leftValue + " = " + rightValue
	} else if !leftMatched && rightMatched {
		return "credentials." + leftValue + " = " + rightValue
	} else if leftMatched && !rightMatched {
		return "credentials." + rightValue + " = " + leftValue
	}
	return "credentials." + leftValue + " = \"" + rightValue + "\""
}

// Renders a constant value which is used in a comparison. This will return the
// rendered value (as it should be persisted in rego), or will just output the
// value as the result. If the value didn't match any of the types boolean,
// string or number, the second boolean output will be set to false, indicating
// that no match was found.
func (o parsedRego) renderConstantForComparison(value string) (string, bool) {
	if o.valueIsBoolean(value) {
		return strings.ToLower(value), true
	} else if o.valueIsNumber(value) {
		return value, true
	} else if o.valueIsQuotedString(value) {
		return "\"" + value[1:len(value)-1] + "\"", true
	}

	return value, false
}

// parses value comparisons, which can be:
// * rule assertions
// * role assertions
// * comparing a value coming from the credentials with a value coming from the
//   target
// * Constant value comparison
func (o parsedRego) parseComparison(value string) (string, error) {
	comparedValues := strings.SplitN(value, ":", 2)

	if comparedValues[0] == "" {
		errorMessage := fmt.Sprintf("You need to provide a left operand for the comparison: %v", value)
		return "", errors.New(errorMessage)
	} else if comparedValues[1] == "" {
		errorMessage := fmt.Sprintf("You need to provide a right operand for the comparison: %v", value)
		return "", errors.New(errorMessage)
	} else if comparedValues[0] == "rule" {
		// No need to render anything, pass the value as-is
		return comparedValues[1], nil
	} else if comparedValues[0] == "role" {
		// Pass in role comparison, which will be rendered being gotten from
		// the credentials. When none of the cases match it renders the right
		// value as a quoted string, which is what we want in this case.
		return o.renderComparison("roles[_]", false, comparedValues[1], false), nil
	} else if strings.HasPrefix(comparedValues[1], "%(") {
		targetValue := ""
		if strings.HasSuffix(comparedValues[1], ")s") {
			targetValue = "target." + comparedValues[1][2:len(comparedValues[1])-2]
		} else {
			errorMessage := fmt.Sprintf("Unmatched parentheses in value %v", value)
			return "", errors.New(errorMessage)
		}
		leftValue, leftMatched := o.renderConstantForComparison(comparedValues[0])
		return o.renderComparison(leftValue, leftMatched, targetValue, true), nil
	}

	leftValue, leftMatched := o.renderConstantForComparison(comparedValues[0])
	rightValue, rightMatched := o.renderConstantForComparison(comparedValues[1])
	return o.renderComparison(leftValue, leftMatched, rightValue, rightMatched), nil
}

// Checks if the given value contains a parentheses expression
func (o parsedRego) containsParenthesesExpression(value string) bool {
	return o.ParenthesesRegexp.MatchString(value)
}

// Returns a random alias name with the named prefix
func randomAliasName(prefix string) string {
	return fmt.Sprintf("%s_%d", prefix, rand.Int())
}

// renders a parentheses expression, which is done by creating a new rule in
// rego that will be refrenced by a random name. This returns the new
// expression that still needs to be evaluated, a key to reference the new rule
// with, and a string containing the sub-expression whithin the parentheses.
func (o parsedRego) renderParenthesesExpression(value string) (string, map[string]string, error) {
	if strings.Count(value, "(") != strings.Count(value, ")") {
		errorMessage := fmt.Sprintf("Unmatched parentheses in value %v", value)
		return "", nil, errors.New(errorMessage)
	}
	replacedExpressions := make(map[string]string)
	outputValue := o.ParenthesesRegexp.ReplaceAllStringFunc(value, func(matchedValue string) string {
		matchStart := 1
		startSeparator := ""
		matchEnd := len(matchedValue) - 1
		if matchedValue[0] == ' ' {
			matchStart = 2
			startSeparator = " "
		}
		if matchedValue[len(matchedValue)-1] == ' ' {
			matchEnd = matchEnd - 1
		}
		aliasName := randomAliasName("openstack_rule")
		replacedExpressions[aliasName] = matchedValue[matchStart:matchEnd]
		return startSeparator + "rule:" + aliasName
	})
	return outputValue, replacedExpressions, nil
}

// Actual parsing function that handles the different cases from oslo.policy.
// It'll parse both simple (rules, roles, statements, constants and
// comparisons), as well as composed statements (ands, ors parentheses). This
// will return a list of strings with the parsed rules, and a map of strings
// with extra sub-expressions that are gotten from parentheses expressions;
// which should be rendered separately
func (o parsedRego) renderRules(value interface{}) ([]string, map[string]string, error) {
	var outputRules []string
	var extraSubexpressions map[string]string
	switch typedValue := value.(type) {
	case string:
		if o.containsParenthesesExpression(typedValue) {
			var err error
			typedValue, extraSubexpressions, err = o.renderParenthesesExpression(typedValue)

			if err != nil {
				return nil, nil, err
			}
		}

		if strings.Contains(typedValue, " and ") {
			assertions, err := o.renderMultipleAssertionsWithAnd(typedValue)
			if err != nil {
				return nil, nil, err
			}
			outputRules = append(outputRules, assertions)
		} else if strings.Contains(typedValue, " or ") {
			rules, err := o.renderMultipleRulesWithOr(typedValue)
			if err != nil {
				return nil, nil, err
			}
			outputRules = append(outputRules, rules...)
		} else if strings.HasPrefix(typedValue, "not ") {
			rules, err := o.renderNotStatements(typedValue[4:])
			if err != nil {
				return nil, nil, err
			}
			outputRules = append(outputRules, rules...)
		} else if strings.Contains(typedValue, ":") {
			rule, err := o.parseComparison(typedValue)
			if err != nil {
				return nil, nil, err
			}
			outputRules = append(outputRules, rule)
		} else if typedValue == "!" {
			outputRules = append(outputRules, "false")
		} else if typedValue == "" || typedValue == "@" {
			outputRules = append(outputRules, "true")
		} else {
			errorMessage := fmt.Sprintf("The value %v is invalid", typedValue)
			return nil, nil, errors.New(errorMessage)
		}
	case []interface{}:
		if len(typedValue) == 0 {
			outputRules = append(outputRules, "true")
		} else {
			return nil, nil, errors.New("Can't give non-empty lists as values")
		}
	default:
		errorMessage := fmt.Sprintf("The value %v is invalid", typedValue)
		return nil, nil, errors.New(errorMessage)
	}
	return outputRules, extraSubexpressions, nil
}

func (o parsedRego) renderEntry(entryType, key string, rules interface{}) (string, error) {
	var output string
	renderedRules, extraSubexpressions, err := o.renderRules(rules)
	if err != nil {
		return "", err
	}

	for _, rule := range renderedRules {
		entry := struct {
			Name  string
			Rules string
		}{
			key,
			rule,
		}
		output = output + "\n" + o.renderTemplate(entryType, entry)
	}

	for subexpressionKey, subexpressionValue := range extraSubexpressions {
		entry, err := o.renderEntry("Alias", subexpressionKey, subexpressionValue)
		if err != nil {
			return "", err
		}
		output = output + entry
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

		entry, err := o.renderEntry(entryType, key, value)
		if err != nil {
			return err
		}

		rulesList = append(rulesList, entry)
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
