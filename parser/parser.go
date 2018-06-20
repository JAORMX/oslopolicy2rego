package oslopolicy2rego

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"text/template"

	"gopkg.in/yaml.v2"
)

const policyHeader = `
package openstack.policy

import input.credentials as credentials
import input.action_name as action_name
import input.target as target

default allow = false
`

const actionTemplate = `allow {
    action_name = "{{.Name}}"
    {{.Expression}}
}`

const aliasTemplate = `{{.Name}} {
    {{.Expression}}
}`

type expression struct {
	assertions []string
}

type regoRule struct {
	RuleType   string
	Name       string
	Expression expression
}

// This contains the actual list of rules
type regoRules []regoRule

type tokenParserStateFunction func(string, bool, *osloParserState) (*regoRule, error)

type osloParserState struct {
	rulesStack    []regoRule
	prefix        string
	nextOperation tokenParserStateFunction
}

// Wrapper struct to write the template
type osloParser struct {
	Rules regoRules
	Tmpl  *template.Template
}

func (e expression) String() string {
	return strings.Join(e.assertions, "\n    ")
}

func (o osloParserState) Len() int {
	return len(o.rulesStack)
}

func (o *osloParserState) addPrefix(prefix string) {
	o.prefix = prefix
}

func (o *osloParserState) addAssertion(assertion string) {
	lastIndex := len(o.rulesStack) - 1
	assertions := o.rulesStack[lastIndex].Expression.assertions

	prefix := ""
	if o.prefix != "" {
		prefix = o.prefix + " "
	}

	assertion = prefix + assertion
	assertions = append(assertions, assertion)

	o.rulesStack[lastIndex].Expression.assertions = assertions
	o.prefix = ""
}

func (o *osloParserState) push(v regoRule) {
	o.rulesStack = append(o.rulesStack, v)
}

func (o *osloParserState) pop() (regoRule, error) {
	l := len(o.rulesStack)
	if l == 0 {
		return regoRule{}, errors.New("Can't pop from an empty stack")
	}
	rule := o.rulesStack[l-1]
	o.rulesStack = o.rulesStack[:l-1]
	return rule, nil
}

// Initialized the osloParser object. This involves initializing the template
// objects in order to render the rego rules.
func (o *osloParser) Init() error {
	tmpl, _ := template.New("Action").Parse(actionTemplate)
	tmpl, _ = tmpl.New("Alias").Parse(aliasTemplate)

	o.Tmpl = tmpl
	return nil
}

// renders the named rego segment related to the templateName. Currently we
// only have two: Action, Alias
func (o osloParser) renderTemplate(templateName string, outputStruct interface{}) string {
	var render bytes.Buffer

	err := o.Tmpl.ExecuteTemplate(&render, templateName, outputStruct)

	if err != nil {
		return ""
	}

	return render.String()
}

func (o osloParser) renderRuleEntry(rule regoRule) string {
	return o.renderTemplate(rule.RuleType, rule)
}

func (o osloParser) String() string {
	var outputPolicies []string
	for _, rule := range o.Rules {
		outputPolicies = append(outputPolicies, o.renderRuleEntry(rule))
	}
	return policyHeader + strings.Join(outputPolicies, "\n")
}

func (o *osloParser) parseExpression(baseRule regoRule, value interface{}) ([]regoRule, error) {
	var outputRules []regoRule
	switch typedValue := value.(type) {
	case string:
		if typedValue == "!" {
			baseRule.Expression = createSimpleExpression("false")
			outputRules = append(outputRules, baseRule)
			return outputRules, nil
		} else if typedValue == "" || typedValue == "@" {
			baseRule.Expression = createSimpleExpression("true")
			outputRules = append(outputRules, baseRule)
			return outputRules, nil
		}
		baseRule.Expression = expression{}
		state := osloParserState{nextOperation: expectStart}
		state.push(baseRule)
		token := ""
		token, typedValue = tokenize(typedValue)

		for token != "" {
			outputRule, err := state.nextOperation(token, false, &state)
			if err != nil {
				return nil, err
			}
			if outputRule != nil {
				outputRules = append(outputRules, *outputRule)
			}
			token, typedValue = tokenize(typedValue)
		}

		outputRule, err := state.nextOperation("", true, &state)
		if err != nil {
			return nil, err
		}
		if outputRule != nil {
			outputRules = append(outputRules, *outputRule)
		}
	case []interface{}:
		if len(typedValue) == 0 {
			baseRule.Expression = createSimpleExpression("true")
			outputRules = append(outputRules, baseRule)
			return outputRules, nil
		} else {
			return nil, errors.New("Can't give non-empty lists as values")
		}
	default:
		errorMessage := fmt.Sprintf("The value %v is invalid", typedValue)
		return nil, errors.New(errorMessage)
	}
	return outputRules, nil
}

// parseRules parses the rules from the given map and persists them on to the
// Rules entry of the osloParser object.
func (o *osloParser) parseRules(rules map[string]interface{}) error {
	var rulesList []regoRule

	for key, value := range rules {
		ruleType := ""
		if strings.Contains(key, ":") {
			ruleType = "Action"
		} else {
			ruleType = "Alias"
		}
		rule := regoRule{RuleType: ruleType, Name: key}
		rules, err := o.parseExpression(rule, value)
		if err != nil {
			errorMessage := fmt.Sprintf("Error in key %s: \"%v\"", key, err)
			return errors.New(errorMessage)
		}
		rulesList = append(rulesList, rules...)
	}

	o.Rules = rulesList
	return nil
}

// Returns a random alias name with the named prefix
func randomAliasName(prefix string) string {
	return fmt.Sprintf("%s_%d", prefix, rand.Int())
}

func createSimpleExpression(value string) expression {
	simpleExpression := expression{}
	simpleExpression.assertions = append(simpleExpression.assertions, value)
	return simpleExpression
}

func createSubRule() regoRule {
	subRule := regoRule{RuleType: "Alias", Name: randomAliasName("openstack_rule")}
	subRule.Expression = expression{}
	return subRule
}

func newRule(baseRule regoRule) regoRule {
	rule := regoRule{RuleType: baseRule.RuleType, Name: baseRule.Name}
	rule.Expression = expression{}
	return rule
}

func valueIsQuotedString(stringValue string) bool {
	if stringValue[0] == '\'' && stringValue[len(stringValue)-1] == '\'' {
		return true
	}
	return false
}

func valueIsNumber(stringValue string) bool {
	_, err := strconv.ParseInt(stringValue, 0, 64)
	if err != nil {
		return false
	}
	return true
}

func valueIsBoolean(stringValue string) bool {
	if stringValue == "True" || stringValue == "False" {
		return true
	}
	return false
}

// Renders the comparison between two values. If they haven't matched a type,
// they are assumed to come from the credentials, so we render it as such. If
// they matched a type we render the value as was given.
func renderComparison(leftValue string, leftMatched bool,
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
func renderConstantForComparison(value string) (string, bool) {
	if valueIsBoolean(value) {
		return strings.ToLower(value), true
	} else if valueIsNumber(value) {
		return value, true
	} else if valueIsQuotedString(value) {
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
func parseComparison(value string) (string, error) {
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
		return renderComparison("roles[_]", false, comparedValues[1], false), nil
	} else if strings.HasPrefix(comparedValues[1], "%(") {
		targetValue := ""
		if strings.HasSuffix(comparedValues[1], ")s") {
			targetValue = "target." + comparedValues[1][2:len(comparedValues[1])-2]
		} else {
			errorMessage := fmt.Sprintf("Unmatched parentheses in value %v", value)
			return "", errors.New(errorMessage)
		}
		leftValue, leftMatched := renderConstantForComparison(comparedValues[0])
		return renderComparison(leftValue, leftMatched, targetValue, true), nil
	}

	leftValue, leftMatched := renderConstantForComparison(comparedValues[0])
	rightValue, rightMatched := renderConstantForComparison(comparedValues[1])
	return renderComparison(leftValue, leftMatched, rightValue, rightMatched), nil
}

func expectStart(token string, end bool, state *osloParserState) (*regoRule, error) {
	if end {
		return nil, errors.New("Unexpected end of expression.")
	} else if token == "(" {
		subRule := createSubRule()
		state.addAssertion(subRule.Name)
		state.push(subRule)
		return nil, nil
	} else if token == ")" {
		currentRule, err := state.pop()
		// We can't advance if we're in the base rule, it has to be a sub rule
		if err != nil || state.Len() == 0 {
			return nil, errors.New("Unexpected closing parenthesis.")
		}
		state.nextOperation = expectEndOrOperator
		return &currentRule, err
	} else if token == "not" {
		state.addPrefix("not")
		state.nextOperation = expectNextToken
		return nil, nil
	} else if strings.Contains(token, ":") {
		assertion, err := parseComparison(token)
		if err != nil {
			return nil, err
		}
		state.addAssertion(assertion)
		state.nextOperation = expectEndOrOperator
		return nil, nil
	}
	errorMessage := fmt.Sprintf("Unexpected token: %v", token)
	return nil, errors.New(errorMessage)
}

func expectNextToken(token string, end bool, state *osloParserState) (*regoRule, error) {
	if end {
		return nil, errors.New("Unexpected end of expression.")
	} else if token == "(" {
		subRule := createSubRule()
		state.addAssertion(subRule.Name)
		state.push(subRule)
		return nil, nil
	} else if token == ")" {
		currentRule, err := state.pop()
		// We can't advance if we're in the base rule, it has to be a sub rule
		if err != nil || state.Len() == 0 {
			return nil, errors.New("Unexpected closing parenthesis.")
		}
		state.nextOperation = expectEndOrOperator
		return &currentRule, err
	} else if strings.Contains(token, ":") {
		assertion, err := parseComparison(token)
		if err != nil {
			return nil, err
		}
		state.addAssertion(assertion)
		state.nextOperation = expectEndOrOperator
		return nil, nil
	}
	errorMessage := fmt.Sprintf("Unexpected token: %v", token)
	return nil, errors.New(errorMessage)
}

func expectEndOrOperator(token string, end bool, state *osloParserState) (*regoRule, error) {
	if end {
		rule, err := state.pop()
		if err != nil {
			return nil, err
		}
		if state.Len() != 0 {
			return nil, errors.New("Unclosed subexpression")
		}
		return &rule, nil
	} else if token == ")" {
		currentRule, err := state.pop()
		// We can't advance if we're in the base rule, it has to be a sub rule
		if err != nil || state.Len() == 0 {
			return nil, errors.New("Unexpected closing parenthesis.")
		}
		return &currentRule, err
	} else if token == "and" {
		state.nextOperation = expectStart
		return nil, nil
	} else if token == "or" {
		currentRule, err := state.pop()
		if err != nil {
			return nil, err
		}
		rule := newRule(currentRule)
		state.push(rule)
		state.nextOperation = expectStart
		return &currentRule, nil
	}
	errorMessage := fmt.Sprintf("Unexpected token: %v", token)
	return nil, errors.New(errorMessage)
}

func runeIsWhitespace(r rune) bool {
	return r == ' ' || r == '\t'
}

func tokenize(value string) (string, string) {
	var parsedIndex int
	var whitespaceOffset int
	var prevChar rune
	var parsingToken bool

	for index, char := range value {
		// If we'ere not parsing a token we return the start parenthesis as a
		// token
		if char == '(' && !parsingToken {
			unparsedStart := index + 1
			return "(", value[unparsedStart:]
		}
		if runeIsWhitespace(char) {
			// If we're parsing a token, a whitespace is a token delimiter.
			if parsingToken && prevChar == ')' {
				// If the previous character was a closing parenthesis, and we
				// encounter a whitespace delimiter, return the token we were
				// parsing, and start the next parsing at the end parenthesis
				parsedEnd := index - 1
				unparsedStart := index - 1
				return value[:parsedEnd], value[unparsedStart:]
			} else if parsingToken {
				parsedEnd := index
				unparsedStart := index + 1
				return value[whitespaceOffset:parsedEnd], value[unparsedStart:]
			} else {
				// ignore whitespaces otherwise
				parsedIndex = index
				prevChar = char
				whitespaceOffset = whitespaceOffset + 1
				continue
			}
		}
		if char == ')' && prevChar == ')' {
			if parsingToken {
				parsedEnd := index - 1
				unparsedStart := index - 1
				return value[:parsedEnd], value[unparsedStart:]
			} else {
				parsedEnd := index
				unparsedStart := index - 1
				return value[:parsedEnd], value[unparsedStart:]
			}
		}
		if char == ')' && !parsingToken {
			unparsedStart := index + 1
			return ")", value[unparsedStart:]
		}
		parsedIndex = index
		parsingToken = true
		prevChar = char
	}
	if prevChar == ')' {
		// If the previous character was a closing parenthesis, and we
		// encounter the end, return the token we were
		// parsing, and start the next parsing at the end parenthesis
		parsedEnd := parsedIndex
		return value[:parsedEnd], value[parsedEnd:]
	}
	if len(value) > 0 {
		parsedEnd := parsedIndex + 1
		return value[:parsedEnd], value[parsedEnd:]
	}
	return "", ""
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

// OsloPolicy2Rego takes a yaml or JSON string containing oslo.policy rules and
// converts them into Rego language.
func OsloPolicy2Rego(input string) (string, error) {
	rules, err := parseYamlOrJSON(input)
	if err != nil {
		return "", err
	}

	op := osloParser{}
	op.Init()
	err = op.parseRules(rules)
	if err != nil {
		return "", err
	}
	return op.String(), nil
}
