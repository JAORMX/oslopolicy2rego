package main

import (
	"fmt"

	o2r "github.com/JAORMX/oslopolicy2rego/parser"
)

func main() {
	sampleInput := `
{
"secrets:get": "((rule:creator and rule:reader))"
}
`
	output, err := o2r.OsloPolicy2Rego(sampleInput)
	if err != nil {
		panic(err)
	}
	fmt.Println(output)
}
