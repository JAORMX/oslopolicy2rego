package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	o2r "github.com/JAORMX/oslopolicy2rego/parser"
)

func main() {
	var outputStream io.Writer

	packageName := flag.String("package-name", "openstack.policy",
		"package name to use for the rego policy.")
	inputFile := flag.String("input", "", "Path to input oslo.policy file.")
	outputFile := flag.String("output", "", "Path to input oslo.policy file.")

	flag.Parse()

	if *inputFile == "" {
		panic("Must specify an input file.")
	}

	inputStream, err := ioutil.ReadFile(*inputFile)
	if err != nil {
		panic(err)
	}
	inputString := string(inputStream)

	if *outputFile == "" {
		outputStream = os.Stdout
	} else {
		var err error
		outputStream, err = os.OpenFile(*outputFile, os.O_RDWR|os.O_CREATE, 0644)
		if err != nil {
			panic(err)
		}
	}
	outputString, err := o2r.OsloPolicy2Rego(*packageName, inputString)
	if err != nil {
		panic(err)
	}
	fmt.Fprint(outputStream, outputString)
}
