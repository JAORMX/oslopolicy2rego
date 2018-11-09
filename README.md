oslopolicy2rego: Oslo policy to rego
====================================

Is a small library and a CLI utility that serves the sole purpose of
converting oslo.policy[1] json or yaml files into Open-Policy-Agent rego
language [2].

The main interface is the `OsloPolicy2Rego` function, which can be called as
follows:

```
package main

import (
	"fmt"

	o2r "github.com/JAORMX/oslopolicy2rego/parser"
)

func main() {
	sampleInput := `
{
	"admin": "role:admin",
	"secrets:get": "rule:admin"
}
`
	output, _ := o2r.OsloPolicy2Rego("openstack.policy", sampleInput)
	fmt.Println(output)
}
```

The expected output would be:

```
package openstack.policy

import input.credentials as credentials
import input.action_name as action_name
import input.target as target

default allow = false

admin {
    credentials.roles[_] = "admin"
}

allow {
    action_name = "secrets:get"
    admin
}
```

There is also a simple CLI option that gets built when you build this project.
It takes three paremeters:

* input: The oslo.policy file that you want to parse.

* (optional) output: The file that you want to store the result in. (defaults
  to stdout)

* (optional) package-name: The name of the package to be used in the rego file.
  (defaults to "openstack.policy")

You could call it as follows:
```
 ./oslopolicy2rego_linux_amd64 --input ~/barbican-policy.yaml --output myfile.rego
```

Dependencies
------------

- **gopkg.in/yaml.v2**: https://gopkg.in/yaml.v2


[1] https://docs.openstack.org/oslo.policy/latest/index.html

[2] https://www.openpolicyagent.org/docs/how-do-i-write-policies.html
