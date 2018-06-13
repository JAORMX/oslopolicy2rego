oslopolicy2rego: Oslo policy to rego
====================================

Is a small library (and eventually a CLI) that serves the sole purpose of
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
	output, _ := o2r.OsloPolicy2Rego(sampleInput)
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

Dependencies
------------

- **gopkg.in/yaml.v2**: https://gopkg.in/yaml.v2

What works
----------

Currently what's here is a very minimal subset of oslo.policy that's accepted.

It accepts true values (empty lists, empty string and "@"), and always negative
values ("!").

It reads a role ("role:admin") and also rule references ("rule:admin")

"and" and "or" expressions are accepted.

TODO
----

* "not" statements

* Comparison with constant value

* Comparison with credentials (project_id, user_id, is_admin)

* Comparison with target

* parentheses

[1] https://docs.openstack.org/oslo.policy/latest/index.html

[2] https://www.openpolicyagent.org/docs/how-do-i-write-policies.html
