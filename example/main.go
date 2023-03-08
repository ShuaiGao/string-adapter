package main

import (
	"fmt"
	sa "github.com/ShuaiGao/string-adapter"
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
)

func newModel(superuser string) model.Model {
	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj, act")
	m.AddDef("p", "p", "sub, obj, act")
	m.AddDef("g", "g", "_, _")
	m.AddDef("e", "e", "some(where (p.eft == allow))")
	if superuser != "" {
		m.AddDef("m", "m", fmt.Sprintf("g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act || r.sub == \"u:%s\"", superuser))
	} else {
		m.AddDef("m", "m", "g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act")
	}
	return m
}

var Enforcer *casbin.Enforcer

func main() {
	m := newModel("")
	policies := `
p, alice, data1, read
p, bob, data2, write
p, data_group_admin, data_group, write

g, alice, data_group_admin
g2, data1, data_group
g2, data2, data_group
`
	sa := sa.NewAdapter(&policies)
	if e, err := casbin.NewEnforcer(m, sa); err != nil {
		panic(err)
	} else {
		Enforcer = e
	}

	Enforcer.LoadPolicy()

	// Check the permission.
	if res, _ := Enforcer.Enforce("alice", "data1", "read"); res {
		fmt.Println("permitted")
	} else {
		fmt.Println("rejected")
	}
	// Save the policy back to DB.
	Enforcer.SavePolicy()
}
