package string_adapter

import (
	"bytes"
	"errors"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/casbin/casbin/v2/util"
	"strings"
)

const (
	notImplemented = "not implemented"
)

type Adapter struct {
	persist.BatchAdapter
	policy *string
}

func NewAdapter(policy *string) *Adapter {
	return &Adapter{
		policy: policy,
	}
}

func (sa *Adapter) LoadPolicy(model model.Model) error {
	if sa.policy == nil {
		return errors.New("not set line")
	}
	line := *(sa.policy)
	if line == "" {
		return nil
	}
	policies := strings.Split(line, "\n")
	for _, p := range policies {
		if p == "" {
			continue
		}
		persist.LoadPolicyLine(p, model)
	}
	return nil
}

func (sa *Adapter) SavePolicy(model model.Model) error {
	var tmp bytes.Buffer
	for pType, ast := range model["p"] {
		for _, rule := range ast.Policy {
			tmp.WriteString(pType + ", ")
			tmp.WriteString(util.ArrayToString(rule))
			tmp.WriteString("\n")
		}
	}
	for pType, ast := range model["g"] {
		for _, rule := range ast.Policy {
			tmp.WriteString(pType + ", ")
			tmp.WriteString(util.ArrayToString(rule))
			tmp.WriteString("\n")
		}
	}
	line := strings.TrimRight(tmp.String(), "\n")
	sa.policy = &line
	return nil
}

func (sa *Adapter) AddPolicy(sec string, ptype string, rule []string) error {
	return errors.New(notImplemented)
}

func (sa *Adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	return nil
}

func (sa *Adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	return errors.New(notImplemented)
}

func (sa *Adapter) AddPolicies(sec string, ptype string, rules [][]string) error {
	return errors.New(notImplemented)
}

func (sa *Adapter) RemovePolicies(sec string, ptype string, rules [][]string) error {
	return errors.New(notImplemented)
}
