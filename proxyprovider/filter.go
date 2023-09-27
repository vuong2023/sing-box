package proxyprovider

import (
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/dlclark/regexp2"
)

type Filter struct {
	whiteMode bool
	rules     []*regexp2.Regexp
}

func NewFilter(f *option.ProxyProviderFilter) (*Filter, error) {
	ff := &Filter{
		whiteMode: f.WhiteMode,
	}
	var rules []*regexp2.Regexp
	if f.Rules != nil && len(f.Rules) > 0 {
		for _, rule := range f.Rules {
			re, err := regexp2.Compile(rule, regexp2.RE2)
			if err != nil {
				return nil, E.Cause(err, "invalid rule: ", rule)
			}
			rules = append(rules, re)
		}
	}
	if len(rules) > 0 {
		ff.rules = rules
	}
	return ff, nil
}

func (f *Filter) Filter(list []string) []string {
	if f.rules != nil && len(f.rules) > 0 {
		newList := make([]string, 0, len(list))
		for _, s := range list {
			match := false
			for _, rule := range f.rules {
				ok, err := rule.MatchString(s)
				if err == nil && ok {
					match = true
					break
				}
			}
			if f.whiteMode {
				if match {
					newList = append(newList, s)
				}
			} else {
				if !match {
					newList = append(newList, s)
				}
			}
		}
		return newList
	}
	return list
}
