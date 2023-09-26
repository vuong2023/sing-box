package proxyprovider

import (
	"regexp"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

type Filter struct {
	whiteMode bool
	rules     []*regexp.Regexp
}

func NewFilter(f *option.ProxyProviderFilter) (*Filter, error) {
	ff := &Filter{
		whiteMode: f.WhiteMode,
	}
	var rules []*regexp.Regexp
	if f.Rules != nil && len(f.Rules) > 0 {
		for _, rule := range f.Rules {
			re, err := regexp.Compile(rule)
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
			for _, rule := range f.rules {
				if f.whiteMode {
					if rule.MatchString(s) {
						newList = append(newList, s)
					}
				} else {
					if !rule.MatchString(s) {
						newList = append(newList, s)
					}
				}
			}
		}
		return newList
	}
	return list
}
