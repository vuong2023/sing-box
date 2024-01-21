package outbound

import (
	"context"
	"regexp"

	"github.com/sagernet/sing-box/adapter"
)

type myGroupAdapter struct {
	ctx             context.Context
	tags            []string
	uses            []string
	useAllProviders bool
	includes        []string
	excludes        string
	types           []string
	providers       map[string]adapter.OutboundProvider
}

func (s *myGroupAdapter) OutboundFilter(outbound adapter.Outbound) bool {
	tag := outbound.Tag()
	oType := outbound.Type()
	return s.TestIncludes(tag) && s.TestExcludes(tag) && s.TestTypes(oType)
}

func (s *myGroupAdapter) TestIncludes(tag string) bool {
	for _, filter := range s.includes {
		reg := regexp.MustCompile("(?i)" + filter)
		if len(reg.FindStringIndex(tag)) == 0 {
			return false
		}
	}
	return true
}

func (s *myGroupAdapter) TestExcludes(tag string) bool {
	filter := s.excludes
	if filter == "" {
		return true
	}
	reg := regexp.MustCompile("(?i)" + filter)
	return len(reg.FindStringIndex(tag)) == 0
}

func (s *myGroupAdapter) TestTypes(oType string) bool {
	if len(s.types) == 0 {
		return true
	}
	for _, iType := range s.types {
		if oType == iType {
			return true
		}
	}
	return false
}
