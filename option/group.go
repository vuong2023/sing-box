package option

type GroupOutboundOptions struct {
	Outbounds       Listable[string] `json:"outbounds,omitempty"`
	Providers       Listable[string] `json:"providers,omitempty"`
	UseAllProviders bool             `json:"use_all_providers,omitempty"`
	Includes        Listable[string] `json:"includes,omitempty"`
	Excludes        string           `json:"excludes,omitempty"`
	Types           Listable[string] `json:"types,omitempty"`
}

type SelectorOutboundOptions struct {
	GroupOutboundOptions
	Default                   string `json:"default,omitempty"`
	InterruptExistConnections bool   `json:"interrupt_exist_connections,omitempty"`
}

type URLTestOutboundOptions struct {
	GroupOutboundOptions
	URL                       string   `json:"url,omitempty"`
	Interval                  Duration `json:"interval,omitempty"`
	Tolerance                 uint16   `json:"tolerance,omitempty"`
	IdleTimeout               Duration `json:"idle_timeout,omitempty"`
	InterruptExistConnections bool     `json:"interrupt_exist_connections,omitempty"`
}
