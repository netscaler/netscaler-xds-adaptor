package vpn

type Vpnsessionpolicy struct {
	Action         string      `json:"action,omitempty"`
	Builtin        interface{} `json:"builtin,omitempty"`
	Expressiontype string      `json:"expressiontype,omitempty"`
	Feature        string      `json:"feature,omitempty"`
	Hits           int         `json:"hits,omitempty"`
	Name           string      `json:"name,omitempty"`
	Rule           string      `json:"rule,omitempty"`
}
