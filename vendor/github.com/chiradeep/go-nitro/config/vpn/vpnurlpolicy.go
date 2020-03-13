package vpn

type Vpnurlpolicy struct {
	Action    string      `json:"action,omitempty"`
	Builtin   interface{} `json:"builtin,omitempty"`
	Comment   string      `json:"comment,omitempty"`
	Logaction string      `json:"logaction,omitempty"`
	Name      string      `json:"name,omitempty"`
	Newname   string      `json:"newname,omitempty"`
	Rule      string      `json:"rule,omitempty"`
	Undefhits int         `json:"undefhits,omitempty"`
}
