package sc

type Scparameter struct {
	Builtin     interface{} `json:"builtin,omitempty"`
	Feature     string      `json:"feature,omitempty"`
	Sessionlife int         `json:"sessionlife,omitempty"`
	Vsr         string      `json:"vsr,omitempty"`
}
