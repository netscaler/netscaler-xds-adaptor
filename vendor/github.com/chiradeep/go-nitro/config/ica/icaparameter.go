package ica

type Icaparameter struct {
	Builtin              interface{} `json:"builtin,omitempty"`
	Enablesronhafailover string      `json:"enablesronhafailover,omitempty"`
	Hdxinsightnonnsap    string      `json:"hdxinsightnonnsap,omitempty"`
}
