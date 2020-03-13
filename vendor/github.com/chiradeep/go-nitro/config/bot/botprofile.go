package bot

type Botprofile struct {
	Builtin   interface{} `json:"builtin,omitempty"`
	Comment   string      `json:"comment,omitempty"`
	Errorurl  string      `json:"errorurl,omitempty"`
	Feature   string      `json:"feature,omitempty"`
	Name      string      `json:"name,omitempty"`
	Signature string      `json:"signature,omitempty"`
}
