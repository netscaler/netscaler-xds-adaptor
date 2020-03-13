package feo

type Feoparameter struct {
	Builtin            interface{} `json:"builtin,omitempty"`
	Cssinlinethressize int         `json:"cssinlinethressize,omitempty"`
	Feature            string      `json:"feature,omitempty"`
	Imginlinethressize int         `json:"imginlinethressize,omitempty"`
	Jpegqualitypercent int         `json:"jpegqualitypercent,omitempty"`
	Jsinlinethressize  int         `json:"jsinlinethressize,omitempty"`
}
