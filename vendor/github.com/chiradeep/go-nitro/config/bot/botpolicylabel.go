package bot

type Botpolicylabel struct {
	Comment   string `json:"comment,omitempty"`
	Hits      int    `json:"hits,omitempty"`
	Labelname string `json:"labelname,omitempty"`
	Newname   string `json:"newname,omitempty"`
	Numpol    int    `json:"numpol,omitempty"`
}
