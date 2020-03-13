package contentinspection

type Contentinspectioncallout struct {
	Comment     string `json:"comment,omitempty"`
	Hits        int    `json:"hits,omitempty"`
	Name        string `json:"name,omitempty"`
	Profilename string `json:"profilename,omitempty"`
	Resultexpr  string `json:"resultexpr,omitempty"`
	Returntype  string `json:"returntype,omitempty"`
	Serverip    string `json:"serverip,omitempty"`
	Servername  string `json:"servername,omitempty"`
	Serverport  int    `json:"serverport,omitempty"`
	Type        string `json:"type,omitempty"`
	Undefhits   int    `json:"undefhits,omitempty"`
	Undefreason string `json:"undefreason,omitempty"`
}
