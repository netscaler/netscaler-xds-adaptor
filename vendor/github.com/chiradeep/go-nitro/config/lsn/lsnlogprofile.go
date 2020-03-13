package lsn

type Lsnlogprofile struct {
	Analyticsprofile string `json:"analyticsprofile,omitempty"`
	Logcompact       string `json:"logcompact,omitempty"`
	Logipfix         string `json:"logipfix,omitempty"`
	Logprofilename   string `json:"logprofilename,omitempty"`
	Logsessdeletion  string `json:"logsessdeletion,omitempty"`
	Logsubscrinfo    string `json:"logsubscrinfo,omitempty"`
}
