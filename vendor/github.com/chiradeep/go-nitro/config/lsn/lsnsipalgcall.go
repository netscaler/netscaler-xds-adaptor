package lsn

type Lsnsipalgcall struct {
	Callflags    int    `json:"callflags,omitempty"`
	Callid       string `json:"callid,omitempty"`
	Callrefcount int    `json:"callrefcount,omitempty"`
	Calltimer    int    `json:"calltimer,omitempty"`
	Nodeid       int    `json:"nodeid,omitempty"`
	Xlatip       string `json:"xlatip,omitempty"`
}
