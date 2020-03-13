package lsn

type Lsnappsattributes struct {
	Name              string `json:"name,omitempty"`
	Port              string `json:"port,omitempty"`
	Sessiontimeout    int    `json:"sessiontimeout,omitempty"`
	Transportprotocol string `json:"transportprotocol,omitempty"`
}
