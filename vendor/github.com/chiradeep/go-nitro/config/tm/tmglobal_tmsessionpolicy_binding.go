package tm

type Tmglobaltmsessionpolicybinding struct {
	Bindpolicytype         int         `json:"bindpolicytype,omitempty"`
	Builtin                interface{} `json:"builtin,omitempty"`
	Feature                string      `json:"feature,omitempty"`
	Gotopriorityexpression string      `json:"gotopriorityexpression,omitempty"`
	Policyname             string      `json:"policyname,omitempty"`
	Priority               int         `json:"priority,omitempty"`
}
