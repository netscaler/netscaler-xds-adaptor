package bot

type Botsettings struct {
	Defaultprofile    string `json:"defaultprofile,omitempty"`
	Dfprequestlimit   int    `json:"dfprequestlimit,omitempty"`
	Javascriptname    string `json:"javascriptname,omitempty"`
	Sessioncookiename string `json:"sessioncookiename,omitempty"`
	Sessiontimeout    int    `json:"sessiontimeout,omitempty"`
}
