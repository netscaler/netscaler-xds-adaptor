package authentication

type Authenticationadfsproxyprofile struct {
	Adfstruststatus string `json:"adfstruststatus,omitempty"`
	Certkeyname     string `json:"certkeyname,omitempty"`
	Name            string `json:"name,omitempty"`
	Password        string `json:"password,omitempty"`
	Serverurl       string `json:"serverurl,omitempty"`
	Username        string `json:"username,omitempty"`
}
