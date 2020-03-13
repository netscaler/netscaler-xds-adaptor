package azure

type Azureapplication struct {
	Clientid      string `json:"clientid,omitempty"`
	Clientsecret  string `json:"clientsecret,omitempty"`
	Name          string `json:"name,omitempty"`
	Tenantid      string `json:"tenantid,omitempty"`
	Tokenendpoint string `json:"tokenendpoint,omitempty"`
}
