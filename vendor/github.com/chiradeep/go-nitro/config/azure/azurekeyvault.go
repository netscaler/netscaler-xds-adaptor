package azure

type Azurekeyvault struct {
	Azureapplication string `json:"azureapplication,omitempty"`
	Azurevaultname   string `json:"azurevaultname,omitempty"`
	Name             string `json:"name,omitempty"`
	State            string `json:"state,omitempty"`
}
