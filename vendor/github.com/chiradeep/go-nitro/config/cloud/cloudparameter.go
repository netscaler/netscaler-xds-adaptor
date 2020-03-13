package cloud

type Cloudparameter struct {
	Activationcode          string `json:"activationcode,omitempty"`
	Connectorresidence      string `json:"connectorresidence,omitempty"`
	Controlconnectionstatus string `json:"controlconnectionstatus,omitempty"`
	Controllerfqdn          string `json:"controllerfqdn,omitempty"`
	Controllerport          int    `json:"controllerport,omitempty"`
	Customerid              string `json:"customerid,omitempty"`
	Deployment              string `json:"deployment,omitempty"`
	Instanceid              string `json:"instanceid,omitempty"`
	Resourcelocation        string `json:"resourcelocation,omitempty"`
}
