/*
Copyright 2019 Citrix Systems, Inc
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package nsconfigengine

import (
	"fmt"
	"github.com/chiradeep/go-nitro/config/basic"
	"github.com/chiradeep/go-nitro/config/lb"
	"github.com/chiradeep/go-nitro/config/ns"
	"github.com/chiradeep/go-nitro/netscaler"
	"log"
	"net"
	"strings"
)

// LBMonitor specifies attributes associated with Outlier Detection feature
type LBMonitor struct {
	Retries       int    // consecutive[Gateway]Errors of Istio's Outlier Detection (OD)
	Interval      int    // interval of Istio's OD
	IntervalUnits string // Units of Interval field.
	DownTime      int    // baseEjectionTime of Istio's OD
	DownTimeUnits string // Units of DownTime
}

// LBApi specifies the attributes associated with a load balancng entity on the Citrix-ADC
type LBApi struct {
	Name                      string
	FrontendServiceType       string
	LbMethod                  string
	BackendServiceType        string
	MaxConnections            int
	MaxHTTP2ConcurrentStreams int
	MaxRequestsPerConnection  int
	NetprofileName            string
	BackendTLS                []SSLSpec
	LbMonitorObj              *LBMonitor
}

// NewLBApi returns a new LBApi object
func NewLBApi(name string, frontendServiceType string, backendServiceType string, lbMethod string) *LBApi {
	lbObj := new(LBApi)
	lbObj.Name = name
	lbObj.FrontendServiceType = frontendServiceType
	lbObj.BackendServiceType = backendServiceType
	lbObj.LbMethod = lbMethod
	return lbObj
}

type timeUnit int

// MSEC, SEC and MIN represents milliseconds, seconds and minutes.
const (
	MSEC timeUnit = iota
	SEC
	MIN
	maxInterval     = 20940
	maxDownTime     = 20939
	defaultInterval = 5 // in seconds
	defaultDownTime = 30
	defaultRetries  = 1
)

func (t timeUnit) String() string {
	return [...]string{"MSEC", "SEC", "MIN"}[t]
}

func (t timeUnit) ToNextLevel() int {
	return [...]int{1000, 60, 60}[t]
}

// getLbMonName function gives the shortened name for lb monitor if entityName length is more than 56 chars
// LB monitor can max be 63 chars long!
func getLbMonName(entityName string) string {
	name := entityName + "_lbmon"
	if len(name) > 63 {
		s := strings.Split(name, "_")
		name = strings.Join([]string{s[2], s[3], s[4], "lbmon"}, "_")
	}
	return name
}

// convertTimeUnits function converts msec to sec or min if the value is more than maxLimit.
// inUnit should not be minutes (MIN)
func convertTimeUnits(inTime int, inUnit string, maxLimit int, defaultValue int) (int, string) {
	var outTime int
	var outUnit timeUnit

	if inTime == 0 || inUnit == "" {
		return defaultValue, "SEC" // default value in always seconds
	}

	var units = map[string]timeUnit{
		"MSEC": MSEC,
		"SEC":  SEC,
		"MIN":  MIN,
	}

	inUnitIdx := units[inUnit]
	for outUnit, outTime = inUnitIdx, inTime; outUnit <= MIN; outUnit++ {
		if outTime > maxLimit && outUnit != MIN {
			outTime = outTime / outUnit.ToNextLevel()
		} else {
			if outTime > maxLimit { // At this stage, it means unit is definitely MIN
				outTime = maxLimit
			}
			break
		}
	}
	return outTime, outUnit.String()
}

// Add method adds/updates an LB vserver and associated servicegroup on Citrix-ADC.
// It also adds httpprofile and http-inline monitor if needed.
func (lbObj *LBApi) Add(client *netscaler.NitroClient) error {
	log.Printf("[TRACE] LBApi add: %v", lbObj)
	confErr := newNitroError()
	confErr.updateError(doNitro(client, nitroConfig{netscaler.Lbvserver.Type(), lbObj.Name, lb.Lbvserver{Name: lbObj.Name, Servicetype: lbObj.FrontendServiceType, Lbmethod: lbObj.LbMethod}, "add"}, nil, nil))
	httpProfileName := "nshttp_default_profile"
	if lbObj.MaxHTTP2ConcurrentStreams != 0 {
		httpProfileName = "nshttp_profile_" + fmt.Sprint(lbObj.MaxHTTP2ConcurrentStreams)
		confErr.updateError(doNitro(client, nitroConfig{netscaler.Nshttpprofile.Type(), httpProfileName, ns.Nshttpprofile{Name: httpProfileName, Http2: "ENABLED", Http2maxconcurrentstreams: lbObj.MaxHTTP2ConcurrentStreams}, "add"}, nil, nil))
	}
	sg := map[string]interface{}{"servicegroupname": lbObj.Name, "servicetype": lbObj.BackendServiceType, "maxclient": lbObj.MaxConnections, "maxreq": lbObj.MaxRequestsPerConnection, "usip": "NO"}
	if lbObj.BackendServiceType == "HTTP" {
		sg["httpprofilename"] = httpProfileName
	}
	if lbObj.NetprofileName != "" {
		sg["netprofile"] = lbObj.NetprofileName
	}
	//TODO copy all servicegroup members before deleting and readding with new type
	confErr.updateError(doNitro(client, nitroConfig{"servicegroup", lbObj.Name, sg, "add"}, nil, []nitroConfig{{"servicegroup", lbObj.Name, nil, "delete"}, {"servicegroup", lbObj.Name, sg, "add"}}))
	confErr.updateError(doNitro(client, nitroConfig{netscaler.Lbvserver_servicegroup_binding.Type(), lbObj.Name, lb.Lbvserverservicegroupbinding{Name: lbObj.Name, Servicegroupname: lbObj.Name}, "add"}, []string{"Resource already exists"}, nil))
	if lbObj.BackendServiceType == "SSL" || lbObj.BackendServiceType == "SSL_TCP" {
		addSSLServiceGroup(client, lbObj.Name, lbObj.BackendTLS, confErr)
	}
	// Creating LB Monitor for outlier detection purpose
	lbMonName := getLbMonName(lbObj.Name)
	if lbObj.LbMonitorObj == nil {
		// Remove HTTP-Inline LB monitor bound to servicegroup if outlier detection field is not passed in cluster resource
		confErr.updateError(doNitro(client, nitroConfig{netscaler.Servicegroup_lbmonitor_binding.Type(), lbObj.Name, map[string]string{"servicegroupname": lbObj.Name, "monitor_name": lbMonName}, "delete"}, []string{"No such resource"}, nil))
		confErr.updateError(doNitro(client, nitroConfig{netscaler.Lbmonitor.Type(), lbMonName, map[string]string{"monitorname": lbMonName, "type": "HTTP-INLINE"}, "delete"}, []string{"No such resource"}, nil))
	} else { // Adds lb monitor, and bind it to the servicegroup
		if lbObj.LbMonitorObj.Retries == 0 {
			lbObj.LbMonitorObj.Retries = defaultRetries
		}
		// Citrix ADC can have max value of 20940 and 20939 for Interval and Downtime resp. but it can accept various types for duration.
		// Convert the time to next level of unit in case time-value is more than max-allowed value.
		lbObj.LbMonitorObj.Interval, lbObj.LbMonitorObj.IntervalUnits = convertTimeUnits(lbObj.LbMonitorObj.Interval, lbObj.LbMonitorObj.IntervalUnits, maxInterval, defaultInterval)
		lbObj.LbMonitorObj.DownTime, lbObj.LbMonitorObj.DownTimeUnits = convertTimeUnits(lbObj.LbMonitorObj.DownTime, lbObj.LbMonitorObj.DownTimeUnits, maxDownTime, defaultDownTime)
		confErr.updateError(doNitro(client, nitroConfig{netscaler.Lbmonitor.Type(), lbMonName, lb.Lbmonitor{Monitorname: lbMonName, Type: "HTTP-INLINE", Action: "DOWN", Respcode: []int{200}, Httprequest: "HEAD /", Retries: lbObj.LbMonitorObj.Retries, Interval: lbObj.LbMonitorObj.Interval, Units2: lbObj.LbMonitorObj.IntervalUnits, Downtime: lbObj.LbMonitorObj.DownTime, Units3: lbObj.LbMonitorObj.DownTimeUnits}, "add"}, []string{"Resource already exists"}, nil))
		confErr.updateError(doNitro(client, nitroConfig{netscaler.Servicegroup_lbmonitor_binding.Type(), lbObj.Name, basic.Servicegrouplbmonitorbinding{Servicegroupname: lbObj.Name, Monitorname: lbMonName}, "add"}, []string{"The monitor is already bound to the service"}, nil))
	}
	return confErr.getError()
}

// Delete method deletes an LB vserver and associated servicegroup
func (lbObj *LBApi) Delete(client *netscaler.NitroClient) error {
	log.Printf("[TRACE] LBApi delete: %v", lbObj)
	confErr := newNitroError()
	confErr.updateError(doNitro(client, nitroConfig{netscaler.Lbvserver.Type(), lbObj.Name, nil, "delete"}, nil,
		[]nitroConfig{{netscaler.Lbvserver.Type(), lbObj.Name, lb.Lbvserver{Name: lbObj.Name, Newname: lbObj.Name + "_stale"}, "rename"},
			{netscaler.Lbvserver.Type(), lbObj.Name, lb.Lbvserver{Name: lbObj.Name + "_stale"}, "disable"}}))
	confErr.updateError(doNitro(client, nitroConfig{netscaler.Servicegroup.Type(), lbObj.Name, nil, "delete"}, nil, nil))
	// Get rid of HTTP-Inline lbmonitor also if present.
	lbMonName := getLbMonName(lbObj.Name)
	confErr.updateError(doNitro(client, nitroConfig{netscaler.Lbmonitor.Type(), lbMonName, map[string]string{"monitorname": lbMonName, "type": "HTTP-INLINE"}, "delete"}, []string{"No such resource"}, nil))
	return confErr.getError()
}

// ServiceGroupMember is a way of specifying the ip/domain-name and port of each service endpoint associayted with an LB vserver
type ServiceGroupMember struct {
	IP     string
	Domain string
	Port   int
}

// ServiceGroupAPI specifies the ip:port members associated with an LB vserver on Citrix-ADC
type ServiceGroupAPI struct {
	Name    string
	Members []ServiceGroupMember
}

// NewServiceGroupAPI returns a new ServiceGroupAPI object
func NewServiceGroupAPI(name string) *ServiceGroupAPI {
	svcGpObj := new(ServiceGroupAPI)
	svcGpObj.Name = name
	return svcGpObj
}

// Add method add/updates the servicegroup members
func (svcGpObj *ServiceGroupAPI) Add(client *netscaler.NitroClient) error {
	log.Printf("[TRACE] ServiceGroupAPI add: %v", svcGpObj)
	confErr := newNitroError()
	for _, member := range svcGpObj.Members {
		if member.Domain != "" {
			serverName := GetNSCompatibleName(member.Domain)
			confErr.updateError(doNitro(client, nitroConfig{netscaler.Server.Type(), serverName, basic.Server{Name: serverName, Domain: member.Domain, State: "ENABLED"}, "add"}, []string{"Invalid value [domain, value differs from existing entity and it cant be updated.]"}, nil))
			confErr.updateError(doNitro(client, nitroConfig{netscaler.Servicegroup_servicegroupmember_binding.Type(), svcGpObj.Name, basic.Servicegroupservicegroupmemberbinding{Servicegroupname: svcGpObj.Name, Servername: serverName, Port: member.Port}, "add"}, []string{"Resource already exists"}, nil))
		} else {
			confErr.updateError(doNitro(client, nitroConfig{netscaler.Servicegroup_servicegroupmember_binding.Type(), svcGpObj.Name, basic.Servicegroupservicegroupmemberbinding{Servicegroupname: svcGpObj.Name, Ip: member.IP, Port: member.Port}, "add"}, []string{"Resource already exists"}, nil))
		}
	}
	/* get all bindings*/
	svcGpBindings, err := client.FindResourceArray(netscaler.Servicegroup_servicegroupmember_binding.Type(), svcGpObj.Name)
	if err != nil {
		confErr.updateError(err)
		return confErr.getError()
	}
	/*delete state bindings*/
	for _, svcGpBinding := range svcGpBindings {
		if servernameVal, ok := svcGpBinding["servername"]; ok {
			if servername, ok := servernameVal.(string); ok {
				if portVal, ok := svcGpBinding["port"]; ok {
					if portF, ok := portVal.(float64); ok {
						port := int(portF)
						found := false
						for _, member := range svcGpObj.Members {
							if member.Port == port &&
								(member.IP == servername ||
									(member.Domain != "" && GetNSCompatibleName(member.Domain) == servername)) {
								found = true
								break
							}
						}
						if found == false {
							deleteBindingMap := map[string]string{"port": fmt.Sprint(port)}
							if net.ParseIP(servername) == nil {
								deleteBindingMap["servername"] = servername
							} else {
								deleteBindingMap["ip"] = servername
							}
							confErr.updateError(doNitro(client, nitroConfig{netscaler.Servicegroup_binding.Type(), svcGpObj.Name, deleteBindingMap, "delete"}, nil, nil))
						}
					}
				}
			}
		}
	}
	return confErr.getError()
}
