/*
Copyright 2022 Citrix Systems, Inc
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
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/citrix/adc-nitro-go/resource/config/analytics"
	"github.com/citrix/adc-nitro-go/resource/config/basic"
	"github.com/citrix/adc-nitro-go/resource/config/lb"
	"github.com/citrix/adc-nitro-go/resource/config/ns"
	"github.com/citrix/adc-nitro-go/resource/config/policy"
	netscaler "github.com/citrix/adc-nitro-go/service"
)

// LBMonitor specifies attributes associated with Outlier Detection feature
type LBMonitor struct {
	Retries       int    // consecutive[Gateway]Errors of Istio's Outlier Detection (OD)
	Interval      int    // interval of Istio's OD
	IntervalUnits string // Units of Interval field.
	DownTime      int    // baseEjectionTime of Istio's OD
	DownTimeUnits string // Units of DownTime
}

// StringMapBinding specifies stringmap and lb-vserver binding
type StringMapBinding struct {
	StringMapName string // Policy stringmap entity's name
	Key           string // Key field will correspond to key of policystringmap_pattern_binding Nitro resource
	Value         string // Value field will correspond to value of policystringmap_pattern_binding Nitro resource
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
	AutoScale                 bool // Whether desired state API can be used here or not
	StringMapBindingObj       *StringMapBinding
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

// This variable is a stop-gap way to disable functionality till LWCPX supports labels infra
var (
	labelsFuncEnabled = getBoolEnv("ENABLE_LABELS_FEATURE")
)

func getBoolEnv(key string) bool {
	value := os.Getenv(key)
	if value == "" {
		return false
	}
	ret, err := strconv.ParseBool(value)
	if err != nil {
		nsconfLogger.Error("getBoolEnv: Could not parse bool env var", "envvar", key)
		return false
	}
	return ret
}

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

// NewLBApi returns a new LBApi object
func NewLBApi(name string, frontendServiceType string, backendServiceType string, lbMethod string) *LBApi {
	lbObj := new(LBApi)
	lbObj.Name = name
	lbObj.FrontendServiceType = frontendServiceType
	lbObj.BackendServiceType = backendServiceType
	lbObj.LbMethod = lbMethod
	return lbObj
}

func isBuildDesiredStateAPICompatible() bool {
	nsReleaseNo, nsBuildNo := GetNsReleaseBuild()
	if nsReleaseNo >= 13.1 || (nsReleaseNo == 13.0 && nsBuildNo >= 45.8) {
		return true
	}
	return false
}

// Add method adds/updates an LB vserver and associated servicegroup on Citrix-ADC.
// It also adds httpprofile and http-inline monitor if needed.
func (lbObj *LBApi) Add(client *netscaler.NitroClient) error {
	nsconfLogger.Trace("LBApi add", "lbObj", GetLogString(lbObj))
	var sg map[string]interface{}
	confErr := newNitroError()
	lbInst := lb.Lbvserver{Name: lbObj.Name, Servicetype: lbObj.FrontendServiceType, Lbmethod: lbObj.LbMethod}
	confErr.updateError(doNitro(client, nitroConfig{netscaler.Lbvserver.Type(), lbObj.Name, lbInst, "add", "", "", ""}, nil, []nitroConfig{{netscaler.Lbvserver.Type(), lbObj.Name, nil, "delete", "", "", ""}, {netscaler.Lbvserver.Type(), lbObj.Name, lbInst, "add", "", "", ""}}))
	httpProfileName := "nshttp_default_profile"
	if lbObj.MaxHTTP2ConcurrentStreams != 0 {
		httpProfileName = "nshttp_profile_" + fmt.Sprint(lbObj.MaxHTTP2ConcurrentStreams)
		confErr.updateError(doNitro(client, nitroConfig{netscaler.Nshttpprofile.Type(), httpProfileName, ns.Nshttpprofile{Name: httpProfileName, Http2: "ENABLED", Http2maxconcurrentstreams: lbObj.MaxHTTP2ConcurrentStreams}, "add", "", "", ""}, nil, nil))
	}
	if isBuildDesiredStateAPICompatible() && lbObj.AutoScale == true { // set autoscale API servicegroup
		sg = map[string]interface{}{"servicegroupname": lbObj.Name, "servicetype": lbObj.BackendServiceType, "autoscale": "API", "maxclient": lbObj.MaxConnections, "maxreq": lbObj.MaxRequestsPerConnection, "usip": "NO"}
	} else {
		sg = map[string]interface{}{"servicegroupname": lbObj.Name, "servicetype": lbObj.BackendServiceType, "maxclient": lbObj.MaxConnections, "maxreq": lbObj.MaxRequestsPerConnection, "usip": "NO"}
	}
	if lbObj.BackendServiceType == "HTTP" {
		sg["httpprofilename"] = httpProfileName
	}
	if lbObj.NetprofileName != "" {
		sg["netprofile"] = lbObj.NetprofileName
	}
	//TODO copy all servicegroup members before deleting and readding with new type
	confErr.updateError(doNitro(client, nitroConfig{"servicegroup", lbObj.Name, sg, "add", "", "", ""}, nil, []nitroConfig{{"servicegroup", lbObj.Name, nil, "delete", "", "", ""}, {"servicegroup", lbObj.Name, sg, "add", "", "", ""}}))
	confErr.updateError(doNitro(client, nitroConfig{netscaler.Lbvserver_servicegroup_binding.Type(), lbObj.Name, lb.Lbvserverservicegroupbinding{Name: lbObj.Name, Servicegroupname: lbObj.Name}, "add", "", "", ""}, []string{"Resource already exists"}, nil))
	if lbObj.BackendServiceType == "SSL" || lbObj.BackendServiceType == "SSL_TCP" {
		addSSLServiceGroup(client, lbObj.Name, lbObj.BackendTLS, confErr)
	}
	// Creating LB Monitor for outlier detection purpose
	lbMonName := getLbMonName(lbObj.Name)
	if lbObj.LbMonitorObj == nil {
		// Remove HTTP-Inline LB monitor bound to servicegroup if outlier detection field is not passed in cluster resource
		confErr.updateError(doNitro(client, nitroConfig{netscaler.Servicegroup_lbmonitor_binding.Type(), lbObj.Name, map[string]string{"servicegroupname": lbObj.Name, "monitor_name": lbMonName}, "delete", "", "", ""}, []string{"No such resource"}, nil))
		confErr.updateError(doNitro(client, nitroConfig{netscaler.Lbmonitor.Type(), lbMonName, map[string]string{"monitorname": lbMonName, "type": "HTTP-INLINE"}, "delete", "", "", ""}, []string{"No such resource"}, nil))
	} else { // Adds lb monitor, and bind it to the servicegroup
		if lbObj.LbMonitorObj.Retries == 0 {
			lbObj.LbMonitorObj.Retries = defaultRetries
		}
		// Citrix ADC can have max value of 20940 and 20939 for Interval and Downtime resp. but it can accept various types for duration.
		// Convert the time to next level of unit in case time-value is more than max-allowed value.
		lbObj.LbMonitorObj.Interval, lbObj.LbMonitorObj.IntervalUnits = convertTimeUnits(lbObj.LbMonitorObj.Interval, lbObj.LbMonitorObj.IntervalUnits, maxInterval, defaultInterval)
		lbObj.LbMonitorObj.DownTime, lbObj.LbMonitorObj.DownTimeUnits = convertTimeUnits(lbObj.LbMonitorObj.DownTime, lbObj.LbMonitorObj.DownTimeUnits, maxDownTime, defaultDownTime)
		confErr.updateError(doNitro(client, nitroConfig{netscaler.Lbmonitor.Type(), lbMonName, lb.Lbmonitor{Monitorname: lbMonName, Type: "HTTP-INLINE", Action: "DOWN", Respcode: []string{"200"}, Httprequest: "HEAD /", Retries: lbObj.LbMonitorObj.Retries, Interval: lbObj.LbMonitorObj.Interval, Units2: lbObj.LbMonitorObj.IntervalUnits, Downtime: lbObj.LbMonitorObj.DownTime, Units3: lbObj.LbMonitorObj.DownTimeUnits}, "add", "", "", ""}, []string{"Resource already exists"}, nil))
		confErr.updateError(doNitro(client, nitroConfig{netscaler.Servicegroup_lbmonitor_binding.Type(), lbObj.Name, basic.Servicegrouplbmonitorbinding{Servicegroupname: lbObj.Name, Monitorname: lbMonName}, "add", "", "", ""}, []string{"The monitor is already bound to the service"}, nil))
	}
	// Add stringmap binding
	if lbObj.StringMapBindingObj != nil {
		confErr.updateError(doNitro(client, nitroConfig{netscaler.Policystringmap_pattern_binding.Type(), lbObj.StringMapBindingObj.StringMapName, policy.Policystringmappatternbinding{Name: lbObj.StringMapBindingObj.StringMapName, Key: lbObj.StringMapBindingObj.Key, Value: lbObj.StringMapBindingObj.Value}, "add", "", "", ""}, nil, nil))
	}
	return confErr.getError()
}

// Delete method deletes an LB vserver and associated servicegroup
func (lbObj *LBApi) Delete(client *netscaler.NitroClient) error {
	nsconfLogger.Trace("LBApi delete", "lbObj", lbObj)
	confErr := newNitroError()
	confErr.updateError(doNitro(client, nitroConfig{netscaler.Lbvserver.Type(), lbObj.Name, nil, "delete", "", "", ""}, nil,
		[]nitroConfig{{netscaler.Lbvserver.Type(), lbObj.Name, lb.Lbvserver{Name: lbObj.Name, Newname: lbObj.Name + "_stale"}, "rename", "", "", ""},
			{netscaler.Lbvserver.Type(), lbObj.Name, lb.Lbvserver{Name: lbObj.Name + "_stale"}, "disable", "", "", ""}}))
	/* Check if SSL ServiceGroup is present, then remove the cert binding */
	removeCertBindings(client, confErr, netscaler.Sslservicegroup.Type(), lbObj.Name, "servicegroupname", netscaler.Sslservicegroup_sslcertkey_binding.Type())
	/* Remove endpoint info for all servicegroup members */
	err := removeEpMetadataForSvcgrp(client, lbObj.Name)
	if err != nil {
		nsconfLogger.Debug("In LBApi delete: Error in removing endPoint metadata", "Servicegroup", lbObj.Name, "Error", err)
	}
	confErr.updateError(doNitro(client, nitroConfig{resourceType: netscaler.Servicegroup.Type(), resourceName: lbObj.Name, resource: nil, operation: "delete"}, nil, nil))
	// Get rid of HTTP-Inline lbmonitor also if present.
	lbMonName := getLbMonName(lbObj.Name)
	confErr.updateError(doNitro(client, nitroConfig{netscaler.Lbmonitor.Type(), lbMonName, map[string]string{"monitorname": lbMonName, "type": "HTTP-INLINE"}, "delete", "", "", ""}, []string{"No such resource"}, nil))
	// Get key of stringmapbinding
	if lbObj.StringMapBindingObj != nil {
		confErr.updateError(doNitro(client, nitroConfig{netscaler.Policystringmap.Type(), lbObj.StringMapBindingObj.StringMapName, nil, "unbind", "pattern", lbObj.StringMapBindingObj.Key, "key"}, nil, nil))
	}
	return confErr.getError()
}

// Metadata stores the labels & metadata info about servicegroupmembers. All svcgrpmembers will have same metadata
type Metadata struct {
	ClusterName string
	HostName    string
	SvcName     string
	Namespace   string
	LabelSubset string
}

// ServiceGroupMember is a way of specifying the ip/domain-name and port of each service endpoint associated with an LB vserver
// Weight assigned to a servicegroup member indicates the percentage of traffic that should be sent to that service
type ServiceGroupMember struct {
	IP     string
	Domain string
	Port   int
	Weight int
	// Metadata will be common for all IP-endpoints. So let it be part of ServiceGroupAPI
}

// ServiceGroupAPI specifies the ip:port members associated with an LB vserver on Citrix-ADC
type ServiceGroupAPI struct {
	Name             string
	Members          []ServiceGroupMember
	IsLogProxySvcGrp bool   // This field specifies if the current service is Citrix Observability exporter or not
	PromEP           string // Prometheus Endpoint
	// IsIPOnlySvcGroup field tells if servicegroup have only IPs as members.
	// If yes, autoScale API opetion will be set on svcgroup to use desiredState API
	IsIPOnlySvcGroup bool
	// Metadata will be common for all IP-endpoints.
	Metadata Metadata
}

// NewServiceGroupAPI returns a new ServiceGroupAPI object
func NewServiceGroupAPI(name string) *ServiceGroupAPI {
	svcGpObj := new(ServiceGroupAPI)
	svcGpObj.Name = name
	svcGpObj.IsLogProxySvcGrp = false
	svcGpObj.PromEP = ""
	svcGpObj.IsIPOnlySvcGroup = true // by default, mark this servicegroup for Desired State API usage
	return svcGpObj
}

func isLogProxyWorkingBuild() bool {
	nsReleaseNo, nsBuildNo := GetNsReleaseBuild()
	if nsReleaseNo >= 13.1 {
		return true
	}
	switch nsReleaseNo {
	case 13.0:
		if nsBuildNo >= 48.0 {
			return true
		}
		return false
	case 12.1:
		if nsBuildNo >= 56.0 {
			return true
		}
		return false
	}
	return false
}

// bindAnalyticsProfile method binds the analytics profile to logproxy (COE) servicegroup
func (svcGpObj *ServiceGroupAPI) bindAnalyticsProfile(client *netscaler.NitroClient, confErr *nitroError) error {
	// Check if the build is fine for this association or not
	if isLogProxyWorkingBuild() == false {
		return nil
	}
	/* Add HTTP and TCP analyticsprofile with collector */
	if svcGpObj.IsLogProxySvcGrp {
		nsconfLogger.Trace("bindAnalyticsProfile: Binding svcGroup as collector to analyticsprofile", "svcGroupName", svcGpObj.Name)
		confErr.updateError(doNitro(client, nitroConfig{"analyticsprofile", "ns_analytics_default_http_profile", analytics.Analyticsprofile{Name: "ns_analytics_default_http_profile", Type: "webinsight", Httpurl: "ENABLED", Httphost: "ENABLED", Httpmethod: "ENABLED", Httpuseragent: "ENABLED", Urlcategory: "ENABLED", Httpcontenttype: "ENABLED", Httpvia: "ENABLED", Httpdomainname: "ENABLED", Httpurlquery: "ENABLED", Collectors: svcGpObj.Name}, "add", "", "", ""}, nil, nil))
		confErr.updateError(doNitro(client, nitroConfig{"analyticsprofile", "ns_analytics_default_tcp_profile", analytics.Analyticsprofile{Name: "ns_analytics_default_tcp_profile", Type: "tcpinsight", Collectors: svcGpObj.Name}, "add", "", "", ""}, nil, nil))
	}
	/* Add Prometheus service and bind to timeseries analytics profile */
	if len(svcGpObj.PromEP) > 0 {
		nsconfLogger.Trace("bindAnalyticsProfile: Add prometheus service as a collector to ns_analytics_time_series_profile", "serviceName", svcGpObj.PromEP)
		if net.ParseIP(svcGpObj.PromEP) != nil { // Prometheus IP
			confErr.updateError(doNitro(client, nitroConfig{netscaler.Service.Type(), "ns_logproxy_prometheus_service", basic.Service{Name: "ns_logproxy_prometheus_service", Servicetype: "HTTP", Ipaddress: svcGpObj.PromEP, Port: 5563, Servername: svcGpObj.PromEP}, "add", "", "", ""}, nil, nil))
		} else { // Prometheus server name
			confErr.updateError(doNitro(client, nitroConfig{netscaler.Service.Type(), "ns_logproxy_prometheus_service", basic.Service{Name: "ns_logproxy_prometheus_service", Servicetype: "HTTP", Servername: svcGpObj.PromEP, Port: 5563}, "add", "", "", ""}, nil, nil))
		}
		confErr.updateError(doNitro(client, nitroConfig{"analyticsprofile", "ns_analytics_time_series_profile", analytics.Analyticsprofile{Name: "ns_analytics_time_series_profile", Type: "timeseries", Outputmode: "prometheus", Metrics: "ENABLED", Collectors: "ns_logproxy_prometheus_service"}, "add", "", "", ""}, nil, []nitroConfig{{netscaler.Service.Type(), "ns_logproxy_prometheus_service", nil, "delete", "", "", ""}}))
	}
	return nil
}

// Add method add/updates the servicegroup members
func (svcGpObj *ServiceGroupAPI) Add(client *netscaler.NitroClient) error {
	nsconfLogger.Trace("ServiceGroupAPI add", "svcGpObj", svcGpObj)
	var err error
	// Check the type of Service Group. whether autoscale
	if isBuildDesiredStateAPICompatible() && svcGpObj.IsIPOnlySvcGroup == true {
		err = svcGpObj.useDesiredStateAPI(client)
	} else {
		err = svcGpObj.useClassicAPI(client)
	}
	return err
}

func (svcGpObj *ServiceGroupAPI) useDesiredStateAPI(client *netscaler.NitroClient) error {
	nsconfLogger.Trace(" Using Desired State API for ServiceGroupAPI add", "svcGpObj", svcGpObj)
	confErr := newNitroError()
	// Retrieve existing Servicegroup details
	rsrc, err := client.FindResource("servicegroup", svcGpObj.Name)
	if err != nil {
		return confErr.getError()
	}
	// If existing service group is not set for Autoscale that means it must have at least one domain name earlier.
	// Deleting servicegroup and creating it again with Autoscale option is tricky. We lose lbvserver-servicegroup binding,
	// sslServicegroup bindings (such as certs), lb monitor bindings etc. Use Classic API as fallback mechanism.
	// TODO: Once ADC supports setting classic API to Autoscale API, make appropriate changes here.
	if rsrc["autoscale"] != "API" {
		nsconfLogger.Trace("useDesiredStateAPI: Servicegroup is created using Classic API. Falling back to using ClassicAPI for member bindings", "svcGroupName", svcGpObj.Name)
		return svcGpObj.useClassicAPI(client)
	}
	var ipmembers []basic.Members
	// Make an array of members
	for _, member := range svcGpObj.Members {
		ipmembers = append(ipmembers, basic.Members{Ip: member.IP, Port: member.Port, Weight: member.Weight})
		//addEndpointMetadata(client, member.IP, svcGpObj.Metadata)
	}
	// Update endpoint info for memberIPs (before changing membergroupbindings with desired state API)
	err = svcGpObj.updateEndpointMetadataForSvcGrp(client)
	if err != nil {
		nsconfLogger.Debug("useDesiredStateAPI: Error in adding endPoint metadata", "svcGpObj", svcGpObj.Name, "Error", err)
	}
	sgmembers := basic.Servicegroupservicegroupmemberlistbinding{Servicegroupname: svcGpObj.Name, Members: ipmembers}
	confErr.updateError(doNitro(client, nitroConfig{netscaler.Servicegroup_servicegroupmemberlist_binding.Type(), svcGpObj.Name, sgmembers, "add", "", "", ""}, []string{"Resource already exists"}, nil))
	svcGpObj.bindAnalyticsProfile(client, confErr)
	return confErr.getError()
}

func (svcGpObj *ServiceGroupAPI) useClassicAPI(client *netscaler.NitroClient) error {
	nsconfLogger.Trace(" Using Classic API for ServiceGroupAPI add", "svcGpObj", svcGpObj)
	var serverName string
	confErr := newNitroError()
	for _, member := range svcGpObj.Members {
		if member.Domain != "" {
			serverName = GetNSCompatibleName(member.Domain)
			confErr.updateError(doNitro(client, nitroConfig{netscaler.Server.Type(), serverName, basic.Server{Name: serverName, Domain: member.Domain, State: "ENABLED"}, "add", "", "", ""}, []string{"Invalid value [domain, value differs from existing entity and it cant be updated.]"}, nil))
			confErr.updateError(doNitro(client, nitroConfig{netscaler.Servicegroup_servicegroupmember_binding.Type(), svcGpObj.Name, basic.Servicegroupservicegroupmemberbinding{Servicegroupname: svcGpObj.Name, Servername: serverName, Port: member.Port}, "add", "", "", ""}, []string{"Resource already exists"}, nil))
		} else {
			confErr.updateError(doNitro(client, nitroConfig{netscaler.Servicegroup_servicegroupmember_binding.Type(), svcGpObj.Name, basic.Servicegroupservicegroupmemberbinding{Servicegroupname: svcGpObj.Name, Ip: member.IP, Port: member.Port}, "add", "", "", ""}, []string{"Resource already exists"}, nil))
			addEndpointMetadata(client, member.IP, svcGpObj.Metadata)
		}
	}
	/* get all bindings*/
	svcGpBindings, err := client.FindResourceArray(netscaler.Servicegroup_servicegroupmember_binding.Type(), svcGpObj.Name)
	if err != nil {
		confErr.updateError(err)
		return confErr.getError()
	}
	/*delete stale bindings*/
	for _, svcGpBinding := range svcGpBindings {
		if servernameVal, ok := svcGpBinding["servername"]; ok {
			if servername, ok := servernameVal.(string); ok {
				if portVal, ok := svcGpBinding["port"]; ok {
					if portF, ok := portVal.(float64); ok {
						port := int(portF)
						found := false
						update := false
						wt, _ := svcGpBinding["weight"].(int)
						for _, member := range svcGpObj.Members {
							if member.Port == port &&
								(member.IP == servername ||
									(member.Domain != "" && GetNSCompatibleName(member.Domain) == servername)) {
								found = true
								/* if the weight of current desired state of servicegroup member doesn't match with the previous weight assigned, then delete old binding and add the new binding */
								if wt != member.Weight {
									update = true
								}
								break
							}
						}
						if found == false || update == true {
							deleteBindingMap := map[string]string{"port": fmt.Sprint(port)}
							if net.ParseIP(servername) == nil {
								deleteBindingMap["servername"] = servername
							} else {
								deleteBindingMap["ip"] = servername
								if found == false {
									deleteEndpointMetadata(client, servername)
								}
							}
							confErr.updateError(doNitro(client, nitroConfig{netscaler.Servicegroup_binding.Type(), svcGpObj.Name, deleteBindingMap, "delete", "", "", ""}, nil, nil))
						}
						if update == true {
							if net.ParseIP(servername) == nil {
								confErr.updateError(doNitro(client, nitroConfig{netscaler.Servicegroup_servicegroupmember_binding.Type(), svcGpObj.Name, basic.Servicegroupservicegroupmemberbinding{Servicegroupname: svcGpObj.Name, Servername: servername, Port: port, Weight: wt}, "add", "", "", ""}, nil, nil))
							} else {
								confErr.updateError(doNitro(client, nitroConfig{netscaler.Servicegroup_servicegroupmember_binding.Type(), svcGpObj.Name, basic.Servicegroupservicegroupmemberbinding{Servicegroupname: svcGpObj.Name, Ip: servername, Port: port, Weight: wt}, "add", "", "", ""}, nil, nil))
							}
						}
					}
				}
			}
		}
	}
	if (len(svcGpObj.PromEP) > 0) && (net.ParseIP(svcGpObj.PromEP) == nil) && (len(serverName) > 0) { // Check if it is Domain Name
		svcGpObj.PromEP = serverName
	}
	svcGpObj.bindAnalyticsProfile(client, confErr)
	return confErr.getError()
}

// Nitro equivalent of `add endpoint info IP <IP> -endpointmetadata cluster.<md.Namespace>.service.<md.SvcName> -endpointlabelsJson {"subset":md.LabelSubset} `
func addEndpointMetadata(client *netscaler.NitroClient, endpointIP string, md Metadata) error {
	// Nitro is available from 13.1 only
	if (curBuild.release < 13.1) || (labelsFuncEnabled == false) {
		return nil
	}
	//confErr := newNitroError()
	if md.SvcName != "" {
		// Kubernetes service can't start with number and can't have `.` in it. But serviceentries can be created for domain-names like www.citrix.com.
		// So GetNameWithoutPeriod will convert serviceentry name having periods to "_"
		// Q4 qualifier is node and xds-control plane doesn't provide this info. So it is marked as *
		mData := md.ClusterName + "." + md.Namespace + "." + GetNameWithQuotedPeriod(md.SvcName) + ".*." + GetNameWithQuotedPeriod(md.HostName) + ".*"
		labelJSON := ""
		if md.LabelSubset != "" {
			labelJSON = "{\"subset\":\"" + md.LabelSubset + "+\"}"
			return doNitro(client, nitroConfig{"endpointinfo", "IP", map[string]interface{}{"endpointkind": "IP", "endpointname": endpointIP, "endpointmetadata": mData, "endpointlabelsjson": labelJSON}, "add", "", "", ""}, nil, nil)
		} else {
			return doNitro(client, nitroConfig{"endpointinfo", "IP", map[string]interface{}{"endpointkind": "IP", "endpointname": endpointIP, "endpointmetadata": mData}, "add", "", "", ""}, nil, nil)
		}
	}
	return nil
}

// Nitro equivalent of `rm endpoint info IP <IP>`
func deleteEndpointMetadata(client *netscaler.NitroClient, endpointIP string) error {
	if (curBuild.release < 13.1) || (labelsFuncEnabled == false) {
		return nil
	}
	return doNitro(client, nitroConfig{"endpointinfo", "IP", map[string]string{"endpointkind": "IP", "endpointname": endpointIP}, "delete", "", "", ""}, nil, nil)
}

// removeEpMetadataForSvcgrp removes all endpoint metadata added for given svcGrpName's members.
func removeEpMetadataForSvcgrp(client *netscaler.NitroClient, svcGrpName string) error {
	if (curBuild.release < 13.1) || (labelsFuncEnabled == false) {
		return nil
	}
	confErr := newNitroError()
	/* get all bindings*/
	svcGpBindings, err := client.FindResourceArray(netscaler.Servicegroup_servicegroupmember_binding.Type(), svcGrpName)
	if err != nil {
		confErr.updateError(err)
		return confErr.getError()
	}
	/* delete all svcgroupmembers from endpoints */
	for _, svcGpBinding := range svcGpBindings {
		if servernameVal, ok := svcGpBinding["servername"]; ok {
			endpointIP := servernameVal.(string)
			// TODO: Can insert a check for validating servername is IP or not. But nitro call would anyway return error (ERROR: Invalid IP address)
			confErr.updateError(doNitro(client, nitroConfig{"endpointinfo", "IP", map[string]string{"endpointkind": "IP", "endpointname": endpointIP}, "delete", "", "", ""}, []string{"Invalid IP address"}, nil))
		}
	}
	return confErr.getError()
}

// updateEndpointMetadataForSvcGrp deletes old members' metadata and adds new members' metadata
func (svcGpObj *ServiceGroupAPI) updateEndpointMetadataForSvcGrp(client *netscaler.NitroClient) error {
	if (curBuild.release < 13.1) || (labelsFuncEnabled == false) {
		return nil
	}
	// Construct a boolean map to track which all endpoints are added
	epAdded := map[string]bool{}
	for _, member := range svcGpObj.Members {
		epAdded[member.IP] = false
	}
	confErr := newNitroError()
	resAbsentMsg := fmt.Sprintf("No resource %s of type servicegroup_servicegroupmember_binding found", svcGpObj.Name)
	firstTime := false
	/* get all existing bindings of servicegroup */
	svcGpBindings, err := client.FindResourceArray(netscaler.Servicegroup_servicegroupmember_binding.Type(), svcGpObj.Name)
	if err != nil {
		if strings.Contains(err.Error(), resAbsentMsg) {
			firstTime = true // It indicates that there is no servicegroupmember created so far
		} else {
			confErr.updateError(err)
			return confErr.getError()
		}
	}
	/* Delete removed member's metadata and update epAdded map */
	if firstTime == false { //
		for _, svcGpBinding := range svcGpBindings {
			if servernameVal, ok := svcGpBinding["servername"]; ok {
				endpointIP := servernameVal.(string)
				if _, ok = epAdded[endpointIP]; ok { // This endpointIP is not stale and already present
					epAdded[endpointIP] = true
				} else { // delete this endpointIP metadata
					confErr.updateError(doNitro(client, nitroConfig{"endpointinfo", "IP", map[string]string{"endpointkind": "IP", "endpointname": endpointIP}, "delete", "", "", ""}, []string{"Invalid IP address"}, nil))
				}
			}
		}
	}
	/* Now add endpoint metadata for new IPs */
	for eip, flag := range epAdded {
		if flag == false {
			confErr.updateError(addEndpointMetadata(client, eip, svcGpObj.Metadata))
		}
	}
	return confErr.getError()
}
