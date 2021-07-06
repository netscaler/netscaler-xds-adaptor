/*
Copyright 2020 Citrix Systems, Inc
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

package adsclient

import (
	"citrix-xds-adaptor/nsconfigengine"
	"container/list"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/citrix/adc-nitro-go/resource/config/analytics"
	"github.com/citrix/adc-nitro-go/resource/config/basic"
	"github.com/citrix/adc-nitro-go/resource/config/dns"
	"github.com/citrix/adc-nitro-go/resource/config/lb"
	"github.com/citrix/adc-nitro-go/resource/config/network"
	"github.com/citrix/adc-nitro-go/resource/config/ns"
	"github.com/citrix/adc-nitro-go/resource/config/policy"
	"github.com/citrix/adc-nitro-go/resource/config/responder"
	"github.com/citrix/adc-nitro-go/resource/config/ssl"
	"github.com/citrix/adc-nitro-go/resource/config/tm"
	netscaler "github.com/citrix/adc-nitro-go/service"
)

type discoveryType int

const (
	cdsAdd discoveryType = iota
	cdsDel
	ldsAdd
	ldsDel
	edsAdd
	rdsAdd
	//MSS for setting various tcp profiles
	MSS = 1410
)

type configBlock struct {
	configType   discoveryType
	resourceName string
	resource     interface{}
}

type configAdaptor struct {
	adsServerPort     string
	client            *netscaler.NitroClient
	nsip              string
	mux               sync.Mutex
	configs           *list.List
	cdsHash           map[string]*list.Element
	edsHash           map[string]*list.Element
	ldsHash           map[string]*list.Element
	rdsHash           map[string]*list.Element
	watch             *Watcher
	quit              chan bool
	vserverIP         string
	netProfile        string
	analyticsServerIP string
	licenseServerIP   string
	logProxyURL       string
	analyticsProfiles []string // Two analyticspofile needed. One for TCP Insight, one for Web Insight
	localHostVIP      string
	caServerPort      string
}

var (
	multiClusterIngress    = getBoolEnv("MULTICLUSTER_INGRESS")
	multiClusterStringMap  = "multiClusterStringMap"
	multiClusterExpression = "multiClusterExpression"
	multiClusterPolExprStr = os.Getenv("MULTICLUSTER_SVC_DOMAIN") //".global"
	multiClusterListenPort = getIntEnv("MULTICLUSTER_LISTENER_PORT")
	coeTracingEnabled      = getBoolEnv("COE_TRACING") // Either COE or ADM can be endpoint for collecting tracing data
)

func getBoolEnv(key string) bool {
	value := os.Getenv(key)
	if value == "" {
		return false
	}
	ret, err := strconv.ParseBool(value)
	if err != nil {
		xDSLogger.Error("getBoolEnv: Could not parse bool env var", "envvar", key)
		return false
	}
	return ret
}

func getIntEnv(key string) int {
	value := os.Getenv(key)
	if value == "" {
		return -1
	}
	ret, err := strconv.Atoi(value)
	if err != nil {
		xDSLogger.Error("getIntEnv: Could not parse int env var", "envvar", key)
		return -1
	}
	return ret
}

// Check if the given ADC is CPX or VPX/MPX
func isCPX(url string) bool {
	if strings.Contains(url, "localhost") || strings.Contains(url, localHostIP) {
		return true
	}
	return false
}

func newConfigAdaptor(nsinfo *NSDetails) (*configAdaptor, error) {
	configAdaptor := new(configAdaptor)
	configAdaptor.adsServerPort = nsinfo.adsServerPort
	configAdaptor.vserverIP = nsinfo.NetscalerVIP
	configAdaptor.netProfile = nsinfo.NetProfile
	configAdaptor.configs = list.New()
	configAdaptor.cdsHash = make(map[string]*list.Element)
	configAdaptor.edsHash = make(map[string]*list.Element)
	configAdaptor.ldsHash = make(map[string]*list.Element)
	configAdaptor.rdsHash = make(map[string]*list.Element)
	configAdaptor.quit = make(chan bool)
	configAdaptor.analyticsServerIP = nsinfo.AnalyticsServerIP
	configAdaptor.licenseServerIP = nsinfo.LicenseServerIP
	configAdaptor.logProxyURL = nsinfo.LogProxyURL
	configAdaptor.localHostVIP = nsinfo.LocalHostVIP
	configAdaptor.caServerPort = nsinfo.caServerPort
	var err error
	logLevel, _ := os.LookupEnv("LOGLEVEL")
	if logLevel == "" {
		logLevel = "DEBUG"
	}
	jsonLogFormat := getBoolEnv("JSONLOG")
	configAdaptor.client, err = netscaler.NewNitroClientFromParams(netscaler.NitroParams{Url: nsinfo.NetscalerURL, Username: nsinfo.NetscalerUsername, Password: nsinfo.NetscalerPassword, SslVerify: nsinfo.SslVerify, RootCAPath: nsinfo.RootCAPath, ServerName: nsinfo.ServerName, LogLevel: logLevel, JSONLogFormat: jsonLogFormat})
	if err != nil {
		return nil, err
	}
	for {
		nsip, err := configAdaptor.getNitroObject(netscaler.Nsip.Type(), map[string]string{"type": "NSIP"})
		if err == nil {
			configAdaptor.nsip = nsip["ipaddress"].(string)
			break
		}
		xDSLogger.Trace("newConfigAdaptor: Error connecting to the ADC", "error", err)
		time.Sleep(1 * time.Second)
	}
	if nsinfo.bootStrapConfReqd {
		if isCPX(nsinfo.NetscalerURL) {
			err = configAdaptor.sidecarBootstrapConfig()
			if err != nil {
				return nil, err
			}
		}
		err = configAdaptor.bootstrapConfig()
		if err != nil {
			xDSLogger.Error("newConfigAdaptor: BootstrapConfig failed", "error", err)
			return nil, err
		}
		err = configAdaptor.dologProxyConfig()
		if err != nil {
			xDSLogger.Warn("newConfigAdaptor: Logproxy related config is not successful", "error", err)
		}
		nsinfo.bootStrapConfReqd = false
	}

	if nsinfo.NetscalerVIP == "nsip" {
		configAdaptor.vserverIP = configAdaptor.nsip
	}
	build, err := configAdaptor.client.FindResource(netscaler.Nsversion.Type(), "")
	if err != nil {
		return nil, err
	}
	err = nsconfigengine.SetNsReleaseBuild(build)
	if err != nil {
		return nil, err
	}
	return configAdaptor, nil
}

func getNameServer() (string, error) {
	b, err := ioutil.ReadFile("/etc/resolv.conf")
	if err != nil {
		return "", err
	}
	re := regexp.MustCompile("[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+")
	match := re.FindString(string(b))
	return match, nil
}

func findXDSServerIP() {
	ips, err := net.LookupIP(xDSServerURL)
	if err != nil {
		xDSLogger.Debug("findXDSServerIP: Could not resolve xdsserverURL", "xDSServerURL", xDSServerURL)
		return
	}
	xDSServerResolvedIP = ips[0].String() // Mostly it is a single IP
	xDSLogger.Debug("findXDSServerIP: xDS Server IP resolved", "xDSServerURL", xDSServerURL, "xDSServerResolvedIP", xDSServerResolvedIP)
}

func (confAdaptor *configAdaptor) sidecarBootstrapConfig() error {
	var err error
	var nameServer string
	nameServer, err = getNameServer()
	if err != nil {
		return err
	}
	findXDSServerIP()
	configs := []nsconfigengine.NsConfigEntity{
		{ResourceType: netscaler.Service.Type(), ResourceName: "dns_service", Resource: basic.Service{Name: "dns_service", Ip: nameServer, Port: 53, Servicetype: "DNS", Healthmonitor: "no"}},
		{ResourceType: netscaler.Lbvserver.Type(), ResourceName: "dns_vserver", Resource: lb.Lbvserver{Name: "dns_vserver", Servicetype: "DNS"}},
		{ResourceType: netscaler.Lbvserver_service_binding.Type(), ResourceName: "dns_vserver", Resource: lb.Lbvserverservicebinding{Name: "dns_vserver", Servicename: "dns_service"}, IgnoreErrors: []string{"Resource already exists"}},
		{ResourceType: netscaler.Dnsnameserver.Type(), ResourceName: "dns_vserver", Resource: dns.Dnsnameserver{Dnsvservername: "dns_vserver"}, IgnoreErrors: []string{"Name servers already configured.", "Invalid value [dnsVserverName, value differs from existing entity and it cant be updated.]"}},
		{ResourceType: netscaler.Nsacl.Type(), ResourceName: "allowpromexp", Resource: ns.Nsacl{Aclname: "allowpromexp", Aclaction: "ALLOW", Protocol: "TCP", Destport: true, Destportval: "8888", Priority: 65536}},
	}
	listenPolicy := "CLIENT.TCP.DSTPORT.NE(" + confAdaptor.adsServerPort + ")"
	// CA port and xDS server's ports can be different
	if len(confAdaptor.caServerPort) > 0 && (confAdaptor.caServerPort != confAdaptor.adsServerPort) {
		listenPolicy = listenPolicy + " && CLIENT.TCP.DSTPORT.NE(" + confAdaptor.caServerPort + ")"
	}
	if len(confAdaptor.analyticsServerIP) > 0 {
		listenPolicy = listenPolicy + " && CLIENT.IP.DST.NE(" + confAdaptor.analyticsServerIP + ")"
		configs = append(configs, nsconfigengine.NsConfigEntity{ResourceType: netscaler.Nsacl.Type(), ResourceName: "allowadmserver", Resource: ns.Nsacl{Aclname: "allowadmserver", Aclaction: "ALLOW", Srcip: true, Srcipval: confAdaptor.analyticsServerIP, Priority: 65537}})
	}
	if len(confAdaptor.licenseServerIP) > 0 && confAdaptor.licenseServerIP != confAdaptor.analyticsServerIP {
		listenPolicy = listenPolicy + " && CLIENT.IP.DST.NE(" + confAdaptor.licenseServerIP + ")"
		configs = append(configs, nsconfigengine.NsConfigEntity{ResourceType: netscaler.Nsacl.Type(), ResourceName: "allowlicenseserver", Resource: ns.Nsacl{Aclname: "allowlicenseserver", Aclaction: "ALLOW", Srcip: true, Srcipval: confAdaptor.licenseServerIP, Priority: 65538}})
	}
	// Create drop_all_vserver config
	configs = append(configs, nsconfigengine.NsConfigEntity{ResourceType: netscaler.Lbvserver.Type(), ResourceName: "drop_all_vserver", Resource: lb.Lbvserver{Name: "drop_all_vserver", Servicetype: "ANY", Ipv46: "*", Port: 65535, Listenpolicy: listenPolicy}})
	configs = append(configs, nsconfigengine.NsConfigEntity{ResourceType: netscaler.Nsacl.Type(), ResourceName: "denyall", Resource: ns.Nsacl{Aclname: "denyall", Aclaction: "DENY", Priority: 100000}})
	configs = append(configs, nsconfigengine.NsConfigEntity{ResourceType: netscaler.Nsacls.Type(), ResourceName: "", Resource: ns.Nsacls{}, Operation: "apply"})
	err = nsconfigengine.NsConfigCommit(confAdaptor.client, configs)
	return err
}

func (confAdaptor *configAdaptor) bootstrapConfig() error {
	var err error
	err = confAdaptor.client.EnableFeatures([]string{"lb", "cs", "ssl", "rewrite", "responder"})
	if err != nil {
		return err
	}
	configs := []nsconfigengine.NsConfigEntity{
		{ResourceType: netscaler.Nstcpprofile.Type(), ResourceName: "nstcp_default_profile", Resource: ns.Nstcpprofile{Name: "nstcp_default_profile", Mss: MSS}, Operation: "set"},
		{ResourceType: netscaler.Nstcpprofile.Type(), ResourceName: "nstcp_internal_apps", Resource: ns.Nstcpprofile{Name: "nstcp_internal_apps", Mss: MSS}, Operation: "set"},
		{ResourceType: netscaler.Nstcpprofile.Type(), ResourceName: "nsulfd_default_profile", Resource: ns.Nstcpprofile{Name: "nsulfd_default_profile", Mss: MSS}, Operation: "set"},
		{ResourceType: netscaler.Nshttpprofile.Type(), ResourceName: "nshttp_default_profile", Resource: ns.Nshttpprofile{Name: "nshttp_default_profile", Http2: "ENABLED", Http2maxconcurrentstreams: 1000}, Operation: "set"},
		{ResourceType: netscaler.Responderaction.Type(), ResourceName: "return404", Resource: responder.Responderaction{Name: "return404", Type: "respondwith", Target: "\"HTTP/1.1 404 Not found\r\n\r\n\""}},
		{ResourceType: netscaler.Responderpolicy.Type(), ResourceName: "return404", Resource: responder.Responderpolicy{Name: "return404", Rule: "true", Action: "return404"}},
		{ResourceType: netscaler.Lbvserver.Type(), ResourceName: "ns_blackhole_http", Resource: lb.Lbvserver{Name: "ns_blackhole_http", Servicetype: "HTTP"}},
		{ResourceType: netscaler.Service.Type(), ResourceName: "ns_blackhole_http", Resource: basic.Service{Name: "ns_blackhole_http", Ip: "127.0.0.1", Port: 1, Servicetype: "HTTP", Healthmonitor: "no"}},
		{ResourceType: netscaler.Lbvserver_service_binding.Type(), ResourceName: "ns_blackhole_http", Resource: lb.Lbvserverservicebinding{Name: "ns_blackhole_http", Servicename: "ns_blackhole_http"}, IgnoreErrors: []string{"Resource already exists"}},
		{ResourceType: netscaler.Lbvserver_responderpolicy_binding.Type(), ResourceName: "ns_blackhole_http", Resource: lb.Lbvserverresponderpolicybinding{Name: "ns_blackhole_http", Policyname: "return404", Priority: 1}},
		// Dummy HTTP Vserver is added for Redirect Case
		{ResourceType: netscaler.Lbvserver.Type(), ResourceName: "ns_dummy_http", Resource: lb.Lbvserver{Name: "ns_dummy_http", Servicetype: "HTTP"}},
		{ResourceType: netscaler.Lbvserver_service_binding.Type(), ResourceName: "ns_dummy_http", Resource: lb.Lbvserverservicebinding{Name: "ns_dummy_http", Servicename: "ns_blackhole_http"}, IgnoreErrors: []string{"Resource already exists"}},
	}
	err = confAdaptor.client.EnableFeatures([]string{"aaa"})
	if err != nil {
		xDSLogger.Warn("bootstrapConfig: AAA feature is not enabled and JWT authentication will not work")
	} else {
		configs = append(configs, nsconfigengine.NsConfigEntity{ResourceType: netscaler.Tmsessionparameter.Type(), ResourceName: "", Resource: tm.Tmsessionparameter{Defaultauthorizationaction: "ALLOW"}, Operation: "set"})
	}
	if len(confAdaptor.netProfile) > 0 {
		netprof := nsconfigengine.NsConfigEntity{
			ResourceType: netscaler.Netprofile.Type(),
			ResourceName: confAdaptor.netProfile,
			Resource:     network.Netprofile{Name: confAdaptor.netProfile},
		}
		configs = append(configs, netprof)
	}
	dummySslCertConfigs := []nsconfigengine.NsConfigEntity{
		{ResourceType: netscaler.Sslrsakey.Type(), ResourceName: "dummy_xds_key", Resource: ssl.Sslrsakey{Keyfile: "dummy_xds_key", Bits: 512}, Operation: "create", IgnoreErrors: []string{"File already exists"}},
		{ResourceType: netscaler.Sslcertreq.Type(), ResourceName: "dummy_xds_cert_req", Resource: ssl.Sslcertreq{Reqfile: "dummy_xds_cert_req", Keyfile: "dummy_xds_key", Countryname: "US", Statename: "Florida", Organizationname: "Citrix", Commonname: "dummy.citrix.xds"}, Operation: "create", IgnoreErrors: []string{"File already exists"}},
		{ResourceType: netscaler.Sslcert.Type(), ResourceName: "dummy_xds_cert", Resource: ssl.Sslcert{Certfile: "dummy_xds_cert", Reqfile: "dummy_xds_cert_req", Certtype: "ROOT_CERT", Keyfile: "dummy_xds_key"}, Operation: "create", IgnoreErrors: []string{"File already exists"}},
	}
	configs = append(configs, dummySslCertConfigs...)
	// Config related to multiCluster Ingress gateway
	if multiClusterIngress == true {
		// Policy stringmap name and policy expression name should not be same.
		expr := "HTTP.REQ.HOSTNAME.BEFORE_STR(\"" + multiClusterPolExprStr + "\").MAP_STRING(\"" + multiClusterStringMap + "\")"
		multiClusterGWConfig := []nsconfigengine.NsConfigEntity{
			{ResourceType: netscaler.Policystringmap.Type(), ResourceName: multiClusterStringMap, Resource: policy.Policystringmap{Name: multiClusterStringMap, Comment: "Stringmap to select LB vserver from servicename"}, Operation: "add"},
			{ResourceType: netscaler.Policyexpression.Type(), ResourceName: multiClusterExpression, Resource: policy.Policyexpression{Name: multiClusterExpression, Value: expr}, Operation: "add"},
		}
		configs = append(configs, multiClusterGWConfig...)
	}

	err = nsconfigengine.NsConfigCommit(confAdaptor.client, configs)
	return err
}

func (confAdaptor *configAdaptor) dologProxyConfig() error {
	var err error
	err = nil
	if len(confAdaptor.logProxyURL) > 0 {
		err = confAdaptor.client.EnableFeatures([]string{"appflow"})
		if err != nil {
			xDSLogger.Warn("dologProxyConfig: AppFlow feature could not be enabled")
		}
		err = confAdaptor.client.EnableModes([]string{"ulfd"})
		if err != nil {
			xDSLogger.Warn("dologProxyConfig: ULFD mode could not be enabled")
		}
		// Below config is for Transaction data (used for tracing, logstream) on default port 5557
		appflowResource := map[string]interface{}{"templaterefresh": 60, "securityinsightrecordinterval": 60, "httpurl": "ENABLED", "httpcookie": "ENABLED", "httpreferer": "ENABLED", "httpmethod": "ENABLED", "httphost": "ENABLED", "httpuseragent": "ENABLED", "httpcontenttype": "ENABLED", "securityinsighttraffic": "ENABLED", "httpquerywithurl": "ENABLED", "urlcategory": "ENABLED", "distributedtracing": "ENABLED", "disttracingsamplingrate": 100}
		configs := []nsconfigengine.NsConfigEntity{
			{ResourceType: netscaler.Appflowparam.Type(), ResourceName: "", Resource: appflowResource, Operation: "set"},
			{ResourceType: "analyticsprofile", ResourceName: "ns_analytics_default_http_profile", Resource: analytics.Analyticsprofile{Name: "ns_analytics_default_http_profile", Type: "webinsight", Httpurl: "ENABLED", Httphost: "ENABLED", Httpmethod: "ENABLED", Httpuseragent: "ENABLED", Urlcategory: "ENABLED", Httpcontenttype: "ENABLED", Httpvia: "ENABLED", Httpdomainname: "ENABLED", Httpurlquery: "ENABLED"}},
			{ResourceType: "analyticsprofile", ResourceName: "ns_analytics_default_tcp_profile", Resource: analytics.Analyticsprofile{Name: "ns_analytics_default_tcp_profile", Type: "tcpinsight"}},
			{ResourceType: "analyticsprofile", ResourceName: "ns_analytics_time_series_profile", Resource: analytics.Analyticsprofile{Name: "ns_analytics_time_series_profile", Type: "timeseries", Outputmode: "prometheus", Metrics: "ENABLED"}},
		}
		err = nsconfigengine.NsConfigCommit(confAdaptor.client, configs)
		if err != nil {
			xDSLogger.Warn("dologProxyConfig: Tracing config (transaction data) failed")
		} else {
			confAdaptor.analyticsProfiles = []string{"ns_analytics_default_tcp_profile", "ns_analytics_default_http_profile"}
		}
		xDSLogger.Trace("dologProxyConfig: Config adaptor's analyticsProfiles", "analyticsProfiles", confAdaptor.analyticsProfiles)
	}
	return err
}

func (confAdaptor *configAdaptor) getNitroObject(ResourceType string, filter map[string]string) (map[string]interface{}, error) {
	objs, err := confAdaptor.client.FindFilteredResourceArray(ResourceType, filter)
	if err == nil {
		if len(objs) != 1 {
			return nil, fmt.Errorf("Expected 1 object of type %s, rcvd %d objects", ResourceType, len(objs))
		}
		return objs[0], nil
	}
	return nil, err
}

func (confAdaptor *configAdaptor) getConfigMap(ct discoveryType) (map[string]*list.Element, map[string]*list.Element) {
	if ct == cdsAdd || ct == cdsDel {
		return confAdaptor.cdsHash, confAdaptor.edsHash
	}
	if ct == edsAdd {
		return confAdaptor.edsHash, nil
	}
	if ct == ldsAdd || ct == ldsDel {
		return confAdaptor.ldsHash, confAdaptor.rdsHash
	}
	if ct == rdsAdd {
		return confAdaptor.rdsHash, nil
	}
	return nil, nil
}

func (confAdaptor *configAdaptor) getConfigByName(configName string, configType discoveryType) (*configBlock, error) {
	cmap, _ := confAdaptor.getConfigMap(configType)
	if cmap == nil {
		return nil, fmt.Errorf("ConfigMap not found for %v", configType)
	}
	if e, ok := cmap[configName]; ok {
		return e.Value.(*configBlock), nil
	}
	return nil, fmt.Errorf("Config Resource not found in hash : %s", configName)
}

func (confAdaptor *configAdaptor) addConfig(config *configBlock) {
	cmap, _ := confAdaptor.getConfigMap(config.configType)
	confAdaptor.mux.Lock()
	if cmap != nil {
		if e, ok := cmap[config.resourceName]; ok {
			enew := confAdaptor.configs.InsertBefore(config, e)
			_ = confAdaptor.configs.Remove(e)
			cmap[config.resourceName] = enew
		} else {
			e := confAdaptor.configs.PushBack(config)
			cmap[config.resourceName] = e
		}
	} else {
		confAdaptor.configs.PushBack(config)
	}
	confAdaptor.mux.Unlock()
}

func (confAdaptor *configAdaptor) delConfig(config *configBlock) {
	cmap, dmap := confAdaptor.getConfigMap(config.configType)
	confAdaptor.mux.Lock()
	if e, ok := cmap[config.resourceName]; ok {
		_ = confAdaptor.configs.Remove(e)
		delete(cmap, config.resourceName)
	}
	e := confAdaptor.configs.PushBack(config)
	cmap[config.resourceName] = e

	if dmap != nil {
		if e, ok := dmap[config.resourceName]; ok {
			_ = confAdaptor.configs.Remove(e)
			delete(dmap, config.resourceName)
		}
	}
	confAdaptor.mux.Unlock()
}

func (confAdaptor *configAdaptor) startConfigAdaptor(adsClient *AdsClient) {
	go func() {
		xDSLogger.Trace("startConfigAdaptor: Starting Config adaptor")
		previousUptime := -1
		lastQueryTime := int64(0)
		for {
			select {
			case <-confAdaptor.quit:
				confAdaptor.client.Logout()
				xDSLogger.Trace("startConfigAdaptor: Stopping Config adaptor")
				return
			default:
				confAdaptor.mux.Lock()
				var config *configBlock
				e := confAdaptor.configs.Front()
				if e != nil {
					config = confAdaptor.configs.Remove(e).(*configBlock)
					cmap, _ := confAdaptor.getConfigMap(config.configType)
					delete(cmap, config.resourceName)
				} else {
					config = nil
				}
				confAdaptor.mux.Unlock()
				if config != nil {
					var err error
					switch config.configType {
					case cdsAdd:
						err = config.resource.(*nsconfigengine.LBApi).Add(confAdaptor.client)
					case cdsDel:
						err = config.resource.(*nsconfigengine.LBApi).Delete(confAdaptor.client)
					case ldsAdd:
						fallthrough
					case ldsDel:
						csResources := config.resource.([]*nsconfigengine.CSApi)
						for _, csResource := range csResources {
							var errCs error
							if config.configType == ldsAdd {
								errCs = csResource.Add(confAdaptor.client)
							} else {
								errCs = csResource.Delete(confAdaptor.client)
							}
							if errCs != nil {
								xDSLogger.Error("startConfigAdaptor: xDS application failed", "configType", config.configType, "error", errCs)
							}
						}
					case edsAdd:
						err = config.resource.(*nsconfigengine.ServiceGroupAPI).Add(confAdaptor.client)
					case rdsAdd:
						err = config.resource.(*nsconfigengine.CSBindingsAPI).Add(confAdaptor.client)
					}
					if err != nil {
						xDSLogger.Error("startConfigAdaptor: xDS application failed", "error", err)
					}
				} else {
					time.Sleep(1 * time.Second)
				}
			}
			curTime := time.Now().Unix()
			if curTime > lastQueryTime+7 {
				currentUptime, err := nsconfigengine.GetNsUptime(confAdaptor.client)
				if err != nil {
					continue
				}
				if currentUptime < previousUptime {
					xDSLogger.Error("startConfigAdaptor: ADC crash/reboot detected.")
					adsClient.stopClientConnection(false)
					adsClient.nsInfo.bootStrapConfReqd = true
					return
				}
				previousUptime = currentUptime
				lastQueryTime = curTime
			}
		}
	}()
}

func (confAdaptor *configAdaptor) stopConfigAdaptor() {
	xDSLogger.Trace("stopConfigAdaptor: Config adaptor is stopped")
	if confAdaptor.watch != nil {
		confAdaptor.watch.Stop()
	}
	confAdaptor.quit <- true
}
