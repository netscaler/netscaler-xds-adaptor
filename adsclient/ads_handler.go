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

package adsclient

import (
	"citrix-istio-adaptor/nsconfigengine"
	"fmt"
	xdsapi "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	xdsRoute "github.com/envoyproxy/go-control-plane/envoy/api/v2/route"
	envoyFault "github.com/envoyproxy/go-control-plane/envoy/config/filter/http/fault/v2"
	envoyFilterHttp "github.com/envoyproxy/go-control-plane/envoy/config/filter/network/http_connection_manager/v2"
	envoyFilterTcp "github.com/envoyproxy/go-control-plane/envoy/config/filter/network/tcp_proxy/v2"
	envoyType "github.com/envoyproxy/go-control-plane/envoy/type"
	envoyUtil "github.com/envoyproxy/go-control-plane/pkg/util"
	types "github.com/gogo/protobuf/types"
	istioAuth "istio.io/api/authentication/v1alpha1"
	istioFilter "istio.io/api/envoy/config/filter/http/authn/v2alpha1"
	"log"
	"net"
	"strconv"
	"strings"
)

const (
	maxConn      = 1024
	maxHTTP2Conn = 1000
	localHostIP  = "127.0.0.1"
	nsLoopbackIP = "192.0.0.2"
)

var valueNameToNum = map[string]int{
	"HUNDRED":      100,
	"TEN_THOUSAND": 10000,
	"MILLION":      1000000,
}

// valid input format: "outbound|80||httpbin.org"
func extractPortAndDomainName(input string) (ok bool, port int, domainName string) {
	s := strings.Split(input, "|")
	if len(s) < 4 {
		log.Printf("[DEBUG] Invalid input to extractPortAndDomainName: %s", input)
		return false, 0, ""
	}
	port, err := strconv.Atoi(s[1])
	if err != nil {
		log.Printf("[DEBUG] Port value %s is invalid in input %s.", s[1], input)
		return false, 0, ""
	}
	domainName = s[3]
	if len(domainName) == 0 {
		log.Printf("[DEBUG]Domain Name is empty in %s!", input)
		return false, 0, ""
	}
	return true, port, domainName
}

func getLbMethod(lbMethod xdsapi.Cluster_LbPolicy) string {
	/*
		xDS Simple LB Method   | CPX Configuration
		------------------------------------------------------------------
		ROUND_ROBIN              | Default. Value 0 ROUNDROBIN
		LEAST_CONN	         | Value 1 LEASTCONNECTION
		RANDOM		         | Value 3 LEASTCONNECTION
		PASSTHROUGH		 | value 4 not supported in CPX right now
	*/
	if lbMethod == xdsapi.Cluster_LEAST_REQUEST || lbMethod == xdsapi.Cluster_RANDOM {
		return "LEASTCONNECTION"
	}
	return "ROUNDROBIN"
}

func addToWatch(nsConfig *configAdaptor, certPath, keyPath string) error {
	var err error
	if certPath == "" {
		return nil
	}
	if nsConfig.watch == nil {
		nsConfig.watch, err = newWatcher(nsConfig)
		if err != nil {
			return err
		}
		go nsConfig.watch.Run()
	}
	return nsConfig.watch.addDir(certPath, keyPath)
}

func clusterAdd(nsConfig *configAdaptor, cluster *xdsapi.Cluster, data interface{}) string {
	log.Printf("[TRACE] clusterAdd : %s type %s", cluster.Name, data.(string))
	log.Printf("[TRACE] clusterAdd : %v", cluster)
	serviceType := data.(string)
	serviceGroupType := serviceType
	if cluster.GetTlsContext() != nil {
		serviceGroupType = "SSL"
		if serviceType == "TCP" {
			serviceGroupType = "SSL_TCP"
		}
	}
	var maxCon, maxHTTP2Con int
	maxCon = maxConn
	maxHTTP2Con = maxHTTP2Conn /* CPX Supports Max 1000 only */
	if cluster.GetCircuitBreakers().GetThresholds() != nil && cluster.GetCircuitBreakers().GetThresholds()[0].GetMaxConnections() != nil {
		maxCon = int(cluster.GetCircuitBreakers().GetThresholds()[0].GetMaxConnections().GetValue())
	}
	if cluster.GetCircuitBreakers().GetThresholds() != nil && cluster.GetCircuitBreakers().GetThresholds()[0].GetMaxRequests() != nil {
		if cluster.GetCircuitBreakers().GetThresholds()[0].GetMaxRequests().GetValue() < 1000 {
			maxHTTP2Con = int(cluster.GetCircuitBreakers().GetThresholds()[0].GetMaxRequests().GetValue())
		}
	}
	lbObj := nsconfigengine.NewLBApi(nsconfigengine.GetNSCompatibleName(cluster.GetName()), serviceType, serviceGroupType, getLbMethod(cluster.GetLbPolicy()))
	lbObj.MaxConnections = maxCon
	lbObj.MaxHTTP2ConcurrentStreams = maxHTTP2Con
	lbObj.MaxRequestsPerConnection = int(cluster.GetMaxRequestsPerConnection().GetValue())
	lbObj.NetprofileName = nsConfig.netProfile
	if serviceGroupType == "SSL" || serviceGroupType == "SSL_TCP" {
		for _, tlsCertificate := range cluster.GetTlsContext().GetCommonTlsContext().GetTlsCertificates() {
			_ = addToWatch(nsConfig, tlsCertificate.GetCertificateChain().GetFilename(), tlsCertificate.GetPrivateKey().GetFilename())
			_ = addToWatch(nsConfig, cluster.GetTlsContext().GetCommonTlsContext().GetValidationContext().GetTrustedCa().GetFilename(), "")
			lbObj.BackendTLS = append(lbObj.BackendTLS, nsconfigengine.SSLSpec{
				CertFilename:       tlsCertificate.GetCertificateChain().GetFilename(),
				PrivateKeyFilename: tlsCertificate.GetPrivateKey().GetFilename(),
				RootCertFilename:   cluster.GetTlsContext().GetCommonTlsContext().GetValidationContext().GetTrustedCa().GetFilename()})
		}
	}
	/* Outlier Detection */
	if serviceType == "HTTP" && cluster.GetOutlierDetection() != nil {
		lbObj.LbMonitorObj = new(nsconfigengine.LBMonitor)
		lbObj.LbMonitorObj.Retries = int(cluster.GetOutlierDetection().GetConsecutiveGatewayFailure().GetValue())
		if cluster.GetOutlierDetection().GetInterval() != nil {
			if cluster.GetOutlierDetection().GetInterval().GetNanos() != 0 { // If units are in Nano seconds, convert all to milli seconds as Citrix ADC understands that as smallest unit
				lbObj.LbMonitorObj.Interval = int(cluster.GetOutlierDetection().GetInterval().GetSeconds()*1000) + int(cluster.GetOutlierDetection().GetInterval().GetNanos())/valueNameToNum["MILLION"]
				lbObj.LbMonitorObj.IntervalUnits = "MSEC"
			} else {
				lbObj.LbMonitorObj.Interval = int(cluster.GetOutlierDetection().GetInterval().GetSeconds())
				lbObj.LbMonitorObj.IntervalUnits = "SEC"
			}
		}
		if cluster.GetOutlierDetection().GetBaseEjectionTime() != nil {
			if cluster.GetOutlierDetection().GetBaseEjectionTime().GetNanos() != 0 {
				lbObj.LbMonitorObj.DownTime = int(cluster.GetOutlierDetection().GetBaseEjectionTime().GetSeconds()*1000) + int(cluster.GetOutlierDetection().GetBaseEjectionTime().GetNanos())/valueNameToNum["MILLION"]
				lbObj.LbMonitorObj.DownTimeUnits = "MSEC"
			} else {
				lbObj.LbMonitorObj.DownTime = int(cluster.GetOutlierDetection().GetBaseEjectionTime().GetSeconds())
				lbObj.LbMonitorObj.DownTimeUnits = "SEC"
			}
		}
	}
	nsConfig.addConfig(&configBlock{configType: cdsAdd, resourceName: lbObj.Name, resource: lbObj})
	if (cluster.GetType() == xdsapi.Cluster_STATIC) || (cluster.GetType() == xdsapi.Cluster_STRICT_DNS) {
		if cluster.GetLoadAssignment() != nil {
			clusterEndpointUpdate(nsConfig, cluster.GetLoadAssignment(), nil)
		} else if cluster.GetHosts() != nil {
			staticAndDNSTypeClusterEndpointUpdate(nsConfig, cluster)
		}
	} else if cluster.GetType() == xdsapi.Cluster_ORIGINAL_DST { // Original Dst type has no load assignment or hosts! Extract info from name.
		staticAndDNSTypeClusterEndpointUpdate(nsConfig, cluster)
	}
	return cluster.GetEdsClusterConfig().GetServiceName()
}

func clusterDel(nsConfig *configAdaptor, clusterName string) {
	log.Printf("[TRACE] clusterDel : %s", clusterName)
	lbObj := &nsconfigengine.LBApi{Name: nsconfigengine.GetNSCompatibleName(clusterName)}
	confBl := configBlock{
		configType:   cdsDel,
		resourceName: lbObj.Name,
		resource:     lbObj,
	}
	nsConfig.delConfig(&confBl)
}

func getAuthRuleMatch(rules []*istioAuth.StringMatch) []nsconfigengine.AuthRuleMatch {
	rulesMatch := make([]nsconfigengine.AuthRuleMatch, 0)
	for _, rule := range rules {
		rulesMatch = append(rulesMatch, nsconfigengine.AuthRuleMatch{Exact: rule.GetExact(), Prefix: rule.GetPrefix(), Suffix: rule.GetSuffix(), Regex: rule.GetRegex()})
	}
	return rulesMatch
}

func getAuthConfig(nsConfig *configAdaptor, listenerName string, httpFilters []*envoyFilterHttp.HttpFilter) *nsconfigengine.AuthSpec {
	for _, httpFilter := range httpFilters {
		switch httpFilter.GetName() {
		case "istio_authn":
			filterConfig := &istioFilter.FilterConfig{}
			if err := envoyUtil.StructToMessage(httpFilter.GetConfig(), filterConfig); err == nil {
				authnPolicy := filterConfig.GetPolicy()
				for _, origin := range authnPolicy.GetOrigins() {
					authSpec := &nsconfigengine.AuthSpec{Name: nsconfigengine.GetNSCompatibleName(listenerName), Issuer: origin.GetJwt().GetIssuer(), JwksURI: origin.GetJwt().GetJwksUri(), Audiences: origin.GetJwt().GetAudiences()}
					for _, rule := range origin.GetJwt().GetTriggerRules() {
						authSpec.IncludePaths = append(authSpec.IncludePaths, getAuthRuleMatch(rule.GetIncludedPaths())...)
						authSpec.ExcludePaths = append(authSpec.ExcludePaths, getAuthRuleMatch(rule.GetExcludedPaths())...)
					}
					_ = addToWatch(nsConfig, clientCertFile, clientKeyFile)
					_ = addToWatch(nsConfig, cacertFile, "")
					authSpec.JwtHeaders = origin.GetJwt().GetJwtHeaders()
					authSpec.JwtParams = origin.GetJwt().GetJwtParams()
					authSpec.FrontendTLS = append(authSpec.FrontendTLS, nsconfigengine.SSLSpec{CertFilename: clientCertFile, PrivateKeyFilename: clientKeyFile, RootCertFilename: cacertFile})
					return authSpec
				}
			}
			break
		}
	}
	return nil
}

func getListenerConfig(nsConfig *configAdaptor, listener *xdsapi.Listener, serviceType string) *nsconfigengine.CSApi {
	entityName := nsconfigengine.GetNSCompatibleName(listener.GetName())
	listenerAddress := listener.GetAddress()
	serviceAddress := listenerAddress.GetSocketAddress().GetAddress()
	if serviceAddress == "0.0.0.0" {
		serviceAddress = "*"
		if nsConfig.vserverIP != "" {
			serviceAddress = nsConfig.vserverIP
		}
	}
	csObj := nsconfigengine.NewCSApi(entityName, serviceType, serviceAddress, int(listenerAddress.GetSocketAddress().GetPortValue()))
	if serviceAddress == nsConfig.nsip {
		csObj.AllowACL = true
	}
	if serviceType == "SSL" || serviceType == "SSL_TCP" {
		for _, filterChain := range listener.GetFilterChains() {
			sniCertVal := false
			if filterChain.GetFilterChainMatch().GetServerNames() != nil {
				sniCertVal = true
			}
			for _, tlsCertificate := range filterChain.GetTlsContext().GetCommonTlsContext().GetTlsCertificates() {
				_ = addToWatch(nsConfig, tlsCertificate.GetCertificateChain().GetFilename(), tlsCertificate.GetPrivateKey().GetFilename())
				_ = addToWatch(nsConfig, filterChain.GetTlsContext().GetCommonTlsContext().GetValidationContext().GetTrustedCa().GetFilename(), "")
				csObj.FrontendTLS = append(csObj.FrontendTLS, nsconfigengine.SSLSpec{SNICert: sniCertVal, CertFilename: tlsCertificate.GetCertificateChain().GetFilename(), PrivateKeyFilename: tlsCertificate.GetPrivateKey().GetFilename(), RootCertFilename: filterChain.GetTlsContext().GetCommonTlsContext().GetValidationContext().GetTrustedCa().GetFilename()})
			}
			if filterChain.GetTlsContext().GetRequireClientCertificate().GetValue() == true {
				csObj.FrontendTLSClientAuth = true
			}
		}
	}
	return csObj
}

func getListenerType(l *xdsapi.Listener) (string, string, string, error) {
	listenerAddress := l.GetAddress()
	tlsContextExists := false
	for _, filterChain := range l.GetFilterChains() {
		if filterChain.GetTlsContext() != nil {
			tlsContextExists = true
		}
		for _, filter := range filterChain.GetFilters() {
			if listenerAddress.GetSocketAddress().GetPortValue() == 443 && listenerAddress.GetSocketAddress().GetAddress() == "0.0.0.0" && filter.Name == envoyUtil.TCPProxy {
				return envoyUtil.TCPProxy, "SSL", "TCP", nil
			}
			if filter.Name == envoyUtil.HTTPConnectionManager {
				if tlsContextExists {
					return envoyUtil.HTTPConnectionManager, "SSL", "HTTP", nil
				}
				return envoyUtil.HTTPConnectionManager, "HTTP", "HTTP", nil
			}
			if filter.Name == envoyUtil.TCPProxy {
				if tlsContextExists {
					return envoyUtil.TCPProxy, "SSL_TCP", "TCP", nil
				}
				return envoyUtil.TCPProxy, "TCP", "TCP", nil
			}
		}
	}
	return "", "", "", fmt.Errorf("Unknown filter type")
}

func listenerAdd(nsConfig *configAdaptor, listener *xdsapi.Listener) map[string]interface{} {
	log.Printf("[TRACE] listenerAdd : %s", listener.GetName())
	log.Printf("[TRACE] listenerAdd : %v", listener)
	filterType, csVserverType, serviceType, err := getListenerType(listener)
	if err != nil {
		log.Printf("[ERROR] listenerAdd : getListenerType failed with - %v", err)
		return nil
	}
	csObj := getListenerConfig(nsConfig, listener, csVserverType)
	confBl := configBlock{
		configType:   ldsAdd,
		resourceName: csObj.Name,
		resource:     csObj,
	}
	var clusterNames []string
	var rdsNames []string
	if filterType == envoyUtil.TCPProxy {
		clusterNames = make([]string, 0)
	} else if filterType == envoyUtil.HTTPConnectionManager {
		rdsNames = make([]string, 0)
	}
	for _, filterChain := range listener.GetFilterChains() {
		for _, filter := range filterChain.GetFilters() {
			switch filterName := filter.GetName(); filterName {
			case envoyUtil.HTTPConnectionManager:
				httpCM := &envoyFilterHttp.HttpConnectionManager{}
				if err := envoyUtil.StructToMessage(filter.GetConfig(), httpCM); err != nil {
					log.Printf("[ERROR] listenerAdd: Error loading http connection manager: %v", err)
				} else {
					csObj.AuthSpec = getAuthConfig(nsConfig, csObj.Name, httpCM.GetHttpFilters())
					if routeConfig := httpCM.GetRouteConfig(); routeConfig != nil {
						nsConfig.addConfig(&confBl)
						return routeUpdate(nsConfig, []*xdsapi.RouteConfiguration{routeConfig}, map[string]interface{}{"listenerName": listener.GetName(), "filterType": envoyUtil.HTTPConnectionManager, "serviceType": serviceType})
					}
					if rds := httpCM.GetRds(); rds != nil {
						rdsNames = append(rdsNames, rds.GetRouteConfigName())
					}
				}
			case envoyUtil.TCPProxy:
				tcpProxy := &envoyFilterTcp.TcpProxy{}
				if err := envoyUtil.StructToMessage(filter.GetConfig(), tcpProxy); err != nil {
					log.Printf("[ERROR] listenerAdd: Error loading tcp proxy filter: %v", err)
				} else {
					if tcpProxy.GetCluster() != "" {
						if filterChain.GetFilterChainMatch().GetServerNames() == nil {
							csObj.DefaultLbVserverName = nsconfigengine.GetNSCompatibleName(tcpProxy.GetCluster())
						} else {
							csObj.SSLForwarding = append(csObj.SSLForwarding, nsconfigengine.SSLForwardSpec{LbVserverName: nsconfigengine.GetNSCompatibleName(tcpProxy.GetCluster()), SNINames: filterChain.GetFilterChainMatch().GetServerNames()})
						}
						clusterNames = append(clusterNames, tcpProxy.GetCluster())
					}
				}
			}
		}
	}
	nsConfig.addConfig(&confBl)
	log.Printf("[TRACE] listenerAdd : %s - request clusters %v", listener.GetName(), clusterNames)
	log.Printf("[TRACE] listenerAdd : %s - request routes %v", listener.GetName(), rdsNames)
	return map[string]interface{}{"cdsNames": clusterNames, "rdsNames": rdsNames, "listenerName": listener.GetName(), "filterType": filterType, "serviceType": serviceType}
}

func listenerDel(nsConfig *configAdaptor, listenerName string) {
	log.Printf("[TRACE] listenerDel: %s", listenerName)
	csObj := nsconfigengine.CSApi{Name: nsconfigengine.GetNSCompatibleName(listenerName)}
	confBl := configBlock{
		configType:   ldsDel,
		resourceName: csObj.Name,
		resource:     &csObj,
	}
	nsConfig.delConfig(&confBl)
}

func clusterEndpointUpdate(nsConfig *configAdaptor, clusterLoadAssignment *xdsapi.ClusterLoadAssignment, data interface{}) {
	log.Printf("[TRACE] clusterEndpointUpdate: %s", clusterLoadAssignment.ClusterName)
	svcGpObj := nsconfigengine.NewServiceGroupAPI(nsconfigengine.GetNSCompatibleName(clusterLoadAssignment.ClusterName))

	confBl := configBlock{
		configType:   edsAdd,
		resourceName: svcGpObj.Name,
		resource:     svcGpObj,
	}
	if clusterLoadAssignment.Endpoints != nil {
		for _, endpoint := range clusterLoadAssignment.Endpoints {
			for _, lbEndpoint := range endpoint.LbEndpoints {
				ep := lbEndpoint.GetEndpoint()
				address := ep.Address.GetSocketAddress().GetAddress()
				port := int(ep.Address.GetSocketAddress().GetPortValue())
				if address == nsConfig.nsip {
					return
				}
				if address == localHostIP {
					address = nsLoopbackIP
				}
				if net.ParseIP(address) == nil {
					svcGpObj.Members = append(svcGpObj.Members, nsconfigengine.ServiceGroupMember{Domain: address, Port: port})
				} else {
					svcGpObj.Members = append(svcGpObj.Members, nsconfigengine.ServiceGroupMember{IP: address, Port: port})
				}
			}
		}
	}
	nsConfig.addConfig(&confBl)
}

// staticAndDNSTypeClusterEndpointUpdate() is to populate Citrix ADC config based on Hosts[] field in cluster
// NOTE: Hosts field is deprecated. But it is possible that this info is still sent by xDS server.
func staticAndDNSTypeClusterEndpointUpdate(nsConfig *configAdaptor, cluster *xdsapi.Cluster) {

	log.Printf("[TRACE] staticAndDNSTypeClusterEndpointUpdate : %s", cluster.GetName())
	svcGpObj := nsconfigengine.NewServiceGroupAPI(nsconfigengine.GetNSCompatibleName(cluster.GetName()))

	confBl := configBlock{
		configType:   edsAdd,
		resourceName: svcGpObj.Name,
		resource:     svcGpObj,
	}
	if cluster.GetType() == xdsapi.Cluster_STATIC {
		for _, host := range cluster.GetHosts() {
			address := host.GetSocketAddress().GetAddress()
			if address == localHostIP {
				address = nsLoopbackIP
			}
			svcGpObj.Members = append(svcGpObj.Members, nsconfigengine.ServiceGroupMember{IP: address, Port: int(host.GetSocketAddress().GetPortValue())})
		}
	} else if cluster.GetType() == xdsapi.Cluster_STRICT_DNS {
		for _, host := range cluster.GetHosts() {
			svcGpObj.Members = append(svcGpObj.Members, nsconfigengine.ServiceGroupMember{Domain: host.GetSocketAddress().GetAddress(), Port: int(host.GetSocketAddress().GetPortValue())})
		}
	} else if cluster.GetType() == xdsapi.Cluster_ORIGINAL_DST {
		ok, port, domain := extractPortAndDomainName(cluster.GetName())
		if !ok {
			return
		}
		svcGpObj.Members = append(svcGpObj.Members, nsconfigengine.ServiceGroupMember{Domain: domain, Port: port})
	}

	nsConfig.addConfig(&confBl)
}

func getPersistencyPolicy(hashPolicy []*xdsRoute.RouteAction_HashPolicy) *nsconfigengine.PersistencyPolicy {
	persistency := &nsconfigengine.PersistencyPolicy{}
	for _, hash := range hashPolicy {
		if hash.GetHeader() != nil {
			persistency.HeaderName = hash.GetHeader().GetHeaderName()
		} else if hash.GetCookie() != nil {
			persistency.CookieName = hash.GetCookie().GetName()
			persistency.Timeout = int(hash.GetCookie().GetTtl().Seconds())
		} else if hash.GetConnectionProperties() != nil && hash.GetConnectionProperties().GetSourceIp() {
			persistency.SourceIP = true
		}
	}
	return persistency
}

func getFault(perFilterConfig map[string]*types.Struct) nsconfigengine.Fault {
	fault := nsconfigengine.Fault{}
	if _, ok := perFilterConfig[envoyUtil.Fault]; ok {
		envoyFaultConfig := &envoyFault.HTTPFault{}
		if err := envoyUtil.StructToMessage(perFilterConfig[envoyUtil.Fault], envoyFaultConfig); err == nil {
			if envoyFaultConfig.GetAbort() != nil {
				percent := envoyFaultConfig.GetAbort().GetPercentage()
				numerator := percent.GetNumerator()
				den := envoyType.FractionalPercent_DenominatorType_name[int32(percent.GetDenominator())]
				if _, ok := valueNameToNum[den]; ok {
					log.Printf("[TRACE]: Abort Percent: numerator: %v, den: %v, denominator: %v", numerator, den, valueNameToNum[den])
					fault.AbortPercent = int((numerator * 100) / uint32(valueNameToNum[den]))
					fault.AbortHTTPStatus = int(envoyFaultConfig.GetAbort().GetHttpStatus())
				} else {
					log.Printf("[ERROR]: Incorrect value of denominator (%s) in percentage! Skipping processing this Abort rule", den)
				}
			}
			if envoyFaultConfig.GetDelay() != nil {
				percent := envoyFaultConfig.GetDelay().GetPercentage()
				numerator := percent.GetNumerator()
				den := envoyType.FractionalPercent_DenominatorType_name[int32(percent.GetDenominator())]
				if _, ok := valueNameToNum[den]; ok {
					log.Printf("[TRACE]: Delay Percent: numerator: %v, den: %v, denominator: %v", numerator, den, valueNameToNum[den])
					fault.DelayPercent = int((numerator * 100) / uint32(valueNameToNum[den]))
					fault.DelaySeconds = int(envoyFaultConfig.GetDelay().GetFixedDelay().Seconds())
				} else {
					log.Printf("[ERROR]: Incorrect value of denominator (%s) in percentage! Skipping processing this Delay rule", den)
				}
			}
		}
	}
	return fault
}

func routeUpdate(nsConfig *configAdaptor, routes []*xdsapi.RouteConfiguration, data interface{}) map[string]interface{} {
	inputMap := data.(map[string]interface{})
	log.Printf("[TRACE] routeUpdate: %v", routes)
	clusterNames := make([]string, 0)
	serviceType := inputMap["serviceType"].(string)
	csBindings := nsconfigengine.NewCSBindingsAPI(nsconfigengine.GetNSCompatibleName(inputMap["listenerName"].(string)))
	confBl := configBlock{
		configType:   rdsAdd,
		resourceName: csBindings.Name,
		resource:     csBindings,
	}
	for _, route := range routes {
		log.Printf("[TRACE] routeUpdate: %s - %s", route.Name, inputMap["listenerName"])
		for _, virtualHost := range route.GetVirtualHosts() {
			for _, vroute := range virtualHost.GetRoutes() {
				binding := nsconfigengine.CSBinding{}
				routeMatch := vroute.GetMatch()
				rule := nsconfigengine.RouteMatch{Domains: virtualHost.GetDomains(), Prefix: routeMatch.GetPrefix(), Path: routeMatch.GetPath(), Regex: routeMatch.GetRegex()}
				for _, headers := range routeMatch.GetHeaders() {
					rule.Headers = append(rule.Headers, nsconfigengine.MatchHeader{Name: headers.GetName(), Exact: headers.GetExactMatch(), Prefix: headers.GetRegexMatch(), Regex: headers.GetPrefixMatch()})
				}
				binding.Rule = rule
				if vroute.GetPerFilterConfig() != nil {
					binding.Fault = getFault(vroute.GetPerFilterConfig())
				}
				binding.RwPolicy.PrefixRewrite = vroute.GetRoute().GetPrefixRewrite()
				binding.RwPolicy.HostRewrite = vroute.GetRoute().GetHostRewrite()
				for _, reqAddHeader := range vroute.GetRoute().GetRequestHeadersToAdd() {
					binding.RwPolicy.AddHeaders = append(binding.RwPolicy.AddHeaders, nsconfigengine.RwHeader{Key: reqAddHeader.GetHeader().GetKey(), Value: reqAddHeader.GetHeader().GetValue()})
				}
				var persistency *nsconfigengine.PersistencyPolicy
				if vroute.GetRoute().GetHashPolicy() != nil && serviceType == "HTTP" {
					persistency = getPersistencyPolicy(vroute.GetRoute().GetHashPolicy())
				}
				if vroute.GetRoute().GetCluster() != "" {
					binding.CsPolicy.Canary = append(binding.CsPolicy.Canary, nsconfigengine.Canary{LbVserverName: nsconfigengine.GetNSCompatibleName(vroute.GetRoute().GetCluster()), LbVserverType: serviceType, Weight: 100, Persistency: persistency})
					clusterNames = append(clusterNames, vroute.GetRoute().GetCluster())
				} else if vroute.GetRoute().GetWeightedClusters().GetClusters() != nil {
					for _, cluster := range vroute.GetRoute().GetWeightedClusters().GetClusters() {
						binding.CsPolicy.Canary = append(binding.CsPolicy.Canary, nsconfigengine.Canary{LbVserverName: nsconfigengine.GetNSCompatibleName(cluster.GetName()), LbVserverType: serviceType, Weight: int(cluster.GetWeight().GetValue())})
						clusterNames = append(clusterNames, cluster.GetName())
					}
				}
				binding.ResPolicy.RedirectHost = vroute.GetRedirect().GetHostRedirect()
				binding.ResPolicy.RedirectPath = vroute.GetRedirect().GetPathRedirect()
				csBindings.Bindings = append(csBindings.Bindings, binding)
			}
		}
		log.Printf("[TRACE] routeUpdate: %s - request clusters: %v", route.Name, clusterNames)
	}
	nsConfig.addConfig(&confBl)
	return map[string]interface{}{"cdsNames": clusterNames, "serviceType": inputMap["serviceType"]}
}
