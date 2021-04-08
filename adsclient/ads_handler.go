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
	"citrix-xds-adaptor/delayserver"
	"citrix-xds-adaptor/nsconfigengine"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"

	xdsCluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	xdsEndpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	xdsListener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	xdsRoute "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"

	envoyFault "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/fault/v3"
	envoyJWT "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/jwt_authn/v3"
	envoyFilterHttp "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoyFilterTcp "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	auth "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	envoyType "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	envoyUtil "github.com/envoyproxy/go-control-plane/pkg/wellknown"
	proto "github.com/gogo/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	any "github.com/golang/protobuf/ptypes/any"
)

const (
	maxConn             = 0xfffffffe // max possible value of `maxClient` in Citrix ADC
	maxHTTP2Conn        = 1000
	maxReqPerConn       = 65535
	localHostIP         = "127.0.0.1"
	nsLoopbackIP        = "192.0.0.2"
	logStreamPort       = 5557 // Logstream is used for Transactional data which is used in tracing (e.g. zipkin)
	ulfdRestPort        = 5563 // Rest port is used for time-series data which is used in Prometheus
	defaultWeight       = 1
	defaultMirrorWeight = 100
	citrixEgressGateway = "citrix-egressgateway"
	istioEgressGateway  = "istio-egressgateway"
	// K8sServiceSuffix is common suffix of k8s service
	K8sServiceSuffix = "svc.cluster.local"
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

func getLbMethod(lbMethod xdsCluster.Cluster_LbPolicy) string {
	/*
		xDS Simple LB Method   | CPX Configuration
		------------------------------------------------------------------
		ROUND_ROBIN              | Default. Value 0 ROUNDROBIN
		LEAST_CONN	         | Value 1 LEASTCONNECTION
		RANDOM		         | Value 3 LEASTCONNECTION
		PASSTHROUGH		 | value 4 not supported in CPX right now
	*/
	if lbMethod == xdsCluster.Cluster_LEAST_REQUEST || lbMethod == xdsCluster.Cluster_RANDOM {
		return "LEASTCONNECTION"
	}
	return "ROUNDROBIN"
}

func addToWatch(nsConfig *configAdaptor, certPath, keyPath string) (string, string, string, error) {
	var err error
	if certPath == "" {
		return "", "", "", nil
	}
	if nsConfig.watch == nil {
		nsConfig.watch, err = newWatcher(nsConfig)
		if err != nil {
			return "", "", "", err
		}
		go nsConfig.watch.Run()
	}
	return nsConfig.watch.addDir(certPath, keyPath)
}

// getTLSDetailsFromTransportSocket will get UpStreamTLSContext which will be bound to SSL ServiceGroup
func getTLSDetailsFromTransportSocket(nsConfig *configAdaptor, transportSocket *core.TransportSocket, lbObj *nsconfigengine.LBApi) {
	if transportSocket == nil || nsConfig == nil || lbObj == nil {
		log.Printf("[DEBUG] Either transportSocket or nsConfig adaptor or lb object is nil")
		return
	}
	tlsContext := &auth.UpstreamTlsContext{}
	switch c := transportSocket.ConfigType.(type) {
	case *core.TransportSocket_TypedConfig:
		if err := ptypes.UnmarshalAny(c.TypedConfig, tlsContext); err != nil {
			log.Printf("[ERROR] Could not unmarshal while retrieving (upstream) TLS context %v", err)
		} else {
			for _, sdsConfig := range tlsContext.GetCommonTlsContext().GetTlsCertificateSdsSecretConfigs() {
				var certFileName, keyFileName, rootCertFileName string
				if sdsConfig.GetName() == "default" {
					certFileName, keyFileName, rootCertFileName, _ = addToWatch(nsConfig, ClientCertChainFile, ClientKeyFile)
					if rootCertFileName == "" {
						_, _, rootCertFileName, _ = addToWatch(nsConfig, CAcertFile, "")
					}
					lbObj.BackendTLS = append(lbObj.BackendTLS, nsconfigengine.SSLSpec{
						CertFilename:       certFileName,
						PrivateKeyFilename: keyFileName,
						RootCertFilename:   rootCertFileName})
				}
			}
			// If certificates are provided as part of UpstreamTlsContext, then retrieve same
			for _, tlsCertificate := range tlsContext.GetCommonTlsContext().GetTlsCertificates() {
				if tlsCertificate.GetCertificateChain().GetFilename() != "" {
					certFileName, keyFileName, rootCertFileName, _ := addToWatch(nsConfig, tlsCertificate.GetCertificateChain().GetFilename(), tlsCertificate.GetPrivateKey().GetFilename())
					if rootCertFileName == "" {
						_, _, rootCertFileName, _ = addToWatch(nsConfig, tlsContext.GetCommonTlsContext().GetValidationContext().GetTrustedCa().GetFilename(), "")
					}
					lbObj.BackendTLS = append(lbObj.BackendTLS, nsconfigengine.SSLSpec{
						CertFilename:       certFileName,
						PrivateKeyFilename: keyFileName,
						RootCertFilename:   rootCertFileName})
				} else if tlsCertificate.GetCertificateChain().GetInlineString() != "" {
					lbObj.BackendTLS = append(lbObj.BackendTLS, nsconfigengine.SSLSpec{
						Cert:       tlsCertificate.GetCertificateChain().GetInlineString(),
						PrivateKey: tlsCertificate.GetPrivateKey().GetInlineString(),
						RootCert:   tlsContext.GetCommonTlsContext().GetValidationContext().GetTrustedCa().GetInlineString()})
				}
			}
		}
	}
}

//getBackendTLS will look for TransportSocket from which TLS details need to be obtained
func getBackendTLS(nsConfig *configAdaptor, cluster *xdsCluster.Cluster, lbObj *nsconfigengine.LBApi) {
	if cluster.GetTransportSocket() == nil { // Loop through transportSocketMatch
		for _, transSocketMatch := range cluster.GetTransportSocketMatches() {
			getTLSDetailsFromTransportSocket(nsConfig, transSocketMatch.GetTransportSocket(), lbObj)
		}
	} else { // TransportSocket is immediately available in cluster resource
		getTLSDetailsFromTransportSocket(nsConfig, cluster.GetTransportSocket(), lbObj)
	}
}

// isTLSContext func checks if the TLS info is present in cluster or not.
// It can be present in any of 3 fields:
// i) TlsContext ii) TransportSocketMatch or iii) TransportSocket (only if it is TLS transport socket)
func isTLSContext(cluster *xdsCluster.Cluster) bool {
	if cluster.GetTransportSocketMatches() != nil {
		return true
	}
	if cluster.GetTransportSocket() != nil {
		//check if it is TLS transport socket or not
		log.Printf("[TRACE] Transport socket name: %s\n", cluster.GetTransportSocket().GetName())
		if strings.EqualFold(cluster.GetTransportSocket().GetName(), envoyUtil.TransportSocketTls) {
			return true
		}
	}
	return false
}

// isEgressGateway checks if the cluster name is citrix-egressgateway or istio-egressgateway
func isEgressGateway(name string) bool {
	return strings.Contains(name, citrixEgressGateway) || strings.Contains(name, istioEgressGateway)
}

// We use policy stringmap configuration to store servicename.namespace as key
// and associated LB vserver entity's name as the value
func getMultiClusterStringMapConfig(clusterName string) *nsconfigengine.StringMapBinding {
	ok, _, domain := extractPortAndDomainName(clusterName)
	if !ok {
		log.Printf("[DEBUG] %s resource does not seem to be having FQDN info", clusterName)
		return nil
	}
	// Check if domain is of servicename.namespace.svc.cluster.local format
	if !strings.HasSuffix(domain, K8sServiceSuffix) {
		log.Printf("[DEBUG] %s resource does not seem to be a service deployed in the cluster", clusterName)
		return nil
	}
	sn := domain[0 : len(domain)-len(K8sServiceSuffix)-1] // Get servicename.namespace
	stringMapBindingObj := new(nsconfigengine.StringMapBinding)
	stringMapBindingObj.StringMapName = multiClusterStringMap
	stringMapBindingObj.Key = sn
	stringMapBindingObj.Value = nsconfigengine.GetNSCompatibleName(clusterName)
	return stringMapBindingObj
}

func clusterAdd(nsConfig *configAdaptor, cluster *xdsCluster.Cluster, data interface{}) string {
	log.Printf("[TRACE] clusterAdd : %s type %s", cluster.Name, data.(string))
	log.Printf("[TRACE] clusterAdd :%v", nsconfigengine.GetLogString(cluster))
	serviceType := data.(string)
	serviceGroupType := serviceType

	if serviceType != "LOGSTREAM" && !isEgressGateway(cluster.Name) && isTLSContext(cluster) {
		serviceGroupType = "SSL"
		if serviceType == "TCP" {
			serviceGroupType = "SSL_TCP"
		}
	}
	lbObj := nsconfigengine.NewLBApi(nsconfigengine.GetNSCompatibleName(cluster.GetName()), serviceType, serviceGroupType, getLbMethod(cluster.GetLbPolicy()))
	lbObj.MaxConnections = maxConn
	lbObj.MaxHTTP2ConcurrentStreams = maxHTTP2Conn /* CPX Supports Max 1000 only */
	lbObj.MaxRequestsPerConnection = maxReqPerConn
	if cluster.GetCircuitBreakers().GetThresholds() != nil && cluster.GetCircuitBreakers().GetThresholds()[0].GetMaxConnections() != nil {
		if cluster.GetCircuitBreakers().GetThresholds()[0].GetMaxConnections().GetValue() < maxConn {
			lbObj.MaxConnections = int(cluster.GetCircuitBreakers().GetThresholds()[0].GetMaxConnections().GetValue())
		}
	}
	if cluster.GetCircuitBreakers().GetThresholds() != nil && cluster.GetCircuitBreakers().GetThresholds()[0].GetMaxRequests() != nil {
		if cluster.GetCircuitBreakers().GetThresholds()[0].GetMaxRequests().GetValue() < maxHTTP2Conn {
			lbObj.MaxHTTP2ConcurrentStreams = int(cluster.GetCircuitBreakers().GetThresholds()[0].GetMaxRequests().GetValue())
		}
	}
	if cluster.GetMaxRequestsPerConnection().GetValue() < maxReqPerConn {
		lbObj.MaxRequestsPerConnection = int(cluster.GetMaxRequestsPerConnection().GetValue())
	}
	lbObj.NetprofileName = nsConfig.netProfile
	if serviceGroupType == "SSL" || serviceGroupType == "SSL_TCP" {
		/* TLSContext is removed in go-control-plane:0.9.8	*/
		getBackendTLS(nsConfig, cluster, lbObj)
	}
	/* Outlier Detection. */
	if serviceGroupType == "HTTP" && cluster.GetOutlierDetection() != nil {
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
	// Below conditions checks if desired state API can be used for this cluster
	if cluster.GetType() == xdsCluster.Cluster_EDS || cluster.GetType() == xdsCluster.Cluster_STATIC {
		lbObj.AutoScale = true
	}
	// Multi Cluster Gateway needs to know point to clusterwide services.
	if multiClusterIngress {
		lbObj.StringMapBindingObj = getMultiClusterStringMapConfig(cluster.GetName())
	}
	nsConfig.addConfig(&configBlock{configType: cdsAdd, resourceName: cluster.Name, resource: lbObj})
	if (cluster.GetType() == xdsCluster.Cluster_STATIC) || (cluster.GetType() == xdsCluster.Cluster_STRICT_DNS) {
		if cluster.GetLoadAssignment() != nil {
			clusterEndpointUpdate(nsConfig, cluster.GetLoadAssignment(), nil)
		}
	} else if cluster.GetType() == xdsCluster.Cluster_ORIGINAL_DST { // Original Dst type has no load assignment or hosts! Extract info from name.
		staticAndDNSTypeClusterEndpointUpdate(nsConfig, cluster)
	} else if cluster.GetType() == xdsCluster.Cluster_EDS {
		if cluster.GetEdsClusterConfig().GetServiceName() != "" {
			return cluster.GetEdsClusterConfig().GetServiceName()
		}
		if cluster.GetEdsClusterConfig().GetEdsConfig().GetAds() != nil {
			return cluster.Name
		}
	}
	return ""
}

func clusterDel(nsConfig *configAdaptor, clusterName string) {
	log.Printf("[TRACE] clusterDel : %s", clusterName)
	lbObj := &nsconfigengine.LBApi{Name: nsconfigengine.GetNSCompatibleName(clusterName)}
	if multiClusterIngress {
		lbObj.StringMapBindingObj = getMultiClusterStringMapConfig(clusterName)
	}
	confBl := configBlock{
		configType:   cdsDel,
		resourceName: clusterName,
		resource:     lbObj,
	}
	nsConfig.delConfig(&confBl)
}
func getAuthConfig(nsConfig *configAdaptor, listenerName string, httpFilters []*envoyFilterHttp.HttpFilter) *nsconfigengine.AuthSpec {
	for _, httpFilter := range httpFilters {
		switch httpFilter.GetName() {
		case "envoy.filters.http.jwt_authn":
			jwtAuth := &envoyJWT.JwtAuthentication{}
			if err := getHTTPFilterConfig(httpFilter, jwtAuth); err == nil {
				jwtProviders := jwtAuth.GetProviders()
				for _, jwtProvider := range jwtProviders {
					authSpec := &nsconfigengine.AuthSpec{Name: nsconfigengine.GetNSCompatibleName(listenerName), Issuer: jwtProvider.GetIssuer(), Jwks: jwtProvider.GetLocalJwks().GetInlineString(), Audiences: jwtProvider.GetAudiences()}
					for _, header := range jwtProvider.GetFromHeaders() {
						authSpec.JwtHeaders = append(authSpec.JwtHeaders, nsconfigengine.JwtHeader{Name: header.Name, Prefix: header.ValuePrefix})
					}
					authSpec.JwtParams = jwtProvider.GetFromParams()
					authSpec.Forward = jwtProvider.GetForward()
					authSpec.ForwardHeader = jwtProvider.GetForwardPayloadHeader()
					authSpec.FrontendTLS = append(authSpec.FrontendTLS, nsconfigengine.SSLSpec{CertFilename: ClientCertChainFile, PrivateKeyFilename: ClientKeyFile})
					return authSpec
				}
			} else {
				log.Printf("[TRACE] getHTTPFilterConfig returned error!")
			}
			break
		}
	}
	return nil
}

// returns IP, port and filterChain name
func getListenerFilterChainMatchInfo(nsConfig *configAdaptor, filterChain *xdsListener.FilterChain, listener *xdsListener.Listener) (string, uint32, string) {
	var filterIP, fcName string
	var filterPort uint32
	trafficDirection := core.TrafficDirection_name[int32(listener.GetTrafficDirection())]
	// Return filterChain name only when destinationPort is specified
	if filterChain.GetFilterChainMatch().GetDestinationPort() != nil {
		fcName = filterChain.GetName()
		filterPort = filterChain.GetFilterChainMatch().GetDestinationPort().GetValue()
		if trafficDirection == "INBOUND" { // In Istio v1.8 onwards (go-control-plane:0.9.8), prefixRanges are not set. Thus we need to check for Direction
			filterIP = nsConfig.nsip
		} else {
			for _, prefixRange := range filterChain.GetFilterChainMatch().GetPrefixRanges() {
				if prefixRange.GetPrefixLen().GetValue() == 32 {
					filterIP = prefixRange.GetAddressPrefix()
					break
				}
			}
		}
	}
	return filterIP, filterPort, fcName
}

//getTLSfromTransportSocket will get DownstreamTLSContext which will be associcated with SSL CS Vserver
func getTLSfromTransportSocket(nsConfig *configAdaptor, csObj *nsconfigengine.CSApi, filterChain *xdsListener.FilterChain, sniCertVal bool) *auth.DownstreamTlsContext {
	tlsContext := &auth.DownstreamTlsContext{}
	switch c := filterChain.GetTransportSocket().ConfigType.(type) {
	case *core.TransportSocket_TypedConfig:
		if err := ptypes.UnmarshalAny(c.TypedConfig, tlsContext); err != nil {
			log.Printf("[ERROR] Could not unmarshal while retrieving (downstream) TLS context %v", err)
			return nil
		}
	}
	for _, sdsConfig := range tlsContext.GetCommonTlsContext().GetTlsCertificateSdsSecretConfigs() {
		if sdsConfig.GetName() == "default" {
			certKeyFileName, keyFileName, rootCertFileName, _ := addToWatch(nsConfig, ClientCertChainFile, ClientKeyFile)
			if rootCertFileName == "" {
				_, _, rootCertFileName, _ = addToWatch(nsConfig, CAcertFile, "")
			}
			csObj.FrontendTLS = append(csObj.FrontendTLS, nsconfigengine.SSLSpec{SNICert: sniCertVal, CertFilename: certKeyFileName, PrivateKeyFilename: keyFileName, RootCertFilename: rootCertFileName})
		}
		return nil
	}
	return tlsContext
}

func getFrontEndTLSConfig(nsConfig *configAdaptor, csObj *nsconfigengine.CSApi, filterChain *xdsListener.FilterChain, sniCertVal bool) {
	var tlsContext *auth.DownstreamTlsContext
	if filterChain.GetTransportSocket() != nil {
		tlsContext = getTLSfromTransportSocket(nsConfig, csObj, filterChain, sniCertVal)
	}
	for _, tlsCertificate := range tlsContext.GetCommonTlsContext().GetTlsCertificates() {
		if tlsCertificate.GetCertificateChain().GetFilename() != "" {
			rootCertFileName := ""
			certKeyFileName, keyFileName, rootCertFileName, _ := addToWatch(nsConfig, tlsCertificate.GetCertificateChain().GetFilename(), tlsCertificate.GetPrivateKey().GetFilename())
			if rootCertFileName == "" {
				_, _, rootCertFileName, _ = addToWatch(nsConfig, tlsContext.GetCommonTlsContext().GetValidationContext().GetTrustedCa().GetFilename(), "")
			}
			csObj.FrontendTLS = append(csObj.FrontendTLS, nsconfigengine.SSLSpec{SNICert: sniCertVal, CertFilename: certKeyFileName, PrivateKeyFilename: keyFileName, RootCertFilename: rootCertFileName})
		} else if tlsCertificate.GetCertificateChain().GetInlineString() != "" {
			csObj.FrontendTLS = append(csObj.FrontendTLS, nsconfigengine.SSLSpec{
				SNICert:    sniCertVal,
				Cert:       tlsCertificate.GetCertificateChain().GetInlineString(),
				PrivateKey: tlsCertificate.GetPrivateKey().GetInlineString(),
				RootCert:   tlsContext.GetCommonTlsContext().GetValidationContext().GetTrustedCa().GetInlineString()})
		}
	}
	if tlsContext.GetRequireClientCertificate().GetValue() == true {
		csObj.FrontendTLSClientAuth = true
	}
}

func getListenerFilterChainConfig(nsConfig *configAdaptor, csObjMap map[string]interface{}, listener *xdsListener.Listener, filterChain *xdsListener.FilterChain) (map[string]interface{}, error) {
	entityName := nsconfigengine.GetNSCompatibleName(listener.GetName())
	vserverAddress := listener.GetAddress().GetSocketAddress().GetAddress()
	vserverPort := listener.GetAddress().GetSocketAddress().GetPortValue()
	filterIP, filterPort, filterChainName := getListenerFilterChainMatchInfo(nsConfig, filterChain, listener)
	if filterPort != 0 {
		vserverAddress = filterIP
		vserverPort = filterPort
		entityName = entityName + "_" + nsconfigengine.GetNSCompatibleName(filterChainName)
	}
	if vserverAddress == "0.0.0.0" {
		vserverAddress = "*"
		if nsConfig.vserverIP != "" {
			vserverAddress = nsConfig.vserverIP
		}
	} else if vserverAddress == localHostIP {
		vserverAddress = nsConfig.localHostVIP
	}
	vserverType, serviceType, err := getListenerFilterType(nsConfig, filterChain, listener)
	if err != nil {
		log.Printf("[TRACE] Listener's filter type not supported. %s", err.Error())
		return nil, err
	}
	csObjMapKey := vserverAddress + ":" + fmt.Sprint(vserverPort)
	if _, ok := csObjMap[csObjMapKey]; !ok {
		if serviceType == "LOGSTREAM" {
			return nil, fmt.Errorf("Skipping LOGSTREAM service")
		}
		csObj := nsconfigengine.NewCSApi(entityName, vserverType, vserverAddress, int(vserverPort))
		if vserverAddress == nsConfig.nsip {
			csObj.AllowACL = true
			csObj.AnalyticsProfileNames = nsConfig.analyticsProfiles
		}
		csObjMap[csObjMapKey] = map[string]interface{}{"csObj": csObj, "rdsNames": nil, "cdsNames": nil, "serviceType": serviceType, "filterChainName": filterChainName, "listenerName": listener.GetName()}
		csObjMap[csObjMapKey].(map[string]interface{})["cdsNames"] = make([]string, 0)
		csObjMap[csObjMapKey].(map[string]interface{})["rdsNames"] = make([]string, 0)
	}
	csObj := csObjMap[csObjMapKey].(map[string]interface{})["csObj"].(*nsconfigengine.CSApi)
	if vserverType == "SSL" || vserverType == "SSL_TCP" {
		sniCertVal := false
		if filterChain.GetFilterChainMatch().GetServerNames() != nil {
			sniCertVal = true
		}
		//SSL Passthrough case
		// TO CHECK: go-control-plane:0.9.8 doesn't have TlsContext.
		// If it is SSL vserver, populate frontendTls with dummy first.
		// If TlsTransportSocketMatch happens, it will be populated in getFrontEndTLSConfig() function and dummy info will be overwritten.
		//if filterChain.GetTlsContext().GetCommonTlsContext().GetTlsCertificates() == nil && vserverType == "SSL" && serviceType == "TCP" {
		if vserverType == "SSL" && serviceType == "TCP" {
			csObj.FrontendTLS = append(csObj.FrontendTLS, nsconfigengine.SSLSpec{SNICert: sniCertVal, CertFilename: "dummy_xds_cert", PrivateKeyFilename: "dummy_xds_key"})
		}
		getFrontEndTLSConfig(nsConfig, csObj, filterChain, sniCertVal)
	}
	return csObjMap[csObjMapKey].(map[string]interface{}), nil
}

func getLogProxyType(nsConfig *configAdaptor, filter *xdsListener.Filter, lPort uint32) (string, string) {
	if lPort != logStreamPort && lPort != ulfdRestPort {
		return "", ""
	}

	var resourceName string
	switch filter.Name {
	case envoyUtil.TCPProxy:
		tcpProxy := &envoyFilterTcp.TcpProxy{}
		if err := getListenerFilterConfig(filter, tcpProxy); err != nil {
			log.Printf("[DEBUG] Could not identify COE service type from TCP proxy filter")
			return "", ""
		}
		resourceName = tcpProxy.GetCluster()
	case envoyUtil.HTTPConnectionManager:
		httpCM := &envoyFilterHttp.HttpConnectionManager{}
		if err := getListenerFilterConfig(filter, httpCM); err != nil {
			log.Printf("[DEBUG] Could not identify COE service type from HTTP connection manager filter")
			return "", ""
		}
		resourceName = httpCM.GetRds().GetRouteConfigName()
	}
	if strings.Contains(resourceName, nsConfig.logProxyURL) {
		// It is indeed logproxy service. Check if logstream port or ulfd port
		if lPort == logStreamPort {
			return "LOGSTREAM", "LOGSTREAM"
		}
		return "HTTP", "HTTP"
	}
	return "", ""
}

func getListenerFilterType(nsConfig *configAdaptor, filterChain *xdsListener.FilterChain, l *xdsListener.Listener) (string, string, error) {
	listenerAddress := l.GetAddress()
	tlsContextExists := false
	if filterChain.GetTransportSocket() != nil {
		tlsContextExists = true
	}
	for _, filter := range filterChain.GetFilters() {
		if listenerAddress.GetSocketAddress().GetPortValue() == 443 && listenerAddress.GetSocketAddress().GetAddress() == "0.0.0.0" && filter.Name == envoyUtil.TCPProxy {
			return "SSL", "TCP", nil
		}
		// Check for the logstream ports IFF logproxy service has been provided
		if len(nsConfig.logProxyURL) > 0 {
			lPort := listenerAddress.GetSocketAddress().GetPortValue()
			vsType, svcType := getLogProxyType(nsConfig, filter, lPort)
			if len(vsType) > 0 {
				return vsType, svcType, nil
			}
		}
		if filter.Name == envoyUtil.HTTPConnectionManager {
			if tlsContextExists {
				return "SSL", "HTTP", nil
			}
			return "HTTP", "HTTP", nil
		}
		if filter.Name == envoyUtil.TCPProxy {
			if tlsContextExists {
				return "SSL_TCP", "TCP", nil
			}
			return "TCP", "TCP", nil
		}
	}
	return "", "", fmt.Errorf("Unknown filter type")
}

func getListenerFilterConfig(filter *xdsListener.Filter, out proto.Message) error {
	switch c := filter.ConfigType.(type) {
	/*
		case *xdsListener.Filter_Config:
			if err := conversion.StructToMessage(c.Config, out); err != nil {
				return err
			}
	*/
	case *xdsListener.Filter_TypedConfig:
		if err := ptypes.UnmarshalAny(c.TypedConfig, out); err != nil {
			return err
		}
	}
	return nil
}

func getHTTPFilterConfig(filter *envoyFilterHttp.HttpFilter, out proto.Message) error {
	switch c := filter.ConfigType.(type) {
	/*
		case *envoyFilterHttp.HttpFilter_Config:
			if err := conversion.StructToMessage(c.Config, out); err != nil {
				return err
			}
	*/
	case *envoyFilterHttp.HttpFilter_TypedConfig:
		if err := ptypes.UnmarshalAny(c.TypedConfig, out); err != nil {
			return err
		}
	}
	return nil
}

// TODO: How do we identify if it is a special listener?
// 1. Check for special port 15443 (take value from ENV var)
// 2. Also check if tcp_cluster_rewrite filter is mentioned or not
func isMultiClusterListener(listener *xdsListener.Listener) bool {
	port := listener.GetAddress().GetSocketAddress().GetPortValue()
	if int(port) == multiClusterListenPort {
		return true
	}
	return false
}

// Config for special listener:
/*
	add cs vserver cs1 SSL NSIP/VIP 15443
	add ssl certkey cs1_certkey
	bind ssl vserver cs1 -certkeyname cs1_certkey
	add cs action cs1 -targetVserverExpr multiClusterExpression
	add cs policy cs1 -rule "HTTP.REQ.HOSTNAME.CONTAINS(\".global\")" -action cs1
	bind cs vserver cs1 -policyName cs1 -priority 1

*/
func multiClusterListenerConfig(nsConfig *configAdaptor, listener *xdsListener.Listener) {
	// Step 1: ldsAdd confBlock. This will create CS vserver of type SSL
	entityName := nsconfigengine.GetNSCompatibleName(listener.GetName())
	vserverAddress := listener.GetAddress().GetSocketAddress().GetAddress()
	vserverPort := listener.GetAddress().GetSocketAddress().GetPortValue()
	if vserverAddress == "0.0.0.0" {
		vserverAddress = "*"
		if nsConfig.vserverIP != "" {
			vserverAddress = nsConfig.vserverIP
		}
	} else if vserverAddress == localHostIP {
		vserverAddress = nsConfig.localHostVIP
	}

	csObj := nsconfigengine.NewCSApi(entityName, "SSL", vserverAddress, int(vserverPort))
	if vserverAddress == nsConfig.nsip {
		csObj.AllowACL = true
		csObj.AnalyticsProfileNames = nsConfig.analyticsProfiles
	}
	// Populate FrontendTLS
	certKeyFileName, keyFileName, rootCertFileName, _ := addToWatch(nsConfig, ClientCertChainFile, ClientKeyFile)
	if rootCertFileName == "" {
		_, _, rootCertFileName, _ = addToWatch(nsConfig, CAcertFile, "")
	}
	csObj.FrontendTLS = append(csObj.FrontendTLS, nsconfigengine.SSLSpec{SNICert: false, CertFilename: certKeyFileName, PrivateKeyFilename: keyFileName, RootCertFilename: rootCertFileName})
	csObj.FrontendTLSClientAuth = true
	ldsConfBl := configBlock{
		configType:   ldsAdd,
		resourceName: entityName,
		resource:     []*nsconfigengine.CSApi{csObj},
	}
	nsConfig.addConfig(&ldsConfBl)

	// Step 2: rdsAdd confBlock (csPolicyAdd). This will create CS action, policy and bind to CS vserver
	csBindings := nsconfigengine.NewCSBindingsAPI(entityName)
	binding := nsconfigengine.CSBinding{}
	binding.Rule = nsconfigengine.RouteMatch{Domains: []string{multiClusterPolExprStr}} // ".global"
	canary := nsconfigengine.Canary{TargetVserverExpr: multiClusterExpression}
	binding.CsPolicy.Canary = append(binding.CsPolicy.Canary, canary)
	csBindings.Bindings = append(csBindings.Bindings, binding)
	rdsConfBl := configBlock{
		configType:   rdsAdd,
		resourceName: entityName,
		resource:     csBindings,
	}
	nsConfig.addConfig(&rdsConfBl)

}

func listenerAdd(nsConfig *configAdaptor, listener *xdsListener.Listener) []map[string]interface{} {
	log.Printf("[TRACE] listenerAdd : %s", listener.GetName())
	log.Printf("[TRACE] listenerAdd : %v", nsconfigengine.GetLogString(listener))
	/* Config block is created inside for loop.
	 * This is to ensure that configBlock for csObj gets added to list
	 * before calling routeUpdate function.
	 * routeUpdate function adds configblock for csBindings.
	 * Thus the order of adding configBlocks matter
	 */
	csObjList := make([]map[string]interface{}, 0)
	// If it is multiCluster gateway, then special config needs to be done for special port (mostly 15443)
	// This type of listener does not provide HTTP CM filter or TCP proxy filter, and it does not have routes/cluster details
	if multiClusterIngress == true && isMultiClusterListener(listener) {
		multiClusterListenerConfig(nsConfig, listener)
		return csObjList
	}
	csObjMaps := make(map[string]interface{})

	for _, filterChain := range listener.GetFilterChains() {
		csObjMap, err := getListenerFilterChainConfig(nsConfig, csObjMaps, listener, filterChain)
		if err != nil {
			log.Printf("[DEBUG] %s", err.Error())
			continue
		}
		csObj := csObjMap["csObj"].(*nsconfigengine.CSApi)
		for _, filter := range filterChain.GetFilters() {
			resName := listener.GetName()
			if filterChain.GetName() != "" {
				resName = listener.GetName() + "_" + filterChain.GetName()
			}
			confBl := configBlock{
				configType:   ldsAdd,
				resourceName: resName,
				resource:     make([]*nsconfigengine.CSApi, 0), // TODO: Convert it to single entity instead of array of csObj
			}

			switch filterName := filter.GetName(); filterName {
			case envoyUtil.HTTPConnectionManager:
				httpCM := &envoyFilterHttp.HttpConnectionManager{}
				if err := getListenerFilterConfig(filter, httpCM); err != nil {
					log.Printf("[ERROR] listenerAdd: Error loading http connection manager: %v", err)
				} else {
					csObj.AuthSpec = getAuthConfig(nsConfig, csObj.Name, httpCM.GetHttpFilters())
					confBl.resource = append(confBl.resource.([]*nsconfigengine.CSApi), csObj)
					// Add configBlock before calling routeUpdate. But don't add for LOGSTREAM type
					// In case of COE service, vserverType and serviceType are set to LOGSTREAM
					// But CS vserver should not be created, only LB vserver should be created for LOGSTREAM
					if csObj.VserverType != "LOGSTREAM" {
						nsConfig.addConfig(&confBl)
					}
					if routeConfig := httpCM.GetRouteConfig(); routeConfig != nil {
						cdsMap := routeUpdate(nsConfig, []*xdsRoute.RouteConfiguration{routeConfig}, map[string]interface{}{"listenerName": listener.GetName(), "filterChainName": filterChain.GetName(), "serviceType": csObjMap["serviceType"].(string)})
						csObjMap["cdsNames"] = append(csObjMap["cdsNames"].([]string), cdsMap["cdsNames"].([]string)...)
					}
					if rds := httpCM.GetRds(); rds != nil {
						csObjMap["rdsNames"] = append(csObjMap["rdsNames"].([]string), rds.GetRouteConfigName())
					}
				}
			case envoyUtil.TCPProxy:
				tcpProxy := &envoyFilterTcp.TcpProxy{}
				if err := getListenerFilterConfig(filter, tcpProxy); err != nil {
					log.Printf("[ERROR] listenerAdd: Error loading tcp proxy filter: %v", err)
				} else {
					if tcpProxy.GetCluster() != "" {
						if filterChain.GetFilterChainMatch().GetServerNames() == nil {
							csObj.DefaultLbVserverName = nsconfigengine.GetNSCompatibleName(tcpProxy.GetCluster())
						} else {
							csObj.SSLForwarding = append(csObj.SSLForwarding, nsconfigengine.SSLForwardSpec{LbVserverName: nsconfigengine.GetNSCompatibleName(tcpProxy.GetCluster()), SNINames: filterChain.GetFilterChainMatch().GetServerNames()})
						}
						confBl.resource = append(confBl.resource.([]*nsconfigengine.CSApi), csObj)
						if csObj.VserverType != "LOGSTREAM" {
							nsConfig.addConfig(&confBl)
						}
						csObjMap["cdsNames"] = append(csObjMap["cdsNames"].([]string), tcpProxy.GetCluster())
					}
				}
			}
		}
	}
	for _, csObjMap := range csObjMaps {
		delete(csObjMap.(map[string]interface{}), "csObj")
		csObjList = append(csObjList, csObjMap.(map[string]interface{}))
	}
	//nsConfig.addConfig(&confBl)
	log.Printf("[TRACE] listenerAdd : %v", csObjList)
	return csObjList
}

func listenerDel(nsConfig *configAdaptor, listenerName string, filterChainNames []string) {
	log.Printf("[TRACE] listenerDel: %s filterChains(%v)", listenerName, filterChainNames)
	csObjs := make([]*nsconfigengine.CSApi, 0)
	csObjs = append(csObjs, &nsconfigengine.CSApi{Name: nsconfigengine.GetNSCompatibleName(listenerName)})
	for _, filterChainName := range filterChainNames {
		csObjs = append(csObjs, &nsconfigengine.CSApi{Name: nsconfigengine.GetNSCompatibleName(listenerName) + "_" + nsconfigengine.GetNSCompatibleName(filterChainName)})
	}
	confBl := configBlock{
		configType:   ldsDel,
		resourceName: listenerName,
		resource:     csObjs,
	}
	nsConfig.delConfig(&confBl)
}

func isLogProxyEndpoint(nsConfig *configAdaptor, clusterName string) string {
	if len(nsConfig.logProxyURL) == 0 {
		return ""
	}
	ok, port, domain := extractPortAndDomainName(clusterName)
	if !ok {
		log.Printf("[DEBUG] Can not ascertain if %s is a logproxy service", clusterName)
		return ""
	}
	if strings.Contains(domain, nsConfig.logProxyURL) {
		if port == logStreamPort {
			return "LOGSTREAM"
		} else if port == ulfdRestPort { // Prometheus
			return "ULFDREST"
		}
	}
	return ""
}

func clusterEndpointUpdate(nsConfig *configAdaptor, clusterLoadAssignment *xdsEndpoint.ClusterLoadAssignment, data interface{}) {
	var promEP string
	log.Printf("[TRACE] clusterEndpointUpdate: %s", clusterLoadAssignment.ClusterName)
	onlyIPs := true // Assume that all endpoints are IP addresses initially
	svcGpObj := nsconfigengine.NewServiceGroupAPI(nsconfigengine.GetNSCompatibleName(clusterLoadAssignment.ClusterName))
	confBl := configBlock{
		configType:   edsAdd,
		resourceName: clusterLoadAssignment.ClusterName,
		resource:     svcGpObj,
	}
	if clusterLoadAssignment.Endpoints != nil {
		for _, endpoint := range clusterLoadAssignment.Endpoints {
			for _, lbEndpoint := range endpoint.LbEndpoints {
				ep := lbEndpoint.GetEndpoint()
				address := ep.Address.GetSocketAddress().GetAddress()
				port := int(ep.Address.GetSocketAddress().GetPortValue())
				weight := int(lbEndpoint.GetLoadBalancingWeight().GetValue())
				if address == nsConfig.nsip {
					return
				}
				if address == localHostIP {
					address = nsLoopbackIP
					weight = defaultWeight
				}
				if net.ParseIP(address) == nil {
					onlyIPs = false
					svcGpObj.Members = append(svcGpObj.Members, nsconfigengine.ServiceGroupMember{Domain: address, Port: port, Weight: weight})
				} else {
					svcGpObj.Members = append(svcGpObj.Members, nsconfigengine.ServiceGroupMember{IP: address, Port: port, Weight: weight})
				}
				promEP = address
			}
		}
	}
	switch lep := isLogProxyEndpoint(nsConfig, clusterLoadAssignment.ClusterName); lep {
	case "LOGSTREAM":
		svcGpObj.IsLogProxySvcGrp = true
	case "ULFDREST":
		svcGpObj.PromEP = promEP
	}
	if onlyIPs == false {
		svcGpObj.IsIPOnlySvcGroup = false
	}
	nsConfig.addConfig(&confBl)
}

// staticAndDNSTypeClusterEndpointUpdate() is to populate Citrix ADC config based on Hosts[] field in cluster
// NOTE: Hosts field is deprecated. But it is possible that this info is still sent by xDS server.
func staticAndDNSTypeClusterEndpointUpdate(nsConfig *configAdaptor, cluster *xdsCluster.Cluster) {
	var promIPorName string
	log.Printf("[TRACE] staticAndDNSTypeClusterEndpointUpdate : %s", cluster.GetName())
	svcGpObj := nsconfigengine.NewServiceGroupAPI(nsconfigengine.GetNSCompatibleName(cluster.GetName()))
	svcGpObj.IsIPOnlySvcGroup = false

	confBl := configBlock{
		configType:   edsAdd,
		resourceName: cluster.GetName(),
		resource:     svcGpObj,
	}
	/* Hosts field is removed in go-control-plane:0.9.8.
	 * So, no ned to check for STATIC and STRICT_DNS type clusters
	 */
	if cluster.GetType() == xdsCluster.Cluster_ORIGINAL_DST {
		ok, port, domain := extractPortAndDomainName(cluster.GetName())
		if !ok {
			return
		}
		svcGpObj.Members = append(svcGpObj.Members, nsconfigengine.ServiceGroupMember{Domain: domain, Port: port})
		svcGpObj.IsIPOnlySvcGroup = false
		promIPorName = domain
	}
	switch lep := isLogProxyEndpoint(nsConfig, cluster.GetName()); lep {
	case "LOGSTREAM":
		svcGpObj.IsLogProxySvcGrp = true
	case "ULFDREST":
		svcGpObj.PromEP = promIPorName
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
			persistency.Timeout = int(hash.GetCookie().GetTtl().GetSeconds())
		} else if hash.GetConnectionProperties() != nil && hash.GetConnectionProperties().GetSourceIp() {
			persistency.SourceIP = true
		}
	}
	return persistency
}

func getFault(typedPerFilterConfig map[string]*any.Any) nsconfigengine.Fault {
	fault := nsconfigengine.Fault{}
	if _, ok := typedPerFilterConfig[envoyUtil.Fault]; ok {
		envoyFaultConfig := &envoyFault.HTTPFault{}
		if err := ptypes.UnmarshalAny(typedPerFilterConfig[envoyUtil.Fault], envoyFaultConfig); err == nil {
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
				delayserver.StartDelayServer()
				percent := envoyFaultConfig.GetDelay().GetPercentage()
				numerator := percent.GetNumerator()
				den := envoyType.FractionalPercent_DenominatorType_name[int32(percent.GetDenominator())]
				if _, ok := valueNameToNum[den]; ok {
					log.Printf("[TRACE]: Delay Percent: numerator: %v, den: %v, denominator: %v", numerator, den, valueNameToNum[den])
					fault.DelayPercent = int((numerator * 100) / uint32(valueNameToNum[den]))
					fault.DelaySeconds = int(envoyFaultConfig.GetDelay().GetFixedDelay().GetSeconds())
				} else {
					log.Printf("[ERROR]: Incorrect value of denominator (%s) in percentage! Skipping processing this Delay rule", den)
				}
			}
		}
	}
	return fault
}

func routeUpdate(nsConfig *configAdaptor, routes []*xdsRoute.RouteConfiguration, data interface{}) map[string]interface{} {
	inputMap := data.(map[string]interface{})
	log.Printf("[TRACE] routeUpdate: %v", routes)
	clusterNames := make([]string, 0)
	serviceType := inputMap["serviceType"].(string)
	listenerName := inputMap["listenerName"].(string)
	filterChainName := inputMap["filterChainName"].(string)
	entityName := nsconfigengine.GetNSCompatibleName(listenerName)
	if filterChainName != "" {
		entityName = entityName + "_" + nsconfigengine.GetNSCompatibleName(filterChainName)
	}

	csBindings := nsconfigengine.NewCSBindingsAPI(entityName)
	confBl := configBlock{
		configType:   rdsAdd,
		resourceName: entityName,
		resource:     csBindings,
	}
	for _, route := range routes {
		log.Printf("[TRACE] routeUpdate: %s - %s", route.Name, entityName)
		for _, virtualHost := range route.GetVirtualHosts() {
			for _, vroute := range virtualHost.GetRoutes() {
				binding := nsconfigengine.CSBinding{}
				routeMatch := vroute.GetMatch()
				rule := nsconfigengine.RouteMatch{Domains: virtualHost.GetDomains(), Prefix: routeMatch.GetPrefix(), Path: routeMatch.GetPath(), Regex: routeMatch.GetSafeRegex().GetRegex()}
				for _, headers := range routeMatch.GetHeaders() {
					rule.Headers = append(rule.Headers, nsconfigengine.MatchHeader{Name: headers.GetName(), Exact: headers.GetExactMatch(), Prefix: headers.GetSafeRegexMatch().GetRegex(), Regex: headers.GetPrefixMatch()})
				}
				binding.Rule = rule
				if vroute.GetTypedPerFilterConfig() != nil {
					binding.Fault = getFault(vroute.GetTypedPerFilterConfig())
				}
				log.Printf("[DEBUG] vroute.GetRoute()=%+v", vroute.GetRoute())
				binding.RwPolicy.PrefixRewrite = vroute.GetRoute().GetPrefixRewrite()
				binding.RwPolicy.HostRewrite = vroute.GetRoute().GetHostRewriteLiteral() //TODO: confirm GetHostRewriteHeader()
				//for _, reqAddHeader := range vroute.GetRoute().GetRequestHeadersToAdd()  OLD - 1.1.2
				for _, reqAddHeader := range vroute.GetRequestHeadersToAdd() {
					binding.RwPolicy.AddHeaders = append(binding.RwPolicy.AddHeaders, nsconfigengine.RwHeader{Key: reqAddHeader.GetHeader().GetKey(), Value: reqAddHeader.GetHeader().GetValue()})
				}
				var persistency *nsconfigengine.PersistencyPolicy
				if vroute.GetRoute().GetHashPolicy() != nil && serviceType == "HTTP" {
					persistency = getPersistencyPolicy(vroute.GetRoute().GetHashPolicy())
				}
				/* HTTP Mirroing */
				// TODO: Array of Mirror policies. Make MirrorPolicy also as an array.
				if vroute.GetRoute().GetRequestMirrorPolicies() != nil {
					rmp := vroute.GetRoute().GetRequestMirrorPolicies()[0] // Choosing first policy
					mirror := new(nsconfigengine.HTTPMirror)
					fullReqHdr := "http.req.full_header + http.req.body(10000000)"
					mirrorClusterName := rmp.GetCluster()
					mirror.Callout = nsconfigengine.NewHTTPCalloutPolicy(nsconfigengine.GetNSCompatibleName(mirrorClusterName), "Bool", fullReqHdr, "", "", "true")
					/* TODO: Support mirror Weight */
					mirror.Weight = defaultMirrorWeight
					/*mirror.Weight =  vroute.GetRoute().GetRequestMirrorPolicy().GetRuntimeFraction()*/
					binding.MirrorPolicy = mirror
					clusterNames = append(clusterNames, mirrorClusterName)
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
