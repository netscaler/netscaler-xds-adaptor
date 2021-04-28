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
	"citrix-xds-adaptor/tests/env"
	"container/list"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"reflect"
	"sort"
	"testing"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	xdsfault "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/common/fault/v3"
	xdshttpfault "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/fault/v3"
	envoy_jwt "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/jwt_authn/v3"
	http_conn "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	auth "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	xdstype "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	xdsutil "github.com/envoyproxy/go-control-plane/pkg/wellknown"
	ptypes "github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	duration "github.com/golang/protobuf/ptypes/duration"
	wrappers "github.com/golang/protobuf/ptypes/wrappers"
)

const (
	serverCert         = "/etc/certs/server-cert.crt"
	serverKey          = "/etc/certs/server-key.key"
	certDir            = "/etc/certs"
	EnvoyTLSSocketName = "envoy.transport_sockets.tls"
	inboundDir         = "INBOUND"
	outboundDir        = "OUTBOUND"
)

func Test_extractPortAndDomainName(t *testing.T) {
	type EO struct {
		ok         bool
		port       int
		domainName string
	}
	cases := []struct {
		input          string
		expectedOutput EO
	}{
		{"outbound|80|http|httpbin.org", EO{true, 80, "httpbin.org"}},
		{"PassthroughCluster", EO{false, 0, ""}},
		{"outbound|8080||*.bar.com", EO{true, 8080, "*.bar.com"}},
		{"inbound|8080||*", EO{true, 8080, "*"}},
		{"inbound|8080||", EO{false, 0, ""}},
		{"outbound|80abcd||httpbin.org", EO{false, 0, ""}},
		{"outbound|||httpbin.org", EO{false, 0, ""}},
		{"ppp|90", EO{false, 0, ""}},
	}

	for _, c := range cases {
		ok, port, domainName := extractPortAndDomainName(c.input)
		if (ok != c.expectedOutput.ok) || (port != c.expectedOutput.port) || (domainName != c.expectedOutput.domainName) {
			t.Errorf("Incorrect output for `%s` : expected %+v but got `ok:%t port:%d domainName:%s`", c.input, c.expectedOutput, ok, port, domainName)
		}
	}
}

func Test_getLbMethod(t *testing.T) {
	cases := []struct {
		input          cluster.Cluster_LbPolicy
		expectedOutput string
	}{
		{cluster.Cluster_ROUND_ROBIN, "ROUNDROBIN"},
		{cluster.Cluster_LEAST_REQUEST, "LEASTCONNECTION"},
		{cluster.Cluster_RANDOM, "LEASTCONNECTION"},
		{cluster.Cluster_RING_HASH, "ROUNDROBIN"},
	}

	for _, c := range cases {
		if output := getLbMethod(c.input); output != c.expectedOutput {
			t.Errorf("incorrect output for `%d` : expected `%s` but got `%s`", c.input, c.expectedOutput, output)
		}
	}
}

func getNsConfAdaptor() *configAdaptor {
	configAdaptor := new(configAdaptor)
	configAdaptor.vserverIP = "1.1.1.1"
	configAdaptor.netProfile = "k8s"
	configAdaptor.configs = list.New()
	configAdaptor.cdsHash = make(map[string]*list.Element)
	configAdaptor.edsHash = make(map[string]*list.Element)
	configAdaptor.ldsHash = make(map[string]*list.Element)
	configAdaptor.rdsHash = make(map[string]*list.Element)
	return configAdaptor
}

func verifyObject(nsConfAdaptor *configAdaptor, configType discoveryType, resourceName string, expectedResource interface{}, expectedResponse interface{}, receivedResponse interface{}) error {
	if configType == ldsAdd && len(receivedResponse.([]map[string]interface{})) > 1 {
		listenerAddRet := receivedResponse.([]map[string]interface{})
		sort.Slice(listenerAddRet[:], func(i, j int) bool {
			return listenerAddRet[i]["csVsName"].(string) < listenerAddRet[j]["csVsName"].(string)
		})
		receivedResponse = listenerAddRet
	}
	compare := reflect.DeepEqual(expectedResponse, receivedResponse)
	if compare == false {
		return fmt.Errorf("Expected response: %s/%+v    Received resource:%s/%+v", reflect.TypeOf(expectedResponse).String(), expectedResponse, reflect.TypeOf(receivedResponse).String(), receivedResponse)
	}
	confBl, err := nsConfAdaptor.getConfigByName(nsconfigengine.GetNSCompatibleName(resourceName), configType)
	if err != nil {
		return fmt.Errorf("Config block fetch failed with %v", err)
	}
	if configType == ldsAdd && len(confBl.resource.([]*nsconfigengine.CSApi)) > 1 {
		resource := confBl.resource.([]*nsconfigengine.CSApi)
		sort.Slice(resource[:], func(i, j int) bool {
			return resource[i].Name < resource[j].Name
		})
		confBl.resource = resource
	}
	log.Printf("Comparing %+s with %+s", confBl.resource, expectedResource)
	compare = reflect.DeepEqual(confBl.resource, expectedResource)
	if compare == false {
		return fmt.Errorf("Expected resource:%s/%+v    Received resource:%s/%+v", reflect.TypeOf(expectedResource).String(), expectedResource, reflect.TypeOf(confBl.resource).String(), confBl.resource)
	}
	return nil
}

func Test_clusterAdd(t *testing.T) {
	multiClusterIngress = true
	multiClusterPolExprStr = ".global"
	multiClusterListenPort = 15443
	certFileName := "../tests/tls_conn_mgmt_certs/client-cert.pem" // Single leaf certificate
	keyFileName := "../tests/tls_conn_mgmt_certs/client-key.pem"
	certData, keyData, err := env.GetCertKeyData(certFileName, keyFileName)
	if err != nil {
		t.Errorf("Failed reading Cert/Key- %v", err)
	}
	nsCertFileName := nsconfigengine.GetNSCompatibleNameHash(string([]byte(certData)), 55)
	nsKeyFileName := nsconfigengine.GetNSCompatibleNameHash(string([]byte(keyData)), 55)
	cds := env.MakeCluster("c1") // Creates a cluster of type EDS
	nsConfAdaptor := getNsConfAdaptor()
	nsConfAdaptor.client = env.GetNitroClient()
	log.Println("HTTP cluster add")
	cds.OutlierDetection = &cluster.OutlierDetection{Interval: &duration.Duration{Seconds: int64(5), Nanos: int32(100000000)}, BaseEjectionTime: &duration.Duration{Seconds: int64(7)}, ConsecutiveGatewayFailure: &wrappers.UInt32Value{Value: uint32(9)}}
	lbObj := &nsconfigengine.LBApi{Name: "c1", FrontendServiceType: "HTTP", LbMethod: "ROUNDROBIN", BackendServiceType: "HTTP", MaxConnections: 0xfffffffe, MaxHTTP2ConcurrentStreams: 1000, NetprofileName: "k8s"}
	lbObj.LbMonitorObj = new(nsconfigengine.LBMonitor)
	lbObj.LbMonitorObj.Retries = 9
	lbObj.LbMonitorObj.Interval = 5100
	lbObj.LbMonitorObj.IntervalUnits = "MSEC"
	lbObj.LbMonitorObj.DownTime = 7
	lbObj.LbMonitorObj.DownTimeUnits = "SEC"
	lbObj.AutoScale = true
	err = verifyObject(nsConfAdaptor, cdsAdd, "c1", lbObj, "c1", clusterAdd(nsConfAdaptor, cds, "HTTP"))
	if err != nil {
		t.Errorf("Verification failed - %v", err)
	}
	lbObj.LbMonitorObj = nil
	log.Println("TCP cluster add")
	lbObj.FrontendServiceType = "TCP"
	lbObj.BackendServiceType = "TCP"
	err = verifyObject(nsConfAdaptor, cdsAdd, "c1", lbObj, "c1", clusterAdd(nsConfAdaptor, cds, "TCP"))
	if err != nil {
		t.Errorf("Verification failed - %v", err)
	}

	log.Println("HTTPS cluster add")
	cds.EdsClusterConfig = &cluster.Cluster_EdsClusterConfig{EdsConfig: &core.ConfigSource{ConfigSourceSpecifier: &core.ConfigSource_Ads{Ads: &core.AggregatedConfigSource{}}}}
	cds.CircuitBreakers = &cluster.CircuitBreakers{Thresholds: []*cluster.CircuitBreakers_Thresholds{&cluster.CircuitBreakers_Thresholds{MaxConnections: &wrappers.UInt32Value{Value: uint32(500)}, MaxRequests: &wrappers.UInt32Value{Value: uint32(750)}}}}
	cds.MaxRequestsPerConnection = &wrappers.UInt32Value{Value: uint32(100)}
	tlsContextM := &auth.UpstreamTlsContext{CommonTlsContext: env.MakeTLSContext(certFileName, keyFileName, "", false)}
	tlsContext, _ := ptypes.MarshalAny(tlsContextM)
	cds.TransportSocket = &core.TransportSocket{Name: EnvoyTLSSocketName, ConfigType: &core.TransportSocket_TypedConfig{TypedConfig: tlsContext}}
	cds.OutlierDetection = &cluster.OutlierDetection{Interval: &duration.Duration{Seconds: int64(21000)}, BaseEjectionTime: &duration.Duration{Seconds: int64(7), Nanos: int32(500000000)}}
	lbObj.FrontendServiceType = "HTTP"
	lbObj.BackendServiceType = "SSL"
	lbObj.MaxConnections = 500
	lbObj.MaxRequestsPerConnection = 100
	lbObj.MaxHTTP2ConcurrentStreams = 750
	lbObj.BackendTLS = []nsconfigengine.SSLSpec{{SNICert: false, CertFilename: nsCertFileName, PrivateKeyFilename: nsKeyFileName}}
	lbObj.LbMonitorObj = nil
	err = verifyObject(nsConfAdaptor, cdsAdd, "c1", lbObj, "c1", clusterAdd(nsConfAdaptor, cds, "HTTP"))
	if err != nil {
		t.Errorf("Verification failed - %v", err)
	}

	log.Println("SSL_TCP cluster add")
	lbObj.FrontendServiceType = "TCP"
	lbObj.BackendServiceType = "SSL_TCP"
	err = verifyObject(nsConfAdaptor, cdsAdd, "c1", lbObj, "c1", clusterAdd(nsConfAdaptor, cds, "TCP"))
	if err != nil {
		t.Errorf("Verification failed - %v", err)
	}
}

func Test_clusterDel(t *testing.T) {
	multiClusterIngress = true
	multiClusterPolExprStr = ".global"
	multiClusterListenPort = 15443
	lbObj := &nsconfigengine.LBApi{Name: "c2"}
	nsConfAdaptor := getNsConfAdaptor()
	clusterDel(nsConfAdaptor, "c2")
	err := verifyObject(nsConfAdaptor, cdsDel, "c2", lbObj, nil, nil)
	if err != nil {
		t.Errorf("Verification failed - %v", err)
	}
}

func Test_clusterEndpointUpdate(t *testing.T) {
	eds := env.MakeEndpoint("e1", []env.ServiceEndpoint{{"1.1.1.1", 80, 8}, {"1.1.1.2", 80, 2}, {"www.google.com", 9080, 7}})
	svcGpObj := &nsconfigengine.ServiceGroupAPI{Name: "e1", Members: []nsconfigengine.ServiceGroupMember{{IP: "1.1.1.1", Port: 80, Weight: 8}, {IP: "1.1.1.2", Port: 80, Weight: 2}, {Domain: "www.google.com", Port: 9080, Weight: 7}}}
	nsConfAdaptor := getNsConfAdaptor()
	clusterEndpointUpdate(nsConfAdaptor, eds, nil)
	err := verifyObject(nsConfAdaptor, edsAdd, "e1", svcGpObj, nil, nil)
	if err != nil {
		t.Errorf("Verification failed - %v", err)
	}
}

func Test_isLogProxyEndpoint(t *testing.T) {
	type EI struct {
		clustername string
		logProxyURL string
	}
	cases := []struct {
		input       EI
		expectedOut string
	}{
		{EI{"outbound|5557||coe.citrix-system.svc.cluster.local", "coe.citrix-system"}, "LOGSTREAM"},
		{EI{"outbound|5563||coe.citrix-system.svc.cluster.local", "coe.citrix-system"}, "ULFDREST"},
		{EI{"outbound|5555||coe.citrix-system.svc.cluster.local", "coe.citrix-system"}, ""},
		{EI{"outbound|5563abcd||coe.citrix-system.svc.cluster.local", "coe.citrix-system"}, ""},
		{EI{"outbound|5557||coe.citrix-system.svc.cluster.local", ""}, ""},
	}
	receivedOutput := ""
	configadaptor := new(configAdaptor)
	for _, c := range cases {
		configadaptor.logProxyURL = c.input.logProxyURL
		receivedOutput = isLogProxyEndpoint(configadaptor, c.input.clustername)
		if receivedOutput != c.expectedOut {
			t.Errorf("Verification failed: expected output %s but received output %s", c.expectedOut, receivedOutput)
		}
	}
}
func Test_listenerAdd(t *testing.T) {
	multiClusterIngress = true
	multiClusterPolExprStr = ".global"
	multiClusterListenPort = 15443
	certFileName := "../tests/tls_conn_mgmt_certs/client-cert.pem" // Single leaf certificate
	keyFileName := "../tests/tls_conn_mgmt_certs/client-key.pem"
	rootCertFile := "../tests/tls_conn_mgmt_certs/root-cert.pem"
	certChainFile := "../tests/tls_conn_mgmt_certs/cert-chain.pem"
	certFile := "../tests/tls_conn_mgmt_certs/cert-chain.pem"
	keyFile := "../tests/tls_conn_mgmt_certs/key.pem"
	nsConfAdaptor := getNsConfAdaptor()
	nsConfAdaptor.client = env.GetNitroClient()
	certData, keyData, err := env.GetCertKeyData(certFileName, keyFileName)
	if err != nil {
		t.Errorf("Failed reading Cert/Key- %v", err)
	}
	nsCertFileName := nsconfigengine.GetNSCompatibleNameHash(string([]byte(certData)), 55)
	nsKeyFileName := nsconfigengine.GetNSCompatibleNameHash(string([]byte(keyData)), 55)
	t.Logf("HTTP listener add")
	err = os.MkdirAll(certDir, 0777)
	if err != nil {
		t.Errorf("Could not create directory /etc/certs")
	}
	err = env.SetCertEnv(certDir, rootCertFile, certChainFile, certFile, keyFile)
	if err != nil {
		t.Errorf("Could not create certificate environment. %s", err.Error())
	}
	certData, keyData, err = env.GetCertKeyData(certChainFile, keyFile)
	if err != nil {
		t.Errorf("Failed reading Cert/Key- %v", err)
	}
	nsCertName := nsconfigengine.GetNSCompatibleNameHash(string([]byte(certData)), 55)
	nsKeyName := nsconfigengine.GetNSCompatibleNameHash(string([]byte(keyData)), 55)
	lds, err := env.MakeHttpListener("l1", "10.0.0.0", 80, outboundDir, "r1")
	if err != nil {
		t.Errorf("MakeHttpListener failed with %v", err)
	}
	csObj := []*nsconfigengine.CSApi{&nsconfigengine.CSApi{Name: "l1", IP: "10.0.0.0", Port: 80, VserverType: "HTTP", AllowACL: false}}
	err = verifyObject(nsConfAdaptor, ldsAdd, "l1", csObj, []map[string]interface{}{{"rdsNames": []string{"r1"}, "cdsNames": []string{}, "listenerName": "l1", "csVsName": "l1", "serviceType": "HTTP"}}, listenerAdd(nsConfAdaptor, lds))
	if err != nil {
		t.Errorf("Verification failed - %v", err)
	}

	t.Logf("TCP listener add")
	lds, err = env.MakeTcpListener("l2", "20.0.0.0", 25, outboundDir, "cl1")
	if err != nil {
		t.Errorf("MakeTcpListener failed with %v", err)
	}
	csObj = []*nsconfigengine.CSApi{&nsconfigengine.CSApi{Name: "l2", IP: "20.0.0.0", Port: 25, VserverType: "TCP", AllowACL: false, DefaultLbVserverName: "cl1"}}
	err = verifyObject(nsConfAdaptor, ldsAdd, "l2", csObj, []map[string]interface{}{{"rdsNames": []string{}, "cdsNames": []string{"cl1"}, "listenerName": "l2", "csVsName": "l2", "serviceType": "TCP"}}, listenerAdd(nsConfAdaptor, lds))
	if err != nil {
		t.Errorf("Verification failed - %v", err)
	}
	t.Logf("HTTPS listener add with SDS TLS transport socket")
	lds, err = env.MakeHttpsListener("l3s", "30.2.0.1", 443, outboundDir, "r1", certFileName, keyFileName, "", false, true, false, true)
	if err != nil {
		t.Errorf("MakeHttpsListener failed with %v", err)
	}
	csObj = []*nsconfigengine.CSApi{&nsconfigengine.CSApi{Name: "l3s", IP: "30.2.0.1", Port: 443, VserverType: "SSL", AllowACL: false, FrontendTLS: []nsconfigengine.SSLSpec{{SNICert: false, CertFilename: nsCertName, PrivateKeyFilename: nsKeyName, RootCertFilename: nsCertName + "_ic1"}}}}
	err = verifyObject(nsConfAdaptor, ldsAdd, "l3s", csObj, []map[string]interface{}{{"rdsNames": []string{"r1"}, "cdsNames": []string{}, "listenerName": "l3s", "csVsName": "l3s", "serviceType": "HTTP"}}, listenerAdd(nsConfAdaptor, lds))
	if err != nil {
		t.Errorf("Verification failed - %v", err)
	}

	t.Logf("HTTPS listener add with downstream TLS transport socket")
	lds, err = env.MakeHttpsListener("l2s", "30.0.0.1", 443, outboundDir, "r1", certFileName, keyFileName, "", false, true, false, false)
	if err != nil {
		t.Errorf("MakeHttpsListener failed with %v", err)
	}
	csObj = []*nsconfigengine.CSApi{&nsconfigengine.CSApi{Name: "l2s", IP: "30.0.0.1", Port: 443, VserverType: "SSL", AllowACL: false, FrontendTLS: []nsconfigengine.SSLSpec{{SNICert: false, CertFilename: nsCertFileName, PrivateKeyFilename: nsKeyFileName}}}}
	err = verifyObject(nsConfAdaptor, ldsAdd, "l2s", csObj, []map[string]interface{}{{"rdsNames": []string{"r1"}, "cdsNames": []string{}, "listenerName": "l2s", "csVsName": "l2s", "serviceType": "HTTP"}}, listenerAdd(nsConfAdaptor, lds))
	if err != nil {
		t.Errorf("Verification failed - %v", err)
	}
	t.Logf("HTTP multiple filterchain listener add")
	r1 := env.MakeRoute("r1", []env.RouteInfo{{Domain: "*", ClusterName: "c1"}})
	f1, err := env.MakeHttpFilter("lm1", "", r1)
	if err != nil {
		t.Errorf("MakeHttpFilter failed %v", err)
	}
	fc1 := env.MakeFilterChain("1.1.1.1", 32, 9090, "", "f1", f1)
	f2, err := env.MakeHttpFilter("lm1", "r2", nil)
	if err != nil {
		t.Errorf("MakeHttpFilter failed %v", err)
	}
	fc2 := env.MakeFilterChain("2.1.1.1", 32, 9070, "", "f2", f2)
	f3, err := env.MakeTcpFilter("lm1", "c3")
	if err != nil {
		t.Errorf("MakeTcpFilter failed %v", err)
	}
	fc3 := env.MakeFilterChain("1.1.1.1", 32, 1010, "", "f3", f3)
	lds = env.MakeListenerFilterChains("lm1", "0.0.0.0", 15001, outboundDir, []*listener.FilterChain{fc1, fc2, fc3})
	csObjExpLm1F1 := []*nsconfigengine.CSApi{
		{Name: "lm1_f1", IP: "1.1.1.1", Port: 9090, VserverType: "HTTP", AllowACL: false},
	}
	csObjExpLm1F2 := []*nsconfigengine.CSApi{
		{Name: "lm1_f2", IP: "2.1.1.1", Port: 9070, VserverType: "HTTP", AllowACL: false},
	}
	csObjExpLm1F3 := []*nsconfigengine.CSApi{
		{Name: "lm1_f3", IP: "1.1.1.1", Port: 1010, VserverType: "TCP", AllowACL: false, DefaultLbVserverName: "c3"},
	}
	listenerAddRetMapExp := []map[string]interface{}{
		{"rdsNames": []string{}, "cdsNames": []string{"c1"}, "listenerName": "lm1", "csVsName": "lm1_f1", "serviceType": "HTTP"},
		{"rdsNames": []string{"r2"}, "cdsNames": []string{}, "listenerName": "lm1", "csVsName": "lm1_f2", "serviceType": "HTTP"},
		{"rdsNames": []string{}, "cdsNames": []string{"c3"}, "listenerName": "lm1", "csVsName": "lm1_f3", "serviceType": "TCP"},
	}
	err = verifyObject(nsConfAdaptor, ldsAdd, "lm1_f1", csObjExpLm1F1, listenerAddRetMapExp, listenerAdd(nsConfAdaptor, lds))
	if err != nil {
		t.Errorf("Verification failed - %v", err)
	}
	err = verifyObject(nsConfAdaptor, ldsAdd, "lm1_f2", csObjExpLm1F2, listenerAddRetMapExp, listenerAdd(nsConfAdaptor, lds))
	if err != nil {
		t.Errorf("Verification failed - %v", err)
	}
	err = verifyObject(nsConfAdaptor, ldsAdd, "lm1_f3", csObjExpLm1F3, listenerAddRetMapExp, listenerAdd(nsConfAdaptor, lds))
	if err != nil {
		t.Errorf("Verification failed - %v", err)
	}
	if err := os.RemoveAll(certDir); err != nil {
		t.Errorf("Could not delete /etc/certs")
	}
}

func Test_listenerDel(t *testing.T) {
	nsConfAdaptor := getNsConfAdaptor()
	t.Logf("HTTP listener delete")
	csObj := []*nsconfigengine.CSApi{&nsconfigengine.CSApi{Name: "l3"}}
	listenerDel(nsConfAdaptor, "l3", []string{"l3"})
	err := verifyObject(nsConfAdaptor, ldsDel, "l3", csObj, nil, nil)
	if err != nil {
		t.Errorf("Verification failed - %v", err)
	}
	t.Logf("HTTP listener filterchains delete")
	csObj = []*nsconfigengine.CSApi{{Name: "lm3"}, {Name: "lm3_fc1"}, {Name: "lm3_fc2"}}
	listenerDel(nsConfAdaptor, "lm3", []string{"lm3", "lm3_fc1", "lm3_fc2"})
	err = verifyObject(nsConfAdaptor, ldsDel, "lm3", csObj, nil, nil)
	if err != nil {
		t.Errorf("Verification failed - %v", err)
	}
}

func Test_routeUpdate(t *testing.T) {
	nsConfAdaptor := getNsConfAdaptor()
	t.Logf("route update")
	csBindings := nsconfigengine.NewCSBindingsAPI("cs1")
	csBindings.Bindings = []nsconfigengine.CSBinding{{Rule: nsconfigengine.RouteMatch{Domains: []string{"*"}, Prefix: "/"}, CsPolicy: nsconfigengine.CsPolicy{Canary: []nsconfigengine.Canary{{LbVserverName: "cl1", LbVserverType: "HTTP", Weight: 100}}}}}
	rds := env.MakeRoute("rt1", []env.RouteInfo{{Domain: "*", ClusterName: "cl1"}})
	err := verifyObject(nsConfAdaptor, rdsAdd, "cs1", csBindings, map[string]interface{}{"cdsNames": []string{"cl1"}, "serviceType": "HTTP"}, routeUpdate(nsConfAdaptor, []*route.RouteConfiguration{rds}, map[string]interface{}{"listenerName": "cs1", "csVsName": "cs1", "serviceType": "HTTP"}))
	if err != nil {
		t.Errorf("Verification failed - %v", err)
	}
}

func Test_clusterAdd_transportSocket(t *testing.T) {
	certFileName := "../tests/tls_conn_mgmt_certs/client-cert.pem"
	keyFileName := "../tests/tls_conn_mgmt_certs/client-key.pem"
	//certFileName := "/etc/certs/server-cert.crt"
	//`keyFileName := "/etc/certs/server-key.key"
	cds := env.MakeCluster("c1") // Creates a cluster of type EDS
	nsConfAdaptor := getNsConfAdaptor()
	nsConfAdaptor.client = env.GetNitroClient()
	certData, keyData, err := env.GetCertKeyData(certFileName, keyFileName)
	if err != nil {
		t.Errorf("Failed reading Cert/Key- %v", err)
	}
	nsCertFileName := nsconfigengine.GetNSCompatibleNameHash(string([]byte(certData)), 55)
	nsKeyFileName := nsconfigengine.GetNSCompatibleNameHash(string([]byte(keyData)), 55)
	log.Println("HTTP cluster add")
	cds.OutlierDetection = &cluster.OutlierDetection{Interval: &duration.Duration{Seconds: int64(5), Nanos: int32(100000000)}, BaseEjectionTime: &duration.Duration{Seconds: int64(7)}, ConsecutiveGatewayFailure: &wrappers.UInt32Value{Value: uint32(9)}}
	lbObj := &nsconfigengine.LBApi{Name: "c1", FrontendServiceType: "HTTP", LbMethod: "ROUNDROBIN", BackendServiceType: "HTTP", MaxConnections: 0xfffffffe, MaxHTTP2ConcurrentStreams: 1000, NetprofileName: "k8s"}
	lbObj.LbMonitorObj = new(nsconfigengine.LBMonitor)
	lbObj.LbMonitorObj.Retries = 9
	lbObj.LbMonitorObj.Interval = 5100
	lbObj.LbMonitorObj.IntervalUnits = "MSEC"
	lbObj.LbMonitorObj.DownTime = 7
	lbObj.LbMonitorObj.DownTimeUnits = "SEC"
	lbObj.AutoScale = true
	err = verifyObject(nsConfAdaptor, cdsAdd, "c1", lbObj, "c1", clusterAdd(nsConfAdaptor, cds, "HTTP"))
	if err != nil {
		t.Errorf("Verification failed - %v", err)
	}
	lbObj.LbMonitorObj = nil

	log.Println("TCP cluster add")
	lbObj.FrontendServiceType = "TCP"
	lbObj.BackendServiceType = "TCP"
	err = verifyObject(nsConfAdaptor, cdsAdd, "c1", lbObj, "c1", clusterAdd(nsConfAdaptor, cds, "TCP"))
	if err != nil {
		t.Errorf("Verification failed - %v", err)
	}

	log.Println("HTTPS cluster add")
	cds.EdsClusterConfig = &cluster.Cluster_EdsClusterConfig{EdsConfig: &core.ConfigSource{ConfigSourceSpecifier: &core.ConfigSource_Ads{Ads: &core.AggregatedConfigSource{}}}}
	cds.CircuitBreakers = &cluster.CircuitBreakers{Thresholds: []*cluster.CircuitBreakers_Thresholds{&cluster.CircuitBreakers_Thresholds{MaxConnections: &wrappers.UInt32Value{Value: uint32(500)}, MaxRequests: &wrappers.UInt32Value{Value: uint32(750)}}}}
	tlsContextM := &auth.UpstreamTlsContext{CommonTlsContext: env.MakeTLSContext(certFileName, keyFileName, "", false)}
	tlsContext, _ := ptypes.MarshalAny(tlsContextM)

	cds.MaxRequestsPerConnection = &wrappers.UInt32Value{Value: uint32(100)}
	transportSocket := &core.TransportSocket{
		Name:       EnvoyTLSSocketName,
		ConfigType: &core.TransportSocket_TypedConfig{TypedConfig: tlsContext},
	}
	cds.TransportSocketMatches = []*cluster.Cluster_TransportSocketMatch{
		{
			Name:            "tlsMode-istio",
			TransportSocket: transportSocket,
		},
	}
	cds.OutlierDetection = &cluster.OutlierDetection{Interval: &duration.Duration{Seconds: int64(21000)}, BaseEjectionTime: &duration.Duration{Seconds: int64(7), Nanos: int32(500000000)}}
	lbObj.FrontendServiceType = "HTTP"
	lbObj.BackendServiceType = "SSL"
	lbObj.MaxConnections = 500
	lbObj.MaxRequestsPerConnection = 100
	lbObj.MaxHTTP2ConcurrentStreams = 750
	lbObj.BackendTLS = []nsconfigengine.SSLSpec{{SNICert: false, CertFilename: nsCertFileName, PrivateKeyFilename: nsKeyFileName}}
	lbObj.LbMonitorObj = nil
	err = verifyObject(nsConfAdaptor, cdsAdd, "c1", lbObj, "c1", clusterAdd(nsConfAdaptor, cds, "HTTP"))
	if err != nil {
		t.Errorf("Verification failed - %v", err)
	}

	log.Println("SSL_TCP cluster add")
	lbObj.FrontendServiceType = "TCP"
	lbObj.BackendServiceType = "SSL_TCP"
	err = verifyObject(nsConfAdaptor, cdsAdd, "c1", lbObj, "c1", clusterAdd(nsConfAdaptor, cds, "TCP"))
	if err != nil {
		t.Errorf("Verification failed - %v", err)
	}
}

func Test_clusterAddInline(t *testing.T) {
	certFileName := "../tests/tls_conn_mgmt_certs/client-cert.pem"
	keyFileName := "../tests/tls_conn_mgmt_certs/client-key.pem"
	clientCert, err := ioutil.ReadFile(certFileName)
	if err != nil {
		t.Errorf("Could not Read Cert File - %v", err)
	}
	clientKey, err := ioutil.ReadFile(keyFileName)
	if err != nil {
		t.Errorf("Could not Read Key File - %v", err)
	}
	cds := env.MakeCluster("c1") // Creates a cluster of type EDS
	nsConfAdaptor := getNsConfAdaptor()
	nsConfAdaptor.client = env.GetNitroClient()
	log.Println("HTTP cluster add")
	cds.OutlierDetection = &cluster.OutlierDetection{Interval: &duration.Duration{Seconds: int64(5), Nanos: int32(100000000)}, BaseEjectionTime: &duration.Duration{Seconds: int64(7)}, ConsecutiveGatewayFailure: &wrappers.UInt32Value{Value: uint32(9)}}
	lbObj := &nsconfigengine.LBApi{Name: "c1", FrontendServiceType: "HTTP", LbMethod: "ROUNDROBIN", BackendServiceType: "HTTP", MaxConnections: 0xfffffffe, MaxHTTP2ConcurrentStreams: 1000, NetprofileName: "k8s"}
	lbObj.LbMonitorObj = new(nsconfigengine.LBMonitor)
	lbObj.LbMonitorObj.Retries = 9
	lbObj.LbMonitorObj.Interval = 5100
	lbObj.LbMonitorObj.IntervalUnits = "MSEC"
	lbObj.LbMonitorObj.DownTime = 7
	lbObj.LbMonitorObj.DownTimeUnits = "SEC"
	lbObj.AutoScale = true
	err = verifyObject(nsConfAdaptor, cdsAdd, "c1", lbObj, "c1", clusterAdd(nsConfAdaptor, cds, "HTTP"))
	if err != nil {
		t.Errorf("Verification failed - %v", err)
	}
	lbObj.LbMonitorObj = nil
	log.Println("TCP cluster add")
	lbObj.FrontendServiceType = "TCP"
	lbObj.BackendServiceType = "TCP"
	err = verifyObject(nsConfAdaptor, cdsAdd, "c1", lbObj, "c1", clusterAdd(nsConfAdaptor, cds, "TCP"))
	if err != nil {
		t.Errorf("Verification failed - %v", err)
	}

	log.Println("HTTPS cluster add")
	cds.EdsClusterConfig = &cluster.Cluster_EdsClusterConfig{EdsConfig: &core.ConfigSource{ConfigSourceSpecifier: &core.ConfigSource_Ads{Ads: &core.AggregatedConfigSource{}}}}
	cds.CircuitBreakers = &cluster.CircuitBreakers{Thresholds: []*cluster.CircuitBreakers_Thresholds{&cluster.CircuitBreakers_Thresholds{MaxConnections: &wrappers.UInt32Value{Value: uint32(500)}, MaxRequests: &wrappers.UInt32Value{Value: uint32(750)}}}}
	cds.MaxRequestsPerConnection = &wrappers.UInt32Value{Value: uint32(100)}

	tlsContextM := &auth.UpstreamTlsContext{CommonTlsContext: env.MakeTLSContext(certFileName, keyFileName, "", true)}
	tlsContext, _ := ptypes.MarshalAny(tlsContextM)
	cds.TransportSocket = &core.TransportSocket{Name: EnvoyTLSSocketName, ConfigType: &core.TransportSocket_TypedConfig{TypedConfig: tlsContext}}

	cds.OutlierDetection = &cluster.OutlierDetection{Interval: &duration.Duration{Seconds: int64(21000)}, BaseEjectionTime: &duration.Duration{Seconds: int64(7), Nanos: int32(500000000)}}
	lbObj.FrontendServiceType = "HTTP"
	lbObj.BackendServiceType = "SSL"
	lbObj.MaxConnections = 500
	lbObj.MaxRequestsPerConnection = 100
	lbObj.MaxHTTP2ConcurrentStreams = 750
	lbObj.BackendTLS = []nsconfigengine.SSLSpec{{SNICert: false, Cert: string(clientCert), PrivateKey: string(clientKey)}}
	lbObj.LbMonitorObj = nil
	err = verifyObject(nsConfAdaptor, cdsAdd, "c1", lbObj, "c1", clusterAdd(nsConfAdaptor, cds, "HTTP"))
	if err != nil {
		t.Errorf("Verification failed - %v", err)
	}

	log.Println("SSL_TCP cluster add")
	lbObj.FrontendServiceType = "TCP"
	lbObj.BackendServiceType = "SSL_TCP"
	err = verifyObject(nsConfAdaptor, cdsAdd, "c1", lbObj, "c1", clusterAdd(nsConfAdaptor, cds, "TCP"))
	if err != nil {
		t.Errorf("Verification failed - %v", err)
	}
}
func Test_clusterAdd_SDS(t *testing.T) {
	cds := env.MakeCluster("c1") // Creates a cluster of type EDS
	nsConfAdaptor := getNsConfAdaptor()
	nsConfAdaptor.client = env.GetNitroClient()
	log.Println("HTTP cluster add")
	rootCertFile := "../tests/tls_conn_mgmt_certs/root-cert.pem"
	certChainFile := "../tests/tls_conn_mgmt_certs/cert-chain.pem"
	certFile := "../tests/tls_conn_mgmt_certs/cert-chain.pem"
	keyFile := "../tests/tls_conn_mgmt_certs/key.pem"
	err := os.MkdirAll(certDir, 0777)
	if err != nil {
		t.Errorf("Could not create directory /etc/certs")
	}
	err = env.SetCertEnv(certDir, rootCertFile, certChainFile, certFile, keyFile)
	if err != nil {
		t.Errorf("Could not create certificate environment. %s", err.Error())
	}
	certData, keyData, err := env.GetCertKeyData(certChainFile, keyFile)
	if err != nil {
		t.Errorf("Failed reading Cert/Key- %v", err)
	}
	nsCertName := nsconfigengine.GetNSCompatibleNameHash(string([]byte(certData)), 55)
	nsKeyName := nsconfigengine.GetNSCompatibleNameHash(string([]byte(keyData)), 55)

	cds.OutlierDetection = &cluster.OutlierDetection{Interval: &duration.Duration{Seconds: int64(5), Nanos: int32(100000000)}, BaseEjectionTime: &duration.Duration{Seconds: int64(7)}, ConsecutiveGatewayFailure: &wrappers.UInt32Value{Value: uint32(9)}}
	lbObj := &nsconfigengine.LBApi{Name: "c1", FrontendServiceType: "HTTP", LbMethod: "ROUNDROBIN", BackendServiceType: "HTTP", MaxConnections: 0xfffffffe, MaxHTTP2ConcurrentStreams: 1000, NetprofileName: "k8s"}
	lbObj.LbMonitorObj = new(nsconfigengine.LBMonitor)
	lbObj.LbMonitorObj.Retries = 9
	lbObj.LbMonitorObj.Interval = 5100
	lbObj.LbMonitorObj.IntervalUnits = "MSEC"
	lbObj.LbMonitorObj.DownTime = 7
	lbObj.LbMonitorObj.DownTimeUnits = "SEC"
	lbObj.AutoScale = true
	err = verifyObject(nsConfAdaptor, cdsAdd, "c1", lbObj, "c1", clusterAdd(nsConfAdaptor, cds, "HTTP"))
	if err != nil {
		t.Errorf("Verification failed - %v", err)
	}
	lbObj.LbMonitorObj = nil

	log.Println("TCP cluster add")
	lbObj.FrontendServiceType = "TCP"
	lbObj.BackendServiceType = "TCP"
	err = verifyObject(nsConfAdaptor, cdsAdd, "c1", lbObj, "c1", clusterAdd(nsConfAdaptor, cds, "TCP"))
	if err != nil {
		t.Errorf("Verification failed - %v", err)
	}

	log.Println("HTTPS cluster add")
	cds.EdsClusterConfig = &cluster.Cluster_EdsClusterConfig{EdsConfig: &core.ConfigSource{ConfigSourceSpecifier: &core.ConfigSource_Ads{Ads: &core.AggregatedConfigSource{}}}}
	cds.CircuitBreakers = &cluster.CircuitBreakers{Thresholds: []*cluster.CircuitBreakers_Thresholds{&cluster.CircuitBreakers_Thresholds{MaxConnections: &wrappers.UInt32Value{Value: uint32(500)}, MaxRequests: &wrappers.UInt32Value{Value: uint32(750)}}}}
	tlsContext := &auth.UpstreamTlsContext{CommonTlsContext: env.CreateSDSTlsStreamSDS()}
	cds.MaxRequestsPerConnection = &wrappers.UInt32Value{Value: uint32(100)}
	mt, _ := ptypes.MarshalAny(tlsContext)
	transportSocket := &core.TransportSocket{
		Name: EnvoyTLSSocketName,
		ConfigType: &core.TransportSocket_TypedConfig{
			TypedConfig: mt,
		},
	}
	cds.TransportSocketMatches = []*cluster.Cluster_TransportSocketMatch{
		{
			Name:            "tlsMode-istio",
			TransportSocket: transportSocket,
		},
	}
	cds.OutlierDetection = &cluster.OutlierDetection{Interval: &duration.Duration{Seconds: int64(21000)}, BaseEjectionTime: &duration.Duration{Seconds: int64(7), Nanos: int32(500000000)}}
	lbObj.FrontendServiceType = "HTTP"
	lbObj.BackendServiceType = "SSL"
	lbObj.MaxConnections = 500
	lbObj.MaxRequestsPerConnection = 100
	lbObj.MaxHTTP2ConcurrentStreams = 750
	lbObj.BackendTLS = []nsconfigengine.SSLSpec{{SNICert: false, CertFilename: nsCertName, PrivateKeyFilename: nsKeyName, RootCertFilename: nsCertName + "_ic1"}}
	lbObj.LbMonitorObj = nil
	err = verifyObject(nsConfAdaptor, cdsAdd, "c1", lbObj, "c1", clusterAdd(nsConfAdaptor, cds, "HTTP"))
	if err != nil {
		t.Errorf("Verification failed - %v", err)
	}

	log.Println("SSL_TCP cluster add")
	lbObj.FrontendServiceType = "TCP"
	lbObj.BackendServiceType = "SSL_TCP"
	err = verifyObject(nsConfAdaptor, cdsAdd, "c1", lbObj, "c1", clusterAdd(nsConfAdaptor, cds, "TCP"))
	if err != nil {
		t.Errorf("Verification failed - %v", err)
	}
	if err := os.RemoveAll(certDir); err != nil {
		t.Errorf("Could not delete /etc/certs")
	}
}

func Test_getAuthConfig(t *testing.T) {
	jwks := []byte(`{ "keys":[ {"e":"AQAB","kid":"DHFbpoIUqrY8t2zpA2qXfCmr5VO5ZEr4RzHU_-envvQ","kty":"RSA","n":"xAE7eB6qugXyCAG3yhh7pkDkT65pHymX-P7KfIupjf59vsdo91bSP9C8H07pSAGQO1MV_xFj9VswgsCg4R6otmg5PV2He95lZdHtOcU5DXIg_pbhLdKXbi66GlVeK6ABZOUW3WYtnNHD-91gVuoeJT_DwtGGcp4ignkgXfkiEm4sw-4sfb4qdt5oLbyVpmW6x9cfa7vs2WTfURiCrBoUqgBo_-4WTiULmmHSGZHOjzwa8WtrtOQGsAFjIbno85jp6MnGGGZPYZbDAa_b3y5u-YpW7ypZrvD8BgtKVjgtQgZhLAGezMt0ua3DRrWnKqTZ0BJ_EyxOGuHJrLsn00fnMQ"}]}`)
	jwtKey := fmt.Sprintf("%v", string(jwks))
	var httpFilters []*http_conn.HttpFilter
	jwtAuthM := &envoy_jwt.JwtAuthentication{
		Rules: []*envoy_jwt.RequirementRule{
			{
				Match: &route.RouteMatch{
					PathSpecifier: &route.RouteMatch_Prefix{
						Prefix: "/",
					},
				},
				RequirementType: &envoy_jwt.RequirementRule_Requires{
					Requires: &envoy_jwt.JwtRequirement{
						RequiresType: &envoy_jwt.JwtRequirement_RequiresAny{
							RequiresAny: &envoy_jwt.JwtRequirementOrList{
								Requirements: []*envoy_jwt.JwtRequirement{
									{
										RequiresType: &envoy_jwt.JwtRequirement_ProviderName{
											ProviderName: "origins-0",
										},
									},
								},
							},
						},
					},
				},
			},
		},
		Providers: map[string]*envoy_jwt.JwtProvider{
			"origins-0": {
				Issuer: "https://secret.foo.com",
				JwksSourceSpecifier: &envoy_jwt.JwtProvider_LocalJwks{
					LocalJwks: &core.DataSource{
						Specifier: &core.DataSource_InlineString{
							InlineString: jwtKey,
						},
					},
				},
				Forward:              false,
				PayloadInMetadata:    "https://secret.foo.com",
				ForwardPayloadHeader: "x-header",
				Audiences:            []string{"a1", "a2"},
			},
		},
	}
	jwtAuth, _ := ptypes.MarshalAny(jwtAuthM)

	httpFilter := http_conn.HttpFilter{
		Name: "envoy.filters.http.jwt_authn",
		ConfigType: &http_conn.HttpFilter_TypedConfig{
			TypedConfig: jwtAuth,
		},
	}
	httpFilters = append(httpFilters, &httpFilter)
	expectedAuthSpec := &nsconfigengine.AuthSpec{Name: "l1", Issuer: "https://secret.foo.com", Jwks: jwtKey, Forward: false, ForwardHeader: "x-header", Audiences: []string{"a1", "a2"}, FrontendTLS: []nsconfigengine.SSLSpec{{SNICert: false, CertFilename: ClientCertChainFile, PrivateKeyFilename: ClientKeyFile}}}
	t.Logf("Get AuthSpecConfig")
	nsConfAdaptor := getNsConfAdaptor()
	authSpec := getAuthConfig(nsConfAdaptor, "l1", httpFilters)
	compare := reflect.DeepEqual(expectedAuthSpec, authSpec)
	if compare == false {
		t.Errorf("Expected AuthSpec:%+v    Received AuthSpec:%+v", expectedAuthSpec, authSpec)
	}
}

func Test_getPersistencyPolicy(t *testing.T) {
	hashPolicy := route.RouteAction_HashPolicy{
		PolicySpecifier: &route.RouteAction_HashPolicy_Cookie_{
			Cookie: &route.RouteAction_HashPolicy_Cookie{
				Name: "hash-cookie",
				Ttl:  &duration.Duration{Seconds: int64(1)},
			},
		},
	}
	var hashPolicies []*route.RouteAction_HashPolicy
	t.Logf("Testing getPersistency")
	hashPolicies = append(hashPolicies, &hashPolicy)
	persistency := getPersistencyPolicy(hashPolicies)
	expectedPersistency := &nsconfigengine.PersistencyPolicy{HeaderName: "", CookieName: "hash-cookie", Timeout: 1, SourceIP: false}
	compare := reflect.DeepEqual(expectedPersistency, persistency)
	if compare == false {
		t.Errorf("Expected PersistencyPolicy:%+v    Received PersistencyPolicy=%+v", expectedPersistency, persistency)
	}

	hashPolicy = route.RouteAction_HashPolicy{
		PolicySpecifier: &route.RouteAction_HashPolicy_ConnectionProperties_{
			ConnectionProperties: &route.RouteAction_HashPolicy_ConnectionProperties{
				SourceIp: true,
			},
		},
	}
	hashPolicies = append(hashPolicies, &hashPolicy)
	persistency = getPersistencyPolicy(hashPolicies)
	expectedPersistency = &nsconfigengine.PersistencyPolicy{SourceIP: true}
	compare = reflect.DeepEqual(expectedPersistency, persistency)
	if compare == false {
		t.Errorf("Expected PersistencyPolicy:%+v    Received PersistencyPolicy=%+v", expectedPersistency, persistency)
	}
	hashPolicy = route.RouteAction_HashPolicy{
		PolicySpecifier: &route.RouteAction_HashPolicy_Header_{
			Header: &route.RouteAction_HashPolicy_Header{
				HeaderName: "x-header",
			},
		},
	}
	hashPolicies = append(hashPolicies, &hashPolicy)
	persistency = getPersistencyPolicy(hashPolicies)
	expectedPersistency = &nsconfigengine.PersistencyPolicy{HeaderName: "x-header", SourceIP: false}
	compare = reflect.DeepEqual(expectedPersistency, persistency)
	if compare == false {
		t.Errorf("Expected PersistencyPolicy:%+v    Received PersistencyPolicy=%+v", expectedPersistency, persistency)
	}
}

func percentToFractPercent(percent float64) *xdstype.FractionalPercent {
	return &xdstype.FractionalPercent{
		Numerator:   uint32(percent * 10000),
		Denominator: xdstype.FractionalPercent_MILLION,
	}
}
func Test_getFault(t *testing.T) {
	typedPerFilterConfig := make(map[string]*any.Any)
	fault := xdshttpfault.HTTPFault{}
	fault.Delay = &xdsfault.FaultDelay{} //Type: xdsfault.FaultDelay_FIXED
	fault.Delay.Percentage = percentToFractPercent(50)
	fault.Delay.FaultDelaySecifier = &xdsfault.FaultDelay_FixedDelay{
		FixedDelay: &duration.Duration{Seconds: int64(1)},
	}
	faultp, _ := ptypes.MarshalAny(&fault)
	typedPerFilterConfig[xdsutil.Fault] = faultp
	outFault := getFault(typedPerFilterConfig)
	expectedFault := nsconfigengine.Fault{DelayPercent: 50, DelaySeconds: 1, AbortPercent: 0, AbortHTTPStatus: 0}
	compare := reflect.DeepEqual(expectedFault, outFault)
	if compare == false {
		t.Errorf("Expected PersistencyPolicy:%+v    Received PersistencyPolicy=%+v", expectedFault, outFault)
	}

	fault.Abort = &xdshttpfault.FaultAbort{}
	fault.Abort.Percentage = percentToFractPercent(10)
	fault.Abort.ErrorType = &xdshttpfault.FaultAbort_HttpStatus{
		HttpStatus: uint32(501),
	}
	faultp, _ = ptypes.MarshalAny(&fault)
	typedPerFilterConfig[xdsutil.Fault] = faultp
	outFault = getFault(typedPerFilterConfig)
	expectedFault = nsconfigengine.Fault{AbortPercent: 10, AbortHTTPStatus: 501, DelayPercent: 50, DelaySeconds: 1}
	compare = reflect.DeepEqual(expectedFault, outFault)
	if compare == false {
		t.Errorf("Expected PersistencyPolicy:%+v    Received PersistencyPolicy=%+v", expectedFault, outFault)
	}
}

func Test_isEgressGateway(t *testing.T) {
	testCases := map[string]struct {
		input          string
		expectedOutput bool
	}{
		"istio egressgateway case": {
			input:          "outbound|443|cnn|istio-egressgateway.istio-system.svc.cluster.local",
			expectedOutput: true,
		},
		"citrix egressgateway case": {
			input:          "outbound|80||citrix-egressgateway.citrix-system.svc.cluster.local",
			expectedOutput: true,
		},
		"not an egressgateway case": {
			input:          "outbound|80||random-egressgateway.citrix-system.svc.cluster.local",
			expectedOutput: false,
		},
	}

	for id, c := range testCases {
		if c.expectedOutput != isEgressGateway(c.input) {
			t.Errorf("Failed for %s", id)
		} else {
			t.Logf("%s successful", id)
		}
	}
}

//func getMultiClusterStringMapConfig(clusterName string) *nsconfigengine.StringMapBinding
func Test_getMultiClusterStringMapConfig(t *testing.T) {
	sMapBindingObj := new(nsconfigengine.StringMapBinding)
	type EO struct {
		retval *nsconfigengine.StringMapBinding
		key    string
		value  string
	}
	testCases := map[string]struct {
		inClusterName string
		expOutput     EO
	}{
		"valid-fqdn-cluster": {
			"outbound|80||httpserver.xyz.svc.cluster.local",
			EO{
				sMapBindingObj,
				"httpserver.xyz",
				"outbound_80__httpserver_xyz_svc_cluster_local",
			},
		},
		"invalid-fqdn-cluster": {
			"invalid-name",
			EO{
				nil,
				"",
				"",
			},
		},
		"invalid-suffix": {
			"outbound|80||httpserver.xyz.svc.global",
			EO{
				nil,
				"",
				"",
			},
		},
	}
	for id, tc := range testCases {
		output := getMultiClusterStringMapConfig(tc.inClusterName)
		if output != nil {
			if (output.Key == tc.expOutput.key) && (output.Value == tc.expOutput.value) {
				t.Logf("Success for %s", id)
			} else {
				t.Errorf("Failed for %s. Expected: %v. Received: %v", id, tc.expOutput, output)
			}
		} else {
			if tc.expOutput.retval == nil {
				t.Logf("Success for %s", id)
			} else {
				t.Errorf("Failed for %s", id)
			}
		}
	}
}

func Test_multiClusterListenerConfig(t *testing.T) {
	multiClusterIngress = true
	multiClusterPolExprStr = ".global"
	multiClusterListenPort = 15443
	rootCertFileName := "../tests/tls_conn_mgmt_certs/client-root-cert.pem"
	certFileName := "../tests/tls_conn_mgmt_certs/client-cert.pem"
	keyFileName := "../tests/tls_conn_mgmt_certs/client-key.pem"
	nsConfAdaptor := getNsConfAdaptor()
	nsConfAdaptor.client = env.GetNitroClient()
	certData, keyData, err := env.GetCertKeyData(certFileName, keyFileName)
	if err != nil {
		t.Errorf("Failed reading Cert/Key- %v", err)
	}
	nsCertFileName := nsconfigengine.GetNSCompatibleNameHash(string([]byte(certData)), 55)
	nsKeyFileName := nsconfigengine.GetNSCompatibleNameHash(string([]byte(keyData)), 55)
	t.Logf("Multicluster Ingress - SNI listener add")
	err = os.MkdirAll(certDir, 0777)
	if err != nil {
		t.Errorf("Could not create directory /etc/certs")
	}
	err = env.SetCertEnv(certDir, rootCertFileName, certFileName, certFileName, keyFileName)
	if err != nil {
		t.Errorf("Could not create certificate environment. %s", err.Error())
	}

	snif1, err := env.MakeSniFilter("0.0.0.0_15443")
	if err != nil {
		t.Errorf("MakeSniFilter failed with %v", err)
	}
	t.Logf("CS Object verification (LDS add)")
	snifc1 := env.MakeFilterChain("", 0, 0, multiClusterPolExprStr, "snif1", snif1)
	lds := env.MakeListenerFilterChains("0.0.0.0_15443", "0.0.0.0", 15443, outboundDir, []*listener.FilterChain{snifc1})
	csObj := []*nsconfigengine.CSApi{&nsconfigengine.CSApi{Name: "ns_0_0_0_0_15443", IP: "1.1.1.1", Port: 15443, VserverType: "SSL", AllowACL: false, FrontendTLS: []nsconfigengine.SSLSpec{{SNICert: false, CertFilename: nsCertFileName, PrivateKeyFilename: nsKeyFileName}}, FrontendTLSClientAuth: true}}
	multiClusterListenerConfig(nsConfAdaptor, lds)
	err = verifyObject(nsConfAdaptor, ldsAdd, "ns_0_0_0_0_15443", csObj, make([]map[string]interface{}, 0), make([]map[string]interface{}, 0))
	if err != nil {
		t.Errorf("Verification failed for CS object - %v", err)
	}

	t.Logf("CS Binding object verification (RDS Add)")
	csBindings := nsconfigengine.NewCSBindingsAPI("ns_0_0_0_0_15443")
	csBindings.Bindings = []nsconfigengine.CSBinding{
		{
			Rule: nsconfigengine.RouteMatch{
				Domains: []string{multiClusterPolExprStr},
			},
			CsPolicy: nsconfigengine.CsPolicy{
				Canary: []nsconfigengine.Canary{
					{
						TargetVserverExpr: multiClusterExpression,
					},
				},
			},
		},
	}
	//rds := env.MakeRoute("ns_0_0_0_0_15443", []env.RouteInfo{{Domain: "*.global"}})
	err = verifyObject(nsConfAdaptor, rdsAdd, "ns_0_0_0_0_15443", csBindings, make([]map[string]interface{}, 0), make([]map[string]interface{}, 0))
	if err != nil {
		t.Errorf("Verification failed - %v", err)
	}

	// Cleanup certificate directory
	if err := os.RemoveAll(certDir); err != nil {
		t.Errorf("Could not delete /etc/certs")
	}
}

func Test_isMultiClusterListener(t *testing.T) {
	multiClusterListenPort = 15443
	snif1, err := env.MakeSniFilter("0.0.0.0_15443")
	if err != nil {
		t.Errorf("MakeSniFilter failed with %v", err)
	}
	snifc1 := env.MakeFilterChain("", 0, 0, "*.global", "snif1", snif1)

	type input struct {
		filterChainName *listener.FilterChain
		listenerName    string
		ip              string
		port            uint16
		direction       string
	}
	testCases := map[string]struct {
		input     input
		expOutput bool
	}{
		"multiclusterListener": {
			input{
				filterChainName: snifc1,
				listenerName:    "multiclusterListener",
				ip:              "0.0.0.0",
				port:            15443,
				direction:       outboundDir,
			}, true,
		},
		"not-multiclusterListener": {
			input{
				filterChainName: snifc1,
				listenerName:    "not-multiclusterListener",
				ip:              "0.0.0.0",
				port:            25443,
				direction:       outboundDir,
			}, false,
		},
	}

	for id, tc := range testCases {
		lds := env.MakeListenerFilterChains(tc.input.listenerName, tc.input.ip, tc.input.port, tc.input.direction, []*listener.FilterChain{tc.input.filterChainName})
		if tc.expOutput != isMultiClusterListener(lds) {
			t.Errorf("Failed for %s", id)
		} else {
			t.Logf("Success for %s", id)
		}
	}
}
