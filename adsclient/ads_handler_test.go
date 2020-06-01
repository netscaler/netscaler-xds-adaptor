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
	"citrix-istio-adaptor/tests/env"
	"container/list"
	"fmt"
	"log"
	"reflect"
	"testing"

	xdsapi "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/auth"
	v2Cluster "github.com/envoyproxy/go-control-plane/envoy/api/v2/cluster"
	v2Core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	envoyUtil "github.com/envoyproxy/go-control-plane/pkg/util"
	"github.com/gogo/protobuf/types"
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
		input          xdsapi.Cluster_LbPolicy
		expectedOutput string
	}{
		{xdsapi.Cluster_ROUND_ROBIN, "ROUNDROBIN"},
		{xdsapi.Cluster_LEAST_REQUEST, "LEASTCONNECTION"},
		{xdsapi.Cluster_RANDOM, "LEASTCONNECTION"},
		{xdsapi.Cluster_RING_HASH, "ROUNDROBIN"},
		{xdsapi.Cluster_ORIGINAL_DST_LB, "ROUNDROBIN"},
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
	compare := reflect.DeepEqual(expectedResponse, receivedResponse)
	if compare == false {
		return fmt.Errorf("Expected response: %s/%+v    Received resource:%s/%+v", reflect.TypeOf(expectedResponse).String(), expectedResponse, reflect.TypeOf(receivedResponse).String(), receivedResponse)
	}
	confBl, err := nsConfAdaptor.getConfigByName(nsconfigengine.GetNSCompatibleName(resourceName), configType)
	if err != nil {
		return fmt.Errorf("Config block fetch failed with %v", err)
	}
	log.Printf("Comapring %v with %v", confBl.resource, expectedResource)
	compare = reflect.DeepEqual(confBl.resource, expectedResource)
	if compare == false {
		return fmt.Errorf("Expected resource:%s/%+v    Received resource:%s/%+v", reflect.TypeOf(expectedResource).String(), expectedResource, reflect.TypeOf(confBl.resource).String(), confBl.resource)
	}
	return nil
}

func Test_clusterAdd(t *testing.T) {
	cds := env.MakeCluster("c1") // Creates a cluster of type EDS
	nsConfAdaptor := getNsConfAdaptor()

	log.Println("HTTP cluster add")
	cds.OutlierDetection = &v2Cluster.OutlierDetection{Interval: &types.Duration{Seconds: int64(5), Nanos: int32(100000000)}, BaseEjectionTime: &types.Duration{Seconds: int64(7)}, ConsecutiveGatewayFailure: &types.UInt32Value{Value: uint32(9)}}
	lbObj := &nsconfigengine.LBApi{Name: "c1", FrontendServiceType: "HTTP", LbMethod: "ROUNDROBIN", BackendServiceType: "HTTP", MaxConnections: 1024, MaxHTTP2ConcurrentStreams: 1000, NetprofileName: "k8s"}
	lbObj.LbMonitorObj = new(nsconfigengine.LBMonitor)
	lbObj.LbMonitorObj.Retries = 9
	lbObj.LbMonitorObj.Interval = 5100
	lbObj.LbMonitorObj.IntervalUnits = "MSEC"
	lbObj.LbMonitorObj.DownTime = 7
	lbObj.LbMonitorObj.DownTimeUnits = "SEC"
	lbObj.AutoScale = true
	err := verifyObject(nsConfAdaptor, cdsAdd, "c1", lbObj, "c1", clusterAdd(nsConfAdaptor, cds, "HTTP"))
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
	cds.EdsClusterConfig = &xdsapi.Cluster_EdsClusterConfig{EdsConfig: &v2Core.ConfigSource{ConfigSourceSpecifier: &v2Core.ConfigSource_Ads{Ads: &v2Core.AggregatedConfigSource{}}}}
	cds.CircuitBreakers = &v2Cluster.CircuitBreakers{Thresholds: []*v2Cluster.CircuitBreakers_Thresholds{&v2Cluster.CircuitBreakers_Thresholds{MaxConnections: &types.UInt32Value{Value: uint32(500)}, MaxRequests: &types.UInt32Value{Value: uint32(750)}}}}
	cds.MaxRequestsPerConnection = &types.UInt32Value{Value: uint32(100)}
	cds.TlsContext = &auth.UpstreamTlsContext{CommonTlsContext: env.MakeTLSContext("/etc/certs/server-cert.crt", "/etc/certs/server-key.key", "")}
	cds.OutlierDetection = &v2Cluster.OutlierDetection{Interval: &types.Duration{Seconds: int64(21000)}, BaseEjectionTime: &types.Duration{Seconds: int64(7), Nanos: int32(500000000)}}
	lbObj.FrontendServiceType = "HTTP"
	lbObj.BackendServiceType = "SSL"
	lbObj.MaxConnections = 500
	lbObj.MaxRequestsPerConnection = 100
	lbObj.MaxHTTP2ConcurrentStreams = 750
	lbObj.BackendTLS = []nsconfigengine.SSLSpec{{SNICert: false, CertFilename: "/etc/certs/server-cert.crt", PrivateKeyFilename: "/etc/certs/server-key.key"}}
	lbObj.LbMonitorObj = new(nsconfigengine.LBMonitor)
	lbObj.LbMonitorObj.Interval = 21000
	lbObj.LbMonitorObj.IntervalUnits = "SEC"
	lbObj.LbMonitorObj.DownTime = 7500
	lbObj.LbMonitorObj.DownTimeUnits = "MSEC"
	err = verifyObject(nsConfAdaptor, cdsAdd, "c1", lbObj, "c1", clusterAdd(nsConfAdaptor, cds, "HTTP"))
	if err != nil {
		t.Errorf("Verification failed - %v", err)
	}
	lbObj.LbMonitorObj = nil

	log.Println("SSL_TCP cluster add")
	lbObj.FrontendServiceType = "TCP"
	lbObj.BackendServiceType = "SSL_TCP"
	err = verifyObject(nsConfAdaptor, cdsAdd, "c1", lbObj, "c1", clusterAdd(nsConfAdaptor, cds, "TCP"))
	if err != nil {
		t.Errorf("Verification failed - %v", err)
	}
}

func Test_clusterDel(t *testing.T) {
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

func Test_listenerAdd(t *testing.T) {
	nsConfAdaptor := getNsConfAdaptor()
	t.Logf("HTTP listener add")
	lds, err := env.MakeHttpListener("l1", "10.0.0.0", 80, "r1")
	if err != nil {
		t.Errorf("MakeHttpListener failed with %v", err)
	}
	csObj := &nsconfigengine.CSApi{Name: "l1", IP: "10.0.0.0", Port: 80, VserverType: "HTTP", AllowACL: false}
	err = verifyObject(nsConfAdaptor, ldsAdd, "l1", csObj, map[string]interface{}{"rdsNames": []string{"r1"}, "cdsNames": ([]string)(nil), "listenerName": "l1", "filterType": envoyUtil.HTTPConnectionManager, "serviceType": "HTTP"}, listenerAdd(nsConfAdaptor, lds))
	if err != nil {
		t.Errorf("Verification failed - %v", err)
	}

	t.Logf("TCP listener add")
	lds, err = env.MakeTcpListener("l2", "20.0.0.0", 25, "cl1")
	if err != nil {
		t.Errorf("MakeTcpListener failed with %v", err)
	}
	csObj = &nsconfigengine.CSApi{Name: "l2", IP: "20.0.0.0", Port: 25, VserverType: "TCP", AllowACL: false, DefaultLbVserverName: "cl1"}
	err = verifyObject(nsConfAdaptor, ldsAdd, "l2", csObj, map[string]interface{}{"rdsNames": ([]string)(nil), "cdsNames": []string{"cl1"}, "listenerName": "l2", "filterType": envoyUtil.TCPProxy, "serviceType": "TCP"}, listenerAdd(nsConfAdaptor, lds))
	if err != nil {
		t.Errorf("Verification failed - %v", err)
	}

	t.Logf("HTTPS listener add")
	lds, err = env.MakeHttpsListener("l1s", "30.0.0.0", 443, "r1", "/etc/certs/server-cert.crt", "/etc/certs/server-key.key", "", false)
	if err != nil {
		t.Errorf("MakeHttpsListener failed with %v", err)
	}
	csObj = &nsconfigengine.CSApi{Name: "l1s", IP: "30.0.0.0", Port: 443, VserverType: "SSL", AllowACL: false, FrontendTLS: []nsconfigengine.SSLSpec{{SNICert: false, CertFilename: "/etc/certs/server-cert.crt", PrivateKeyFilename: "/etc/certs/server-key.key"}}}
	err = verifyObject(nsConfAdaptor, ldsAdd, "l1s", csObj, map[string]interface{}{"rdsNames": []string{"r1"}, "cdsNames": ([]string)(nil), "listenerName": "l1s", "filterType": envoyUtil.HTTPConnectionManager, "serviceType": "HTTP"}, listenerAdd(nsConfAdaptor, lds))
	if err != nil {
		t.Errorf("Verification failed - %v", err)
	}
}

func Test_listenerDel(t *testing.T) {
	nsConfAdaptor := getNsConfAdaptor()
	t.Logf("HTTP listener delete")
	csObj := &nsconfigengine.CSApi{Name: "l3"}
	listenerDel(nsConfAdaptor, "l3")
	err := verifyObject(nsConfAdaptor, ldsDel, "l3", csObj, nil, nil)
	if err != nil {
		t.Errorf("Verification failed - %v", err)
	}
}

func Test_routeUpdate(t *testing.T) {
	nsConfAdaptor := getNsConfAdaptor()
	t.Logf("route update")
	csBindings := nsconfigengine.NewCSBindingsAPI("cs1")
	csBindings.Bindings = []nsconfigengine.CSBinding{{Rule: nsconfigengine.RouteMatch{Domains: []string{"*"}, Prefix: "/"}, CsPolicy: nsconfigengine.CsPolicy{Canary: []nsconfigengine.Canary{{LbVserverName: "cl1", LbVserverType: "HTTP", Weight: 100}}}}}
	rds := env.MakeRoute("rt1", "*", "cl1")
	err := verifyObject(nsConfAdaptor, rdsAdd, "cs1", csBindings, map[string]interface{}{"cdsNames": []string{"cl1"}, "serviceType": "HTTP"}, routeUpdate(nsConfAdaptor, []*xdsapi.RouteConfiguration{rds}, map[string]interface{}{"listenerName": "cs1", "serviceType": "HTTP"}))
	if err != nil {
		t.Errorf("Verification failed - %v", err)
	}
}
