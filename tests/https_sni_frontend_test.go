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

package client_test

import (
	"citrix-xds-adaptor/adsclient"
	"citrix-xds-adaptor/tests/env"
	"testing"
	"time"

	xdsapi "github.com/envoyproxy/go-control-plane/envoy/api/v2"
)

const (
	domainA   = "svca.dummyrootcitrix1.com"
	domainB   = "svcb.dummyrootcitrix2.com"
	certFileA = "certs/certssvca/svca.dummyrootcitrix1.com.crt"
	keyFileA  = "certs/certssvca/svca.dummyrootcitrix1.com.key"
	rootCertA = "certs/certssvca/rootCA1.crt"
	certFileB = "certs/certssvcb/svcb.dummyrootcitrix2.com.crt"
	keyFileB  = "certs/certssvcb/svcb.dummyrootcitrix2.com.key"
	rootCertB = "certs/certssvcb/rootCA2.crt"
)

func Test_https_sni_frontend(t *testing.T) {
	t.Log("Https sni service test start")
	err := env.AddHostToHostFile(env.GetNetscalerIP(), "", []string{domainA, domainB})
	if err != nil {
		t.Errorf("Updating /etc/hosts failed - %v", err)
	}
	env.ClearNetscalerConfig()
	grpcServer, err := env.NewGrpcADSServer(1234)
	if err != nil {
		t.Errorf("GRPC server creation failed: %v", err)
	}
	httpServerA, errA := env.StartHTTPServer(9041, "/pathA", "This is svc a!")
	if errA != nil {
		t.Errorf("http server A creation failed : %v", errA)
	}
	httpServerB, errB := env.StartHTTPServer(9042, "/pathB", "This is svc b!")
	if errB != nil {
		t.Errorf("http server B creation failed : %v", errB)
	}
	adsinfo := new(adsclient.AdsDetails)
	nsinfo := new(adsclient.NSDetails)
	adsinfo.AdsServerURL = "localhost:1234"
	adsinfo.AdsServerSpiffeID = ""
	adsinfo.SecureConnect = false
	adsinfo.NodeID = "ads_client_node_1"
	adsinfo.ApplicationName = "test-app"
	nsinfo.NetscalerURL = env.GetNetscalerURL()
	nsinfo.NetscalerUsername = env.GetNetscalerUser()
	nsinfo.NetscalerPassword = env.GetNetscalerPassword()
	nsinfo.NetscalerVIP = "nsip"
	nsinfo.NetProfile = ""
	nsinfo.AnalyticsServerIP = ""
	nsinfo.LogProxyURL = "ns-logproxy.citrix-system"
	discoveryClient, errc := adsclient.NewAdsClient(adsinfo, nsinfo, nil)
	if errc != nil {
		t.Errorf("newAdsClient failed with %v", errc)
	}
	discoveryClient.StartClient()
	routeA := env.MakeRoute("ra", []env.RouteInfo{{Domain: domainA, ClusterName: "ca"}})
	routeB := env.MakeRoute("rb", []env.RouteInfo{{Domain: domainB, ClusterName: "cb"}})
	sniInfo := []env.SniInfo{
		{ServerName: domainA, RouteName: "ra", CertFile: certFileA, KeyFile: keyFileA, RootFile: rootCertA},
		{ServerName: domainB, RouteName: "rb", CertFile: certFileB, KeyFile: keyFileB, RootFile: rootCertB},
	}
	listener, errl := env.MakeHttpsSniListener("l1", "0.0.0.0", 8005, sniInfo, false, false)
	if errl != nil {
		t.Errorf("MakeHttpsSniListener failed with %v", errl)
	}
	clusterA := env.MakeCluster("ca")
	endpointA := env.MakeEndpoint("ca", []env.ServiceEndpoint{{env.GetLocalIP(), 9041, 1}})
	clusterB := env.MakeCluster("cb")
	endpointB := env.MakeEndpoint("cb", []env.ServiceEndpoint{{env.GetLocalIP(), 9042, 1}})

	err = grpcServer.UpdateSpanshotCacheMulti("1", discoveryClient.GetNodeID(), []*xdsapi.Listener{listener}, []*xdsapi.RouteConfiguration{routeA, routeB}, []*xdsapi.Cluster{clusterA, clusterB}, []*xdsapi.ClusterLoadAssignment{endpointA, endpointB})
	if err != nil {
		t.Errorf("updateSpanshotCacheMulti failed with %v", err)
	}

	time.Sleep(5 * time.Second)

	t.Logf("HTTPS get on svca.dummyrootcitrix1.com")
	code, resp, err1 := env.DoHTTPSGet("https://svca.dummyrootcitrix1.com:8005/pathA", rootCertA)
	if err1 != nil {
		t.Errorf("https get on returned error: %v", err1)
	}
	t.Logf("HTTPSget returned code:%d response:%s", code, resp)
	if code != 200 {
		t.Errorf("Expected 200 OK response, received %d", code)
	}
	if resp != "This is svc a!" {
		t.Errorf("Expected response 'This is svc a!', received %s", resp)
	}
	t.Logf("HTTPS get on svcb.dummyrootcitrix2.com")
	code, resp, err1 = env.DoHTTPSGet("https://svcb.dummyrootcitrix2.com:8005/pathB", rootCertB)
	if err1 != nil {
		t.Errorf("https get on returned error: %v", err1)
	}
	t.Logf("HTTPSget returned code:%d response:%s", code, resp)
	if code != 200 {
		t.Errorf("Expected 200 OK response, received %d", code)
	}
	if resp != "This is svc b!" {
		t.Errorf("Expected response 'This is svc b!', received %s", resp)
	}
	env.RemoveAddressFromHostFile(env.GetNetscalerIP())
	discoveryClient.StopClient()
	grpcServer.StopGrpcADSServer()
	env.StopHTTPServer(httpServerA)
	env.StopHTTPServer(httpServerB)
	t.Log("Https sni service test stop")
}

func Test_https_sni_frontend_transportSocket(t *testing.T) {
	t.Log("Https sni service test start")
	err := env.AddHostToHostFile(env.GetNetscalerIP(), "", []string{domainA, domainB})
	if err != nil {
		t.Errorf("Updating /etc/hosts failed - %v", err)
	}
	env.ClearNetscalerConfig()
	grpcServer, err := env.NewGrpcADSServer(1234)
	if err != nil {
		t.Errorf("GRPC server creation failed: %v", err)
	}
	httpServerA, errA := env.StartHTTPServer(9041, "/pathA", "This is svc a!")
	if errA != nil {
		t.Errorf("http server A creation failed : %v", errA)
	}
	httpServerB, errB := env.StartHTTPServer(9042, "/pathB", "This is svc b!")
	if errB != nil {
		t.Errorf("http server B creation failed : %v", errB)
	}
	adsinfo := new(adsclient.AdsDetails)
	nsinfo := new(adsclient.NSDetails)
	adsinfo.AdsServerURL = "localhost:1234"
	adsinfo.AdsServerSpiffeID = ""
	adsinfo.SecureConnect = false
	adsinfo.NodeID = "ads_client_node_1"
	adsinfo.ApplicationName = "test-app"
	nsinfo.NetscalerURL = env.GetNetscalerURL()
	nsinfo.NetscalerUsername = env.GetNetscalerUser()
	nsinfo.NetscalerPassword = env.GetNetscalerPassword()
	nsinfo.NetscalerVIP = "nsip"
	nsinfo.NetProfile = ""
	nsinfo.AnalyticsServerIP = ""
	nsinfo.LogProxyURL = "ns-logproxy.citrix-system"
	discoveryClient, errc := adsclient.NewAdsClient(adsinfo, nsinfo, nil)
	if errc != nil {
		t.Errorf("newAdsClient failed with %v", errc)
	}
	discoveryClient.StartClient()
	routeA := env.MakeRoute("ra", []env.RouteInfo{{Domain: domainA, ClusterName: "ca"}})
	routeB := env.MakeRoute("rb", []env.RouteInfo{{Domain: domainB, ClusterName: "cb"}})
	sniInfo := []env.SniInfo{
		{ServerName: domainA, RouteName: "ra", CertFile: certFileA, KeyFile: keyFileA, RootFile: rootCertA},
		{ServerName: domainB, RouteName: "rb", CertFile: certFileB, KeyFile: keyFileB, RootFile: rootCertB},
	}
	listener, errl := env.MakeHttpsSniListener("l1", "0.0.0.0", 8005, sniInfo, true, false)
	if errl != nil {
		t.Errorf("MakeHttpsSniListener failed with %v", errl)
	}
	clusterA := env.MakeCluster("ca")
	endpointA := env.MakeEndpoint("ca", []env.ServiceEndpoint{{env.GetLocalIP(), 9041, 1}})
	clusterB := env.MakeCluster("cb")
	endpointB := env.MakeEndpoint("cb", []env.ServiceEndpoint{{env.GetLocalIP(), 9042, 1}})

	err = grpcServer.UpdateSpanshotCacheMulti("1", discoveryClient.GetNodeID(), []*xdsapi.Listener{listener}, []*xdsapi.RouteConfiguration{routeA, routeB}, []*xdsapi.Cluster{clusterA, clusterB}, []*xdsapi.ClusterLoadAssignment{endpointA, endpointB})
	if err != nil {
		t.Errorf("updateSpanshotCacheMulti failed with %v", err)
	}

	time.Sleep(5 * time.Second)

	t.Logf("HTTPS get on svca.dummyrootcitrix1.com")
	code, resp, err1 := env.DoHTTPSGet("https://svca.dummyrootcitrix1.com:8005/pathA", rootCertA)
	if err1 != nil {
		t.Errorf("https get on returned error: %v", err1)
	}
	t.Logf("HTTPSget returned code:%d response:%s", code, resp)
	if code != 200 {
		t.Errorf("Expected 200 OK response, received %d", code)
	}
	if resp != "This is svc a!" {
		t.Errorf("Expected response 'This is svc a!', received %s", resp)
	}
	t.Logf("HTTPS get on svcb.dummyrootcitrix2.com")
	code, resp, err1 = env.DoHTTPSGet("https://svcb.dummyrootcitrix2.com:8005/pathB", rootCertB)
	if err1 != nil {
		t.Errorf("https get on returned error: %v", err1)
	}
	t.Logf("HTTPSget returned code:%d response:%s", code, resp)
	if code != 200 {
		t.Errorf("Expected 200 OK response, received %d", code)
	}
	if resp != "This is svc b!" {
		t.Errorf("Expected response 'This is svc b!', received %s", resp)
	}
	env.RemoveAddressFromHostFile(env.GetNetscalerIP())
	discoveryClient.StopClient()
	grpcServer.StopGrpcADSServer()
	env.StopHTTPServer(httpServerA)
	env.StopHTTPServer(httpServerB)
	t.Log("Https sni service test stop")
}
func Test_https_sni_frontend_inline(t *testing.T) {
	t.Log("Https sni service test start")
	err := env.AddHostToHostFile(env.GetNetscalerIP(), "", []string{"svca.dummyrootcitrix1.com", "svcb.dummyrootcitrix2.com"})
	if err != nil {
		t.Errorf("Updating /etc/hosts failed - %v", err)
	}
	env.ClearNetscalerConfig()
	grpcServer, err := env.NewGrpcADSServer(1234)
	if err != nil {
		t.Errorf("GRPC server creation failed: %v", err)
	}
	httpServerA, errA := env.StartHTTPServer(9041, "/pathA", "This is svc a!")
	if errA != nil {
		t.Errorf("http server A creation failed : %v", errA)
	}
	httpServerB, errB := env.StartHTTPServer(9042, "/pathB", "This is svc b!")
	if errB != nil {
		t.Errorf("http server B creation failed : %v", errB)
	}
	adsinfo := new(adsclient.AdsDetails)
	nsinfo := new(adsclient.NSDetails)
	adsinfo.AdsServerURL = "localhost:1234"
	adsinfo.AdsServerSpiffeID = ""
	adsinfo.SecureConnect = false
	adsinfo.NodeID = "ads_client_node_1"
	adsinfo.ApplicationName = "test-app"
	nsinfo.NetscalerURL = env.GetNetscalerURL()
	nsinfo.NetscalerUsername = env.GetNetscalerUser()
	nsinfo.NetscalerPassword = env.GetNetscalerPassword()
	nsinfo.NetscalerVIP = "nsip"
	nsinfo.NetProfile = ""
	nsinfo.AnalyticsServerIP = ""
	nsinfo.LogProxyURL = "ns-logproxy.citrix-system"
	discoveryClient, errc := adsclient.NewAdsClient(adsinfo, nsinfo, nil)
	if errc != nil {
		t.Errorf("newAdsClient failed with %v", errc)
	}
	discoveryClient.StartClient()
	routeA := env.MakeRoute("ra", []env.RouteInfo{{Domain: "svca.dummyrootcitrix1.com", ClusterName: "ca"}})
	routeB := env.MakeRoute("rb", []env.RouteInfo{{Domain: "svcb.dummyrootcitrix2.com", ClusterName: "cb"}})
	sniInfo := []env.SniInfo{
		{ServerName: "svca.dummyrootcitrix1.com", RouteName: "ra", CertFile: "certs/certssvca/svca.dummyrootcitrix1.com.crt", KeyFile: "certs/certssvca/svca.dummyrootcitrix1.com.key", RootFile: "certs/certssvca/rootCA1.crt"},
		{ServerName: "svcb.dummyrootcitrix2.com", RouteName: "rb", CertFile: "certs/certssvcb/svcb.dummyrootcitrix2.com.crt", KeyFile: "certs/certssvcb/svcb.dummyrootcitrix2.com.key", RootFile: "certs/certssvcb/rootCA2.crt"},
	}
	listener, errl := env.MakeHttpsSniListener("l1", "0.0.0.0", 8005, sniInfo, false, true)
	if errl != nil {
		t.Errorf("MakeHttpsSniListener failed with %v", errl)
	}
	clusterA := env.MakeCluster("ca")
	endpointA := env.MakeEndpoint("ca", []env.ServiceEndpoint{{env.GetLocalIP(), 9041, 1}})
	clusterB := env.MakeCluster("cb")
	endpointB := env.MakeEndpoint("cb", []env.ServiceEndpoint{{env.GetLocalIP(), 9042, 1}})

	err = grpcServer.UpdateSpanshotCacheMulti("1", discoveryClient.GetNodeID(), []*xdsapi.Listener{listener}, []*xdsapi.RouteConfiguration{routeA, routeB}, []*xdsapi.Cluster{clusterA, clusterB}, []*xdsapi.ClusterLoadAssignment{endpointA, endpointB})
	if err != nil {
		t.Errorf("updateSpanshotCacheMulti failed with %v", err)
	}

	time.Sleep(5 * time.Second)

	t.Logf("HTTPS get on svca.dummyrootcitrix1.com")
	code, resp, err1 := env.DoHTTPSGet("https://svca.dummyrootcitrix1.com:8005/pathA", "certs/certssvca/rootCA1.crt")
	if err1 != nil {
		t.Errorf("https get on returned error: %v", err1)
	}
	t.Logf("HTTPSget returned code:%d response:%s", code, resp)
	if code != 200 {
		t.Errorf("Expected 200 OK response, received %d", code)
	}
	if resp != "This is svc a!" {
		t.Errorf("Expected response 'This is svc a!', received %s", resp)
	}
	t.Logf("HTTPS get on svcb.dummyrootcitrix2.com")
	code, resp, err1 = env.DoHTTPSGet("https://svcb.dummyrootcitrix2.com:8005/pathB", "certs/certssvcb/rootCA2.crt")
	if err1 != nil {
		t.Errorf("https get on returned error: %v", err1)
	}
	t.Logf("HTTPSget returned code:%d response:%s", code, resp)
	if code != 200 {
		t.Errorf("Expected 200 OK response, received %d", code)
	}
	if resp != "This is svc b!" {
		t.Errorf("Expected response 'This is svc b!', received %s", resp)
	}

	env.StopHTTPServer(httpServerA)
	env.StopHTTPServer(httpServerB)
	err = env.AddHostToHostFile(env.GetNetscalerIP(), "", []string{"new_svca.dummyrootcitrix1.com", "new_svcb.dummyrootcitrix2.com"})
	if err != nil {
		t.Errorf("Updating /etc/hosts failed - %v", err)
	}
	httpServerA, errA = env.StartHTTPServer(9041, "/pathA", "This is svc a!")
	if errA != nil {
		t.Errorf("http server A creation failed : %v", errA)
	}
	httpServerB, errB = env.StartHTTPServer(9042, "/pathB", "This is svc b!")
	if errB != nil {
		t.Errorf("http server B creation failed : %v", errB)
	}
	routeA = env.MakeRoute("ra", []env.RouteInfo{{Domain: "new_svca.dummyrootcitrix1.com", ClusterName: "ca"}})
	routeB = env.MakeRoute("rb", []env.RouteInfo{{Domain: "new_svcb.dummyrootcitrix2.com", ClusterName: "cb"}})
	sniInfo = []env.SniInfo{
		{ServerName: "new_svca.dummyrootcitrix1.com", RouteName: "ra", CertFile: "certs/certssvca/new_svca.dummyrootcitrix1.com.crt", KeyFile: "certs/certssvca/new_svca.dummyrootcitrix1.com.key", RootFile: "certs/certssvca/new_rootCA1.crt"},
		{ServerName: "new_svcb.dummyrootcitrix2.com", RouteName: "rb", CertFile: "certs/certssvcb/new_svcb.dummyrootcitrix2.com.crt", KeyFile: "certs/certssvcb/new_svcb.dummyrootcitrix2.com.key", RootFile: "certs/certssvcb/new_rootCA2.crt"},
	}
	listener, errl = env.MakeHttpsSniListener("l1", "0.0.0.0", 8005, sniInfo, false, true)
	if errl != nil {
		t.Errorf("MakeHttpsSniListener failed with %v", errl)
	}
	err = grpcServer.UpdateSpanshotCacheMulti("3", discoveryClient.GetNodeID(), []*xdsapi.Listener{listener}, []*xdsapi.RouteConfiguration{routeA, routeB}, []*xdsapi.Cluster{clusterA, clusterB}, []*xdsapi.ClusterLoadAssignment{endpointA, endpointB})
	if err != nil {
		t.Errorf("updateSpanshotCacheMulti failed with %v", err)
	}

	time.Sleep(5 * time.Second)

	t.Logf("HTTPS get on new_svca.dummyrootcitrix1.com")
	code, resp, err1 = env.DoHTTPSGet("https://new_svca.dummyrootcitrix1.com:8005/pathA", "certs/certssvca/new_rootCA1.crt")
	if err1 != nil {
		t.Errorf("https get on returned error: %v", err1)
	}
	t.Logf("HTTPSget returned code:%d response:%s", code, resp)
	if code != 200 {
		t.Errorf("Expected 200 OK response, received %d", code)
	}
	if resp != "This is svc a!" {
		t.Errorf("Expected response 'This is svc a!', received %s", resp)
	}
	t.Logf("HTTPS get on new_svcb.dummyrootcitrix2.com")
	code, resp, err1 = env.DoHTTPSGet("https://new_svcb.dummyrootcitrix2.com:8005/pathB", "certs/certssvcb/new_rootCA2.crt")
	if err1 != nil {
		t.Errorf("https get on returned error: %v", err1)
	}
	t.Logf("HTTPSget returned code:%d response:%s", code, resp)
	if code != 200 {
		t.Errorf("Expected 200 OK response, received %d", code)
	}
	if resp != "This is svc b!" {
		t.Errorf("Expected response 'This is svc b!', received %s", resp)
	}

	env.RemoveAddressFromHostFile(env.GetNetscalerIP())
	discoveryClient.StopClient()
	grpcServer.StopGrpcADSServer()
	env.StopHTTPServer(httpServerA)
	env.StopHTTPServer(httpServerB)
	t.Log("Https sni service test stop")
}
