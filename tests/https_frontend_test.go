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
	"strconv"
	"testing"
	"time"
)

func Test_https_frontend(t *testing.T) {
	t.Log("Https service test start")
	errh := env.AddHostToHostFile(env.GetNetscalerIP(), "svc1.citrixrootdummy1.com", nil)
	if errh != nil {
		t.Errorf("Updating /etc/hosts failed - %v", errh)
	}
	env.ClearNetscalerConfig()
	grpcServer, err := env.NewGrpcADSServer(0)
	if err != nil {
		t.Errorf("GRPC server creation failed: %v", err)
	}
	httpServer, err := env.StartHTTPServer(9002, "/path1", "Hello world!")
	if err != nil {
		t.Errorf("http server creation failed : %v", err)
	}
	adsinfo := new(adsclient.AdsDetails)
	nsinfo := new(adsclient.NSDetails)
	adsinfo.AdsServerURL = "localhost:" + strconv.Itoa(grpcServer.Port)
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
	route := env.MakeRoute("r1", []env.RouteInfo{{Domain: "*", ClusterName: "c1"}})
	listener, errl := env.MakeHttpsListener("l1", "0.0.0.0", 8002, "OUTBOUND", "r1", "certs/certssvc1/svc1.citrixrootdummy1.com.crt", "certs/certssvc1/svc1.citrixrootdummy1.com.key", "", false, true, false, false)
	if errl != nil {
		t.Errorf("makeListener failed with %v", errl)
	}
	cluster := env.MakeCluster("c1")
	endpoint := env.MakeEndpoint("c1", []env.ServiceEndpoint{{env.GetLocalIP(), 9002, 1}})

	err = grpcServer.UpdateSpanshotCache("1", discoveryClient.GetNodeID(), listener, route, cluster, endpoint)
	if err != nil {
		t.Errorf("updateSpanshotCache failed with %v", err)
	}

	time.Sleep(5 * time.Second)

	code, resp, err1 := env.DoHTTPSGet("https://svc1.citrixrootdummy1.com:8002/path1", "certs/certssvc1/rootCA.crt")
	if err1 != nil {
		t.Errorf("https get returned error: %v", err1)
	}
	t.Logf("HTTPSget returned code:%d response:%s", code, resp)
	if code != 200 {
		t.Errorf("Expected 200 OK response, received %d", code)
	}
	env.RemoveAddressFromHostFile(env.GetNetscalerIP())
	discoveryClient.StopClient()
	grpcServer.StopGrpcADSServer()
	env.StopHTTPServer(httpServer)
	t.Log("Https service test stop")
}

func Test_https_frontend_transportSocket(t *testing.T) {
	t.Log("Https service test start")
	errh := env.AddHostToHostFile(env.GetNetscalerIP(), "svc1.citrixrootdummy1.com", nil)
	if errh != nil {
		t.Errorf("Updating /etc/hosts failed - %v", errh)
	}
	env.ClearNetscalerConfig()
	grpcServer, err := env.NewGrpcADSServer(0)
	if err != nil {
		t.Errorf("GRPC server creation failed: %v", err)
	}
	httpServer, err := env.StartHTTPServer(9002, "/path1", "Hello world!")
	if err != nil {
		t.Errorf("http server creation failed : %v", err)
	}
	adsinfo := new(adsclient.AdsDetails)
	nsinfo := new(adsclient.NSDetails)
	adsinfo.AdsServerURL = "localhost:" + strconv.Itoa(grpcServer.Port)
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
	route := env.MakeRoute("r1", []env.RouteInfo{{Domain: "*", ClusterName: "c1"}})
	listener, errl := env.MakeHttpsListener("l1", "0.0.0.0", 8002, "OUTBOUND", "r1", "certs/certssvc1/svc1.citrixrootdummy1.com.crt", "certs/certssvc1/svc1.citrixrootdummy1.com.key", "", false, true, false, false)
	if errl != nil {
		t.Errorf("makeListener failed with %v", errl)
	}
	cluster := env.MakeCluster("c1")
	endpoint := env.MakeEndpoint("c1", []env.ServiceEndpoint{{env.GetLocalIP(), 9002, 1}})

	err = grpcServer.UpdateSpanshotCache("1", discoveryClient.GetNodeID(), listener, route, cluster, endpoint)
	if err != nil {
		t.Errorf("updateSpanshotCache failed with %v", err)
	}

	time.Sleep(5 * time.Second)

	code, resp, err1 := env.DoHTTPSGet("https://svc1.citrixrootdummy1.com:8002/path1", "certs/certssvc1/rootCA.crt")
	if err1 != nil {
		t.Errorf("https get returned error: %v", err1)
	}
	t.Logf("HTTPSget returned code:%d response:%s", code, resp)
	if code != 200 {
		t.Errorf("Expected 200 OK response, received %d", code)
	}
	env.RemoveAddressFromHostFile(env.GetNetscalerIP())
	discoveryClient.StopClient()
	grpcServer.StopGrpcADSServer()
	env.StopHTTPServer(httpServer)
	t.Log("Https service test stop")
}

func Test_https_frontendInline(t *testing.T) {
	t.Log("Https service test start")
	errh := env.AddHostToHostFile(env.GetNetscalerIP(), "svc1.citrixrootdummy1.com", nil)
	if errh != nil {
		t.Errorf("Updating /etc/hosts failed - %v", errh)
	}
	env.ClearNetscalerConfig()
	grpcServer, err := env.NewGrpcADSServer(0)
	if err != nil {
		t.Errorf("GRPC server creation failed: %v", err)
	}
	httpServer, err := env.StartHTTPServer(9002, "/path1", "Hello world!")
	if err != nil {
		t.Errorf("http server creation failed : %v", err)
	}
	adsinfo := new(adsclient.AdsDetails)
	nsinfo := new(adsclient.NSDetails)
	adsinfo.AdsServerURL = "localhost:" + strconv.Itoa(grpcServer.Port)
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
	route := env.MakeRoute("r1", []env.RouteInfo{{Domain: "*", ClusterName: "c1"}})
	listener, errl := env.MakeHttpsListener("l1", "0.0.0.0", 8002, "OUTBOUND", "r1", "certs/certssvc1/svc1.citrixrootdummy1.com.crt", "certs/certssvc1/svc1.citrixrootdummy1.com.key", "certs/certssvc1/rootCA.crt", false, true, true, false)
	if errl != nil {
		t.Errorf("makeListener failed with %v", errl)
	}
	cluster := env.MakeCluster("c1")
	endpoint := env.MakeEndpoint("c1", []env.ServiceEndpoint{{env.GetLocalIP(), 9002, 1}})

	err = grpcServer.UpdateSpanshotCache("1", discoveryClient.GetNodeID(), listener, route, cluster, endpoint)
	if err != nil {
		t.Errorf("updateSpanshotCache failed with %v", err)
	}

	time.Sleep(5 * time.Second)

	code, resp, err1 := env.DoHTTPSGet("https://svc1.citrixrootdummy1.com:8002/path1", "certs/certssvc1/rootCA.crt")
	if err1 != nil {
		t.Errorf("https get returned error: %v", err1)
	}
	t.Logf("HTTPSget returned code:%d response:%s", code, resp)
	if code != 200 {
		t.Errorf("Expected 200 OK response, received %d", code)
	}
	listener, errl = env.MakeHttpsListener("l1", "0.0.0.0", 8002, "OUTBOUND", "r1", "certs/certssvc1/new_svc1.citrixrootdummy1.com.crt", "certs/certssvc1/new_svc1.citrixrootdummy1.com.key", "certs/certssvc1/new_rootCA.crt", false, true, true, false)
	if errl != nil {
		t.Errorf("makeListener failed with %v", errl)
	}

	err = grpcServer.UpdateSpanshotCache("3", discoveryClient.GetNodeID(), listener, route, cluster, endpoint)
	if err != nil {
		t.Errorf("updateSpanshotCache failed with %v", err)
	}

	time.Sleep(5 * time.Second)

	code, resp, err1 = env.DoHTTPSGet("https://svc1.citrixrootdummy1.com:8002/path1", "certs/certssvc1/new_rootCA.crt")

	if err1 != nil {
		t.Errorf("https get returned error: %v", err1)
	}
	t.Logf("HTTPSget returned code:%d response:%s", code, resp)
	if code != 200 {
		t.Errorf("Expected 200 OK response, received %d", code)
	}

	env.RemoveAddressFromHostFile(env.GetNetscalerIP())
	discoveryClient.StopClient()
	grpcServer.StopGrpcADSServer()
	env.StopHTTPServer(httpServer)
	t.Log("Https service test stop")
}
