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

func Test_external_service_http_passthrough(t *testing.T) {
	t.Log("Http external service passthrough test starts")
	err := env.AddHostToHostFile(env.GetNetscalerIP(), "", []string{"www.google.com", "www.citrix.com"})
	if err != nil {
		t.Errorf("Updating /etc/hosts failed - %v", err)
	}
	env.ClearNetscalerConfig()
	env.ConfigureDNS()
	grpcServer, err := env.NewGrpcADSServer(1234)
	if err != nil {
		t.Errorf("Grpc server creation failed  - %v", err)
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
	nsinfo.LogProxyURL = "ns-logproxy.citrix-system"
	discoveryClient, errc := adsclient.NewAdsClient(adsinfo, nsinfo, nil)
	if errc != nil {
		t.Errorf("newAdsClient failed with %v", errc)
	}
	discoveryClient.StartClient()
	routeGC := env.MakeRoute("rts", []env.RouteInfo{{Domain: "www.google.com", ClusterName: "cl_google"}, {Domain: "www.citrix.com", ClusterName: "cl_citrix"}})
	listener, errl := env.MakeHttpListener("l1", "0.0.0.0", 80, "rts")
	if errl != nil {
		t.Errorf("MakeHttpListener returned error : %v", errl)
	}
	clusterG := env.MakeClusterDNS("cl_google", "www.google.com", 80)
	clusterC := env.MakeClusterDNS("cl_citrix", "www.citrix.com", 80)

	err = grpcServer.UpdateSpanshotCacheMulti("1", discoveryClient.GetNodeID(), []*xdsapi.Listener{listener}, []*xdsapi.RouteConfiguration{routeGC}, []*xdsapi.Cluster{clusterG, clusterC}, nil)
	if err != nil {
		t.Errorf("updateSpanshotCacheMulti failed with %v", err)
	}

	time.Sleep(5 * time.Second)

	t.Logf("HTTP get on google passthrough")
	resp, err1 := env.DoHTTPGetAll("http://www.google.com/")
	if err1 != nil {
		t.Errorf("http get returned error: %v", err1)
	}
	if resp.StatusCode != 200 {
		t.Errorf("Expected 200 OK response, received %d", resp.StatusCode)
	}
	t.Logf("HTTP get on citrix passthrough")
	resp, err1 = env.DoHTTPGetAll("http://www.citrix.com/")
	if err1 != nil {
		t.Errorf("http get returned error: %v", err1)
	}
	if resp.StatusCode != 301 {
		t.Errorf("Expected 301 response, received %d", resp.StatusCode)
	}
	if resp.Header.Get("Location") != "https://www.citrix.com/" {
		t.Errorf("Expected Location header \"https://www.citrix.com/\", received \"%s\"", resp.Header.Get("Location"))
	}
	env.RemoveAddressFromHostFile(env.GetNetscalerIP())
	discoveryClient.StopClient()
	grpcServer.StopGrpcADSServer()
	t.Log("Http external service passthrough test stop")
}
