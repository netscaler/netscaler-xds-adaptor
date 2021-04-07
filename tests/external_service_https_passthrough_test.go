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

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
)

func Test_external_service_https_passthrough(t *testing.T) {
	t.Log("Https external service passthrough test starts")
	err := env.AddHostToHostFile(env.GetNetscalerIP(), "", []string{"www.google.com", "www.citrix.com"})
	if err != nil {
		t.Errorf("Updating /etc/hosts failed - %v", err)
	}
	env.ClearNetscalerConfig()
	env.ConfigureDNS()
	grpcServer, err := env.NewGrpcADSServer(0)
	if err != nil {
		t.Errorf("GRPC server creation failed: %v", err)
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
	nsinfo.LogProxyURL = "ns-logproxy.citrix-system"
	discoveryClient, errc := adsclient.NewAdsClient(adsinfo, nsinfo, nil)
	if errc != nil {
		t.Errorf("newAdsClient failed with %v", errc)
	}
	discoveryClient.StartClient()
	sniInfo := []env.SniInfo{
		{ServerName: "www.google.com", ClusterName: "cl_google"},
		{ServerName: "www.citrix.com", ClusterName: "cl_citrix"},
	}
	listenerL, errl := env.MakeTcpSniListener("l1", "0.0.0.0", 443, sniInfo)
	if errl != nil {
		t.Errorf("MakeTcpSniListener returned error : %v", errl)
	}
	clusterG := env.MakeClusterDNS("cl_google", "www.google.com", 443)
	clusterC := env.MakeClusterDNS("cl_citrix", "www.citrix.com", 443)

	err = grpcServer.UpdateSpanshotCacheMulti("1", discoveryClient.GetNodeID(), []*listener.Listener{listenerL}, nil, []*cluster.Cluster{clusterG, clusterC}, nil)
	if err != nil {
		t.Errorf("updateSpanshotCacheMulti failed with %v", err)
	}

	time.Sleep(5 * time.Second)

	t.Logf("HTTPS get on google passthrough")
	code, _, err1 := env.DoHTTPSGet("https://www.google.com/", "")
	if err1 != nil {
		t.Errorf("https get returned error: %v", err1)
		return
	}
	if code != 200 {
		t.Errorf("Expected 200 OK response, received %d", code)
	}
	t.Logf("HTTPS get on citrix passthrough")
	code, _, err1 = env.DoHTTPSGet("https://www.citrix.com/", "")
	if err1 != nil {
		t.Errorf("http get returned error: %v", err1)
		return
	}
	if code != 200 {
		t.Errorf("Expected 200 OK response, received %d", code)
	}
	env.RemoveAddressFromHostFile(env.GetNetscalerIP())
	discoveryClient.StopClient()
	grpcServer.StopGrpcADSServer()
	t.Log("Https external service passthrough test stop")
}
