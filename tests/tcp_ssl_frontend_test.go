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

func Test_tcp_ssl_frontend(t *testing.T) {
	t.Log("TCP service test start")
	errh := env.AddHostToHostFile(env.GetNetscalerIP(), "svc2.citrixrootdummy2.com", nil)
	if errh != nil {
		t.Errorf("Updating /etc/hosts failed - %v", errh)
	}
	env.ClearNetscalerConfig()
	grpcServer, err := env.NewGrpcADSServer(0)
	if err != nil {
		t.Errorf("GRPC server creation failed: %v", err)
	}
	tcpServer, err := env.StartTCPServer(9003)
	if err != nil {
		t.Errorf("tcp server creation failed : %v", err)
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

	listener, errl := env.MakeTcpSslListener("ls1", "0.0.0.0", 8003, "OUTBOUND", "cstcp", "certs/certssvc2/svc2.citrixrootdummy2.com.crt", "certs/certssvc2/svc2.citrixrootdummy2.com.key", "", false)
	if errl != nil {
		t.Errorf("makeTcpSslListener failed with %v", errl)
	}
	cluster := env.MakeCluster("cstcp")
	endpoint := env.MakeEndpoint("cstcp", []env.ServiceEndpoint{{env.GetLocalIP(), 9003, 1}})

	err = grpcServer.UpdateSpanshotCache("1", discoveryClient.GetNodeID(), listener, nil, cluster, endpoint)
	if err != nil {
		t.Errorf("updateSpanshotCache failed with %v", err)
	}

	time.Sleep(5 * time.Second)

	resp, err1 := env.DoTcpSslRequest("svc2.citrixrootdummy2.com", 8003, "hello world!", "certs/certssvc2/rootCA.crt")
	if err1 != nil {
		t.Errorf("tcp ssl request returned error: %v", err1)
	}
	t.Logf("TCP SSL request returned response:%s", resp)
	if resp != "hello world!" {
		t.Errorf("Expected response 'hello world!', received '%s'", resp)
	}

	env.RemoveAddressFromHostFile(env.GetNetscalerIP())
	discoveryClient.StopClient()
	grpcServer.StopGrpcADSServer()
	env.StopTCPServer(tcpServer)
	t.Log("TCP service test stop")
}
