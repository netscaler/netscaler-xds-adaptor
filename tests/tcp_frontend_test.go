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
package client_test

import (
	"citrix-istio-adaptor/adsclient"
	"citrix-istio-adaptor/tests/env"
	"testing"
	"time"
)

func Test_tcp_frontend(t *testing.T) {
	t.Log("TCP service test start")
	env.ClearNetscalerConfig()
	grpcServer := env.NewGrpcADSServer(1234)
	tcpServer, err := env.StartTCPServer(9001)
	if err != nil {
		t.Errorf("tcp server creation failed : %v", err)
	}
	discoveryClient, errc := adsclient.NewAdsClient("localhost:1234", "", false, "ads_client_node_1", "test-app", env.GetNetscalerURL(), env.GetNetscalerUser(), env.GetNetscalerPassword(), "nsip", "", "")
	if errc != nil {
		t.Errorf("newAdsClient failed with %v", errc)
	}
	discoveryClient.StartClient()

	listener, errl := env.MakeTcpListener("l1", "0.0.0.0", 8001, "ctcp")
	if errl != nil {
		t.Errorf("makeListener failed with %v", errl)
	}
	cluster := env.MakeCluster("ctcp")
	endpoint := env.MakeEndpoint("ctcp", []env.ServiceEndpoint{{env.GetLocalIP(), 9001}})

	err = grpcServer.UpdateSpanshotCache("1", discoveryClient.GetNodeID(), listener, nil, cluster, endpoint)
	if errl != nil {
		t.Errorf("updateSpanshotCache failed with %v", err)
	}

	time.Sleep(2 * time.Second)

	resp, err1 := env.DoTcpRequest(env.GetNetscalerIP(), 8001, "hello world!")
	if err1 != nil {
		t.Errorf("tcprequest returned error: %v", err1)
	}
	t.Logf("TCP request returned response:%s", resp)
	if resp != "hello world!" {
		t.Errorf("Expected response 'hello world!', received '%s'", resp)
	}

	discoveryClient.StopClient()
	grpcServer.StopGrpcADSServer()
	env.StopTCPServer(tcpServer)
	t.Log("TCP service test stop")
}
