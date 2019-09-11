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
	xdsapi "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	"testing"
	"time"
)

func Test_https_sni_frontend(t *testing.T) {
	t.Log("Https sni service test start")
	err := env.AddHostToHostFile(env.GetNetscalerIP(), "", []string{"svca.dummyrootcitrix1.com", "svcb.dummyrootcitrix2.com"})
	if err != nil {
		t.Errorf("Updating /etc/hosts failed - %v", err)
	}
	env.ClearNetscalerConfig()
	grpcServer := env.NewGrpcADSServer(1234)
	httpServerA, errA := env.StartHTTPServer(9041, "/pathA", "This is svc a!")
	if errA != nil {
		t.Errorf("http server A creation failed : %v", errA)
	}
	httpServerB, errB := env.StartHTTPServer(9042, "/pathB", "This is svc b!")
	if errB != nil {
		t.Errorf("http server B creation failed : %v", errB)
	}
	discoveryClient, errc := adsclient.NewAdsClient("localhost:1234", "", false, "ads_client_node_1", "test-app", env.GetNetscalerURL(), env.GetNetscalerUser(), env.GetNetscalerPassword(), "nsip", "", "")
	if errc != nil {
		t.Errorf("newAdsClient failed with %v", errc)
	}
	discoveryClient.StartClient()
	routeA := env.MakeRoute("ra", "svca.dummyrootcitrix1.com", "ca")
	routeB := env.MakeRoute("rb", "svcb.dummyrootcitrix2.com", "cb")
	sniInfo := []env.SniInfo{
		{ServerName: "svca.dummyrootcitrix1.com", RouteName: "ra", CertFile: "certs/certssvca/svca.dummyrootcitrix1.com.crt", KeyFile: "certs/certssvca/svca.dummyrootcitrix1.com.key", RootFile: "certs/certssvca/rootCA1.crt"},
		{ServerName: "svcb.dummyrootcitrix2.com", RouteName: "rb", CertFile: "certs/certssvcb/svcb.dummyrootcitrix2.com.crt", KeyFile: "certs/certssvcb/svcb.dummyrootcitrix2.com.key", RootFile: "certs/certssvcb/rootCA2.crt"},
	}
	listener, errl := env.MakeHttpsSniListener("l1", "0.0.0.0", 8005, sniInfo)
	if errl != nil {
		t.Errorf("MakeHttpsSniListener failed with %v", errl)
	}
	clusterA := env.MakeCluster("ca")
	endpointA := env.MakeEndpoint("ca", []env.ServiceEndpoint{{env.GetLocalIP(), 9041}})
	clusterB := env.MakeCluster("cb")
	endpointB := env.MakeEndpoint("cb", []env.ServiceEndpoint{{env.GetLocalIP(), 9042}})

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
	env.RemoveAddressFromHostFile(env.GetNetscalerIP())
	discoveryClient.StopClient()
	grpcServer.StopGrpcADSServer()
	env.StopHTTPServer(httpServerA)
	env.StopHTTPServer(httpServerB)
	t.Log("Https sni service test stop")
}
