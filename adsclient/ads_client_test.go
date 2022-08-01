/*
Copyright 2022 Citrix Systems, Inc
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
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/citrix/citrix-xds-adaptor/certkeyhandler"
	"github.com/citrix/citrix-xds-adaptor/tests/env"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
)

func setCertEnv(certpath string) error {
	err := os.MkdirAll("/etc/certs", 0777)
	if err != nil {
		return fmt.Errorf("Could not create directory /etc/certs")
	}
	err = copyFile(certpath, ClientCertFile)
	if err != nil {
		return fmt.Errorf("Could not copy %s contents to %s. Err=%s", certpath, ClientCertFile, err)
	}
	return nil
}

func Test_StartClient(t *testing.T) {
	t.Logf("ads StartClient with unreachable secure ads grpc server")
	nsinfo := new(NSDetails)
	adsinfo := new(AdsDetails)
	adsinfo.AdsServerURL = "localhost:15011"
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
	nsinfo.LicenseServer = ""
	nsinfo.LogProxyURL = "ns-logproxy.citrix-system"
	// CA details
	cainfo := new(certkeyhandler.CADetails)
	cainfo.CAAddress = "localhost:15012"
	cainfo.CAProvider = "Istiod"
	cainfo.ClusterID = "Kubernetes"
	cainfo.Env = "onprem"
	cainfo.TrustDomain = "cluster.local"
	cainfo.NameSpace = "my-namespace"
	cainfo.SAName = "my-service"
	cainfo.CertTTL = 1 * time.Hour
	err := setCertEnv("../tests/tls_conn_mgmt_certs/client-cert.pem")
	if err != nil {
		t.Errorf("Could not set certificate environment for StartClient")
	}
	adsClient, err := NewAdsClient(adsinfo, nsinfo, cainfo)
	if err != nil {
		t.Errorf("newAdsClient failed with %v", err)
	}

	adsClient.StartClient()
	time.Sleep(3 * time.Second)
	adsClient.StopClient()
	t.Logf("ads StartClient with unreachable insecure ads grpc server")
	adsinfo.AdsServerURL = "localhost:15010"
	adsClient, err = NewAdsClient(adsinfo, nsinfo, nil)
	if err != nil {
		t.Errorf("newAdsClient failed with %v", err)
	}
	adsClient.StartClient()
	time.Sleep(2 * time.Second)
	adsClient.StopClient()
	// Delete the etc/certs directory created in setCertEnv
	if err := os.RemoveAll("/etc/certs"); err != nil {
		t.Errorf("Could not delete /etc/certs")
	}
}

func Test_http_clusters(t *testing.T) {
	t.Log("http clusters test start")
	multiClusterIngress = true // To get all clusters from xds-server
	multiClusterPolExprStr = ".global"
	multiClusterListenPort = 15443
	env.ClearNetscalerConfig()
	grpcServer, err := env.NewGrpcADSServer(0)
	if err != nil {
		t.Errorf("GRPC server creation failed: %v", err)
	}
	adsinfo := new(AdsDetails)
	nsinfo := new(NSDetails)
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
	discoveryClient, err := NewAdsClient(adsinfo, nsinfo, nil)
	if err != nil {
		t.Errorf("newAdsClient failed with %v", err)
	}
	discoveryClient.StartClient()
	routeR1 := env.MakeRoute("r1", []env.RouteInfo{{Domain: "*", ClusterName: "c1"}})
	listenerL1, err := env.MakeHttpListener("l1", "0.0.0.0", 8000, outboundDir, "r1")
	if err != nil {
		t.Errorf("makeListener failed with %v", err)
	}
	clusterC1 := env.MakeCluster("c1")
	endpointE1 := env.MakeEndpoint("c1", []env.ServiceEndpoint{{env.GetLocalIP(), 9000, 1}})

	clusterC2 := env.MakeCluster("c2")
	clusterC3 := env.MakeCluster("c3")

	err = grpcServer.UpdateSpanshotCacheMulti("1", discoveryClient.GetNodeID(), []*listener.Listener{listenerL1}, []*route.RouteConfiguration{routeR1}, []*cluster.Cluster{clusterC1, clusterC3, clusterC2}, []*endpoint.ClusterLoadAssignment{endpointE1})
	if err != nil {
		t.Errorf("updateSpanshotCacheMulti failed with %v", err)
	}

	time.Sleep(5 * time.Second)

	configs := []env.VerifyNitroConfig{
		{"lbvserver", "c1", map[string]interface{}{"name": "c1", "servicetype": "HTTP"}},
		{"lbvserver", "c2", map[string]interface{}{"name": "c2", "servicetype": "HTTP"}},
		{"lbvserver", "c3", map[string]interface{}{"name": "c3", "servicetype": "HTTP"}},
	}
	client := env.GetNitroClient()
	err = env.VerifyConfigBlockPresence(client, configs)
	if err != nil {
		t.Errorf("Clusters verification failed with %v", err)
	}

	discoveryClient.StopClient()
	grpcServer.StopGrpcADSServer()
	t.Log("HTTP clusters test stop")
}
