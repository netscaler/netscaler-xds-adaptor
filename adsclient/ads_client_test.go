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
	"citrix-istio-adaptor/tests/env"
	"testing"
	"time"
)

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
	nsinfo.LogProxyURL = "ns-logproxy.citrix-system"
	adsClient, err := NewAdsClient(adsinfo, nsinfo)
	if err != nil {
		t.Errorf("newAdsClient failed with %v", err)
	}
	adsClient.StartClient()
	time.Sleep(3 * time.Second)
	adsClient.StopClient()
	t.Logf("ads StartClient with unreachable insecure ads grpc server")
	adsinfo.AdsServerURL = "localhost:15010"
	adsClient, err = NewAdsClient(adsinfo, nsinfo)
	if err != nil {
		t.Errorf("newAdsClient failed with %v", err)
	}
	adsClient.StartClient()
	time.Sleep(2 * time.Second)
	adsClient.StopClient()
}
