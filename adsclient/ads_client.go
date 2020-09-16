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

package adsclient

import (
	"citrix-xds-adaptor/certkeyhandler"
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	xdsapi "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	envoy_api_v2_core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	ads "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v2"
	"github.com/golang/protobuf/ptypes"
	"google.golang.org/grpc"
)

const (
	cdsURL = "type.googleapis.com/envoy.api.v2.Cluster"
	ldsURL = "type.googleapis.com/envoy.api.v2.Listener"
	edsURL = "type.googleapis.com/envoy.api.v2.ClusterLoadAssignment"
	rdsURL = "type.googleapis.com/envoy.api.v2.RouteConfiguration"
)

type cdsAddHandlerType func(*configAdaptor, *xdsapi.Cluster, interface{}) string
type cdsDelHandlerType func(*configAdaptor, string)
type edsAddHandlerType func(*configAdaptor, *xdsapi.ClusterLoadAssignment, interface{})
type ldsAddHandlerType func(*configAdaptor, *xdsapi.Listener) []map[string]interface{}
type ldsDelHandlerType func(*configAdaptor, string, []string)
type rdsAddHandlerType func(*configAdaptor, []*xdsapi.RouteConfiguration, interface{}) map[string]interface{}

//AdsDetails will define the members which will be read up at bootup time
type AdsDetails struct {
	AdsServerURL      string
	AdsServerSpiffeID string
	SecureConnect     bool
	NodeID            string
	ApplicationName   string
}

//NSDetails will define the members which will be read up at bootup time
type NSDetails struct {
	NetscalerURL      string
	NetscalerUsername string
	NetscalerPassword string
	NetscalerVIP      string
	NetProfile        string
	AnalyticsServerIP string
	LicenseServerIP   string
	LogProxyURL       string
	SslVerify         bool
	RootCAPath        string
	ServerName        string
	adsServerPort     string
	LocalHostVIP      string
	caServerPort      string
}

type apiRequest struct {
	typeURL     string
	versionInfo string
	nonce       string
	resources   map[string]interface{}
	/*
		ldsURL -> [filterChaninName]
		rdsURL -> lds Name, filterChainName, serviceType
		cdsURL -> serviceType
		edsURL -> cds Name
	*/
	handler func(*AdsClient, *xdsapi.DiscoveryResponse)
}

// AdsClient is a client to an Aggregated Discovery Service
type AdsClient struct {
	nsInfo             *NSDetails
	adsServerURL       string
	adsServerSpiffeID  string
	secureConnect      bool
	nodeID             *envoy_api_v2_core.Node
	apiRequests        map[string]*apiRequest
	connection         *grpc.ClientConn
	connectionMux      sync.Mutex
	stream             grpc.ClientStream
	quit               chan int
	nsConfigAdaptor    *configAdaptor
	nsConfigAdaptorMux sync.Mutex
	cdsAddHandler      cdsAddHandlerType
	cdsDelHandler      cdsDelHandlerType
	edsAddHandler      edsAddHandlerType
	ldsAddHandler      ldsAddHandlerType
	ldsDelHandler      ldsDelHandlerType
	rdsAddHandler      rdsAddHandlerType
	caInfo             *certkeyhandler.CADetails
	ckHandler          *certkeyhandler.CertKeyHandler
	ckHandlerMux       sync.Mutex
}

func (client *AdsClient) writeADSRequest(req *apiRequest) {
	var resourceNames []string
	if req.typeURL == edsURL || req.typeURL == rdsURL {
		resourceNames = make([]string, len(req.resources))
		i := 0
		for k := range req.resources {
			resourceNames[i] = k
			i++
		}
	}
	msg := &xdsapi.DiscoveryRequest{TypeUrl: req.typeURL, Node: client.nodeID, VersionInfo: req.versionInfo, ResponseNonce: req.nonce, ResourceNames: resourceNames}
	if err := client.stream.SendMsg(msg); err != nil {
		log.Printf("[ERROR] Failed to send a message: %v", err)
	} else {
		log.Printf("[TRACE] Wrote req message : version-%s  nonce-%s  type-%s", msg.VersionInfo, msg.ResponseNonce, msg.TypeUrl)
	}
}

func (client *AdsClient) callRequestHandler(msg *xdsapi.DiscoveryResponse) error {
	if client.apiRequests[msg.TypeUrl].handler != nil {
		client.nsConfigAdaptorMux.Lock()
		defer client.nsConfigAdaptorMux.Unlock()
		if client.nsConfigAdaptor != nil {
			client.apiRequests[msg.TypeUrl].handler(client, msg)
		} else {
			return fmt.Errorf("ADS client has no config-adaptor")
		}
	}
	return nil
}

func (client *AdsClient) readADSResponse() {
	for {
		m := new(xdsapi.DiscoveryResponse)
		if err := client.stream.RecvMsg(m); err != nil {
			log.Printf("[ERROR] Failed to recv a message: %v", err)
			time.Sleep(2 * time.Second)
			return
		}
		log.Printf("[TRACE] Received a message at version: %s  for type: %s resourceCount: %d", m.VersionInfo, m.TypeUrl, len(m.Resources))
		if err := client.callRequestHandler(m); err != nil {
			log.Printf("[ERROR] Request handler returned error: %v", err)
			return
		}
		client.apiRequests[m.TypeUrl].versionInfo = m.VersionInfo
		client.apiRequests[m.TypeUrl].nonce = m.Nonce
		client.writeADSRequest(client.apiRequests[m.TypeUrl])
	}
}

func cdsHandler(client *AdsClient, m *xdsapi.DiscoveryResponse) {
	clusterNames := make(map[string]bool)
	edsResources := make(map[string]interface{})
	requestEds := false
	cdsResource := &xdsapi.Cluster{}
	for _, resource := range m.Resources {
		if err := ptypes.UnmarshalAny(resource, cdsResource); err != nil {
			log.Printf("[TRACE]:Could not find Unmarshal resources in CDS Handler")
			continue
		}
		clusterNames[cdsResource.Name] = true
		if _, ok := client.apiRequests[cdsURL].resources[cdsResource.Name]; ok {
			edsName := client.cdsAddHandler(client.nsConfigAdaptor, cdsResource, client.apiRequests[cdsURL].resources[cdsResource.Name])
			if edsName != "" {
				edsResources[edsName] = cdsResource.Name
				if _, ok1 := client.apiRequests[edsURL].resources[edsName]; !ok1 {
					requestEds = true
				}
			}
		}
	}
	for clusterName := range client.apiRequests[cdsURL].resources {
		if _, ok := clusterNames[clusterName]; !ok {
			client.cdsDelHandler(client.nsConfigAdaptor, clusterName)
		}
	}
	client.apiRequests[edsURL].resources = edsResources

	if requestEds == true {
		client.writeADSRequest(client.apiRequests[edsURL])
	}
}

func ldsHandler(client *AdsClient, m *xdsapi.DiscoveryResponse) {
	rdsResources := make(map[string]interface{})
	ldsResources := make(map[string]interface{})
	requestRds := false
	requestCds := false
	ldsResource := &xdsapi.Listener{}
	for _, resource := range m.Resources {
		if err := ptypes.UnmarshalAny(resource, ldsResource); err != nil {
			log.Printf("[TRACE]:Could not find Unmarshal resources in LDS handler")
			continue
		}
		ldsResources[ldsResource.Name] = make([]string, 0)
		dependentResourcesList := client.ldsAddHandler(client.nsConfigAdaptor, ldsResource)
		for _, dependentResources := range dependentResourcesList {
			for _, rdsConfigName := range dependentResources["rdsNames"].([]string) {
				rdsResources[rdsConfigName] = dependentResources
				if _, ok := client.apiRequests[rdsURL].resources[rdsConfigName]; !ok {
					requestRds = true
				}
			}
			for _, cdsConfigName := range dependentResources["cdsNames"].([]string) {
				if _, ok := client.apiRequests[cdsURL].resources[cdsConfigName]; !ok {
					requestCds = true
					client.apiRequests[cdsURL].resources[cdsConfigName] = dependentResources["serviceType"]
				}
			}
			if dependentResources["filterChainName"].(string) != "" {
				ldsResources[ldsResource.Name] = append(ldsResources[ldsResource.Name].([]string), dependentResources["filterChainName"].(string))
			}
		}
	}
	for ldsResourceName := range client.apiRequests[ldsURL].resources {
		if _, ok := ldsResources[ldsResourceName]; !ok {
			client.ldsDelHandler(client.nsConfigAdaptor, ldsResourceName, client.apiRequests[ldsURL].resources[ldsResourceName].([]string))
		}
	}

	client.apiRequests[ldsURL].resources = ldsResources
	client.apiRequests[rdsURL].resources = rdsResources

	if requestRds == true {
		client.writeADSRequest(client.apiRequests[rdsURL])
	}
	if requestCds == true {
		client.reloadCds()
	}
}

func edsHandler(client *AdsClient, m *xdsapi.DiscoveryResponse) {
	edsResource := &xdsapi.ClusterLoadAssignment{}
	for _, resource := range m.Resources {
		if err := ptypes.UnmarshalAny(resource, edsResource); err != nil {
			log.Printf("[TRACE]:Could not find Unmarshal resources in EDS handler")
			continue
		}
		if _, ok := client.apiRequests[edsURL].resources[edsResource.GetClusterName()]; !ok {
			log.Printf("[ERROR]: received an EDS resource that we haven't yet subscribed for %s ... ignoring", edsResource.GetClusterName())
			continue
		}
		client.edsAddHandler(client.nsConfigAdaptor, edsResource, client.apiRequests[edsURL].resources[edsResource.GetClusterName()])
	}
}

func rdsHandler(client *AdsClient, m *xdsapi.DiscoveryResponse) {
	requestCds := false
	rdsToLds := make(map[string][]*xdsapi.RouteConfiguration)
	for _, resource := range m.Resources {
		rdsResource := &xdsapi.RouteConfiguration{}
		if err := ptypes.UnmarshalAny(resource, rdsResource); err != nil {
			continue
		}
		if _, ok := client.apiRequests[rdsURL].resources[rdsResource.GetName()]; !ok {
			log.Printf("[ERROR]: received an RDS resource that we haven't yet subscribed for %s ... ignoring", rdsResource.GetName())
			continue
		}
		listenerName := client.apiRequests[rdsURL].resources[rdsResource.GetName()].(map[string]interface{})["listenerName"].(string)
		if _, ok := rdsToLds[listenerName]; !ok {
			rdsToLds[listenerName] = make([]*xdsapi.RouteConfiguration, 0)
		}
		rdsToLds[listenerName] = append(rdsToLds[listenerName], rdsResource)
	}
	log.Printf("[DEBUG] rdsToLds - %v", rdsToLds)
	for _, rdsArray := range rdsToLds {
		dependentClusters := client.rdsAddHandler(client.nsConfigAdaptor, rdsArray, client.apiRequests[rdsURL].resources[rdsArray[0].GetName()])
		for _, clusterName := range dependentClusters["cdsNames"].([]string) {
			if _, ok := client.apiRequests[cdsURL].resources[clusterName]; !ok {
				requestCds = true
				client.apiRequests[cdsURL].resources[clusterName] = dependentClusters["serviceType"]
			}
		}
	}
	if requestCds == true {
		client.reloadCds()
	}
}

func (client *AdsClient) reloadCds() {
	if client.apiRequests[cdsURL].nonce == "" {
		client.writeADSRequest(client.apiRequests[cdsURL])
		return
	}
	client.connectionMux.Lock()
	adsClient := ads.NewAggregatedDiscoveryServiceClient(client.connection)
	client.connectionMux.Unlock()
	stream, err := adsClient.StreamAggregatedResources(context.Background())
	if err != nil {
		log.Printf("[ERROR] reloadCds create stream failed : %v", err)
		return
	}
	if err = stream.Send(&xdsapi.DiscoveryRequest{TypeUrl: cdsURL, Node: client.nodeID}); err != nil {
		log.Printf("[ERROR] reloadCds send request failed : %v", err)
	} else {
		res, err := stream.Recv()
		if err != nil {
			log.Printf("[ERROR] reloadCds recv failed : %v", err)
		} else {
			log.Printf("[TRACE] reloadCds rcvd message")
			cdsHandler(client, res)
		}
	}
	stream.CloseSend()
}

//NewAdsClient returns a new Aggregated Discovery Service client
func NewAdsClient(adsinfo *AdsDetails, nsinfo *NSDetails, cainfo *certkeyhandler.CADetails) (*AdsClient, error) {
	adsClient := new(AdsClient)
	adsClient.adsServerURL = adsinfo.AdsServerURL
	adsClient.adsServerSpiffeID = adsinfo.AdsServerSpiffeID
	adsClient.secureConnect = adsinfo.SecureConnect
	adsClient.nodeID = &envoy_api_v2_core.Node{Id: adsinfo.NodeID, Cluster: adsinfo.ApplicationName}
	adsClient.quit = make(chan int)
	adsClient.cdsAddHandler = clusterAdd
	adsClient.cdsDelHandler = clusterDel
	adsClient.ldsAddHandler = listenerAdd
	adsClient.ldsDelHandler = listenerDel
	adsClient.edsAddHandler = clusterEndpointUpdate
	adsClient.rdsAddHandler = routeUpdate
	s := strings.Split(adsinfo.AdsServerURL, ":")
	nsinfo.adsServerPort = "unknown"
	if len(s) > 1 {
		nsinfo.adsServerPort = s[1]
	}
	if cainfo != nil {
		s = strings.Split(cainfo.CAAddress, ":")
		if len(s) > 1 {
			nsinfo.caServerPort = s[1]
		}
	}
	adsClient.nsInfo = nsinfo
	adsClient.caInfo = cainfo
	return adsClient, nil
}

// GetNodeID returns the node ID of the client
func (client *AdsClient) GetNodeID() *envoy_api_v2_core.Node {
	return client.nodeID
}

func (client *AdsClient) startCertKeyHandler(errCh chan<- error) error {
	if client.caInfo == nil {
		log.Printf("[DEBUG] CA details are not specified. Not creating certificate key handler.")
		return nil
	}
	certinfo := new(certkeyhandler.CertDetails)
	certinfo.RootCertFile = CAcertFile
	certinfo.CertChainFile = ClientCertChainFile
	certinfo.CertFile = ClientCertFile
	certinfo.KeyFile = ClientKeyFile
	certinfo.RSAKeySize = rsaKeySize
	certinfo.Org = orgName
	certkeyhdlr, err := certkeyhandler.NewCertKeyHandler(client.caInfo, certinfo)
	if err != nil {
		log.Printf("[ERROR] Could not create certkey handler. Error: %s", err.Error())
		return err
	}
	client.ckHandlerMux.Lock()
	client.ckHandler = certkeyhdlr
	client.ckHandlerMux.Unlock()
	go certkeyhdlr.StartHandler(errCh)
	return nil
}

// StartClient starts connecting and listening to the ADS server
func (client *AdsClient) StartClient() {
	var err error
	log.Printf("[TRACE]: Starting ADS client")
	go func() {
		ckHandlerStarted := false
		ckhErrCh := make(chan error)
		for {
			select {
			case <-client.quit:
				log.Printf("[TRACE]: Stopping ADS client")
				return
			case ckherr := <-ckhErrCh:
				if ckherr != nil {
					log.Printf("[ERROR] Certificate Key Handler Problem. %s", ckherr.Error())
					client.ckHandlerMux.Lock()
					client.ckHandler = nil
					client.ckHandlerMux.Unlock()
					// Start handler again
					if err := client.startCertKeyHandler(ckhErrCh); err != nil {
						log.Printf("[ERROR] Could not start certificate key handler. Error= %s", err.Error())
						return
					}
					ckHandlerStarted = true
				}
			default:
				err = client.assignConfigAdaptor()
				if err != nil {
					continue
				}
				if client.caInfo != nil && ckHandlerStarted == false {
					if err := client.startCertKeyHandler(ckhErrCh); err != nil {
						log.Printf("[ERROR] Could not start certificate key handler. Error= %s", err.Error())
						return
					}
					ckHandlerStarted = true
				}
				client.connectionMux.Lock()
				if client.secureConnect == true {
					client.connection, err = secureConnectToServer(client.adsServerURL, client.adsServerSpiffeID)
				} else {
					client.connection, err = insecureConnectToServer(client.adsServerURL, ckHandlerStarted)
				}
				if err != nil {
					log.Printf("[TRACE]: Connection to grpc server failed with %v", err)
					client.connectionMux.Unlock()
					time.Sleep(1 * time.Second)
					continue
				}
				adsClient := ads.NewAggregatedDiscoveryServiceClient(client.connection)
				client.connectionMux.Unlock()
				client.stream, err = adsClient.StreamAggregatedResources(context.Background())
				if err != nil {
					log.Printf("[ERROR] grpc Creating new stream failed with : %v", err)
					continue
				}
				client.apiRequests = map[string]*apiRequest{
					cdsURL: &apiRequest{typeURL: cdsURL, handler: cdsHandler, resources: make(map[string]interface{})},
					ldsURL: &apiRequest{typeURL: ldsURL, handler: ldsHandler, resources: make(map[string]interface{})},
					edsURL: &apiRequest{typeURL: edsURL, handler: edsHandler, resources: make(map[string]interface{})},
					rdsURL: &apiRequest{typeURL: rdsURL, handler: rdsHandler, resources: make(map[string]interface{})},
				}
				client.writeADSRequest(client.apiRequests[ldsURL])
				client.readADSResponse()
				client.stopClientConnection(true)
			}
		}
	}()
}

func (client *AdsClient) assignConfigAdaptor() error {
	var err error
	client.nsConfigAdaptorMux.Lock()
	defer client.nsConfigAdaptorMux.Unlock()
	if client.nsConfigAdaptor == nil {
		client.nsConfigAdaptor, err = newConfigAdaptor(client.nsInfo)
		if err != nil {
			return err
		}
		client.nsConfigAdaptor.startConfigAdaptor(client)
	}
	return nil
}

func (client *AdsClient) releaseConfigAdaptor(shouldStopConfigAdaptor bool) {
	client.nsConfigAdaptorMux.Lock()
	defer client.nsConfigAdaptorMux.Unlock()
	if client.nsConfigAdaptor != nil {
		if shouldStopConfigAdaptor == true {
			client.nsConfigAdaptor.stopConfigAdaptor()
		}
		client.nsConfigAdaptor = nil
	}
}

func (client *AdsClient) stopClientConnection(shouldStopConfigAdaptor bool) {
	client.connectionMux.Lock()
	if client.connection != nil {
		client.connection.Close()
	}
	client.connectionMux.Unlock()
	client.releaseConfigAdaptor(shouldStopConfigAdaptor)
	log.Printf("[TRACE]: closed client connection")
}

// StopClient closes the connection to the ADS server
func (client *AdsClient) StopClient() {
	client.stopClientConnection(true)
	client.ckHandlerMux.Lock()
	if client.ckHandler != nil {
		client.ckHandler.StopHandler()
	}
	client.ckHandlerMux.Unlock()
	client.quit <- 1
	log.Printf("[TRACE]: Stopped adsClient")
}
