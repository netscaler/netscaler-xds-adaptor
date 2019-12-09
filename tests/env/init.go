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

package env

import (
	"fmt"
	"github.com/chiradeep/go-nitro/netscaler"
	xdsapi "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/auth"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/endpoint"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/listener"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/route"
	hcm "github.com/envoyproxy/go-control-plane/envoy/config/filter/network/http_connection_manager/v2"
	tcm "github.com/envoyproxy/go-control-plane/envoy/config/filter/network/tcp_proxy/v2"
	"github.com/envoyproxy/go-control-plane/pkg/util"
	"github.com/gogo/protobuf/types"
	"github.com/txn2/txeh"
	"io/ioutil"
	"net"
	"os"
	"time"
)

func GetNetscalerIP() string {
	return os.Getenv("NS_TEST_IP")
}

func GetNetscalerURL() string {
	return "http://" + GetNetscalerIP() + ":" + os.Getenv("NS_TEST_NITRO_PORT")
}

func GetNetscalerUser() string {
	return os.Getenv("NS_TEST_LOGIN")
}

func GetNetscalerPassword() string {
	return os.Getenv("NS_TEST_PASSWORD")
}

func GetNitroClient() *netscaler.NitroClient {
	return netscaler.NewNitroClient(GetNetscalerURL(), GetNetscalerUser(), GetNetscalerPassword())
}

func ClearNetscalerConfig() {
	client := GetNitroClient()
	client.ClearConfig()
	fmt.Println("Cleared netscaler config")
}

func GetLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, address := range addrs {
			if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					return ipnet.IP.String()
				}
			}
		}
	}
	return ""
}

func Init() {
	client := GetNitroClient()
	for {
		_, err := client.FindFilteredResourceArray(netscaler.Nsip.Type(), map[string]string{"type": "NSIP"})
		if err == nil {
			break
		}
		time.Sleep(1 * time.Second)
	}
	client.ClearConfig()
	fmt.Println("Netscaler is ready")
}

func AddHostToHostFile(ip string, hostName string, hostNames []string) error {
	hosts, err := txeh.NewHostsDefault()
	if err != nil {
		return err
	}
	if hostName != "" {
		hosts.AddHost(ip, hostName)
	}
	if hostNames != nil {
		hosts.AddHosts(ip, hostNames)
	}

	hosts.Save()
	fmt.Printf("Host render file:\n")
	hfData := hosts.RenderHostsFile()
	fmt.Println(hfData)
	fmt.Printf("/etc/hosts:\n")
	file, errf := os.Open("/etc/hosts")
	if errf != nil {
		fmt.Printf("File open failed - %v", err)
	} else {
		b, _ := ioutil.ReadAll(file)
		fmt.Print("___________________________________\n")
		fmt.Print(string(b))
		file.Close()
	}
	return nil
}

func RemoveAddressFromHostFile(ip string) error {
	hosts, err := txeh.NewHostsDefault()
	if err != nil {
		return err
	}
	hosts.RemoveAddress(ip)
	hosts.Save()
	return nil
}

type ServiceEndpoint struct {
	IP   string
	Port int
}

func MakeEndpoint(clusterName string, serviceEndpoints []ServiceEndpoint) *xdsapi.ClusterLoadAssignment {
	lbEndpoints := make([]endpoint.LbEndpoint, 0)
	for _, ep := range serviceEndpoints {
		lbEndpoint := endpoint.LbEndpoint{
			HostIdentifier: &endpoint.LbEndpoint_Endpoint{
				Endpoint: &endpoint.Endpoint{
					Address: &core.Address{
						Address: &core.Address_SocketAddress{
							SocketAddress: &core.SocketAddress{
								Protocol:      core.TCP,
								Address:       ep.IP,
								PortSpecifier: &core.SocketAddress_PortValue{PortValue: uint32(ep.Port)},
							},
						},
					},
				},
			},
		}
		lbEndpoints = append(lbEndpoints, lbEndpoint)
	}
	return &xdsapi.ClusterLoadAssignment{
		ClusterName: clusterName,
		Endpoints: []endpoint.LocalityLbEndpoints{
			endpoint.LocalityLbEndpoints{
				LbEndpoints: lbEndpoints,
			},
		},
	}
}

func MakeCluster(clusterName string) *xdsapi.Cluster {
	return &xdsapi.Cluster{
		Name:           clusterName,
		ConnectTimeout: 1 * time.Second,
		ClusterDiscoveryType: &xdsapi.Cluster_Type{
			Type: xdsapi.Cluster_EDS,
		},
		LbPolicy: xdsapi.Cluster_ROUND_ROBIN,
		EdsClusterConfig: &xdsapi.Cluster_EdsClusterConfig{
			ServiceName: clusterName,
		},
	}
}

func MakeRoute(routeName string, domain string, clusterName string) *xdsapi.RouteConfiguration {
	return &xdsapi.RouteConfiguration{
		Name: routeName,
		VirtualHosts: []route.VirtualHost{{
			Name:    routeName,
			Domains: []string{domain},
			Routes: []route.Route{{
				Match: route.RouteMatch{PathSpecifier: &route.RouteMatch_Prefix{Prefix: "/"}},
				Action: &route.Route_Route{Route: &route.RouteAction{
					ClusterSpecifier: &route.RouteAction_Cluster{Cluster: clusterName},
				}},
			}},
		}},
	}
}

func MakeListener(listenerName string, ip string, port uint16, filter listener.Filter) (*xdsapi.Listener, error) {
	return &xdsapi.Listener{
		Name: listenerName,
		Address: core.Address{Address: &core.Address_SocketAddress{SocketAddress: &core.SocketAddress{
			Address:       ip,
			PortSpecifier: &core.SocketAddress_PortValue{PortValue: uint32(port)}}}},
		FilterChains: []listener.FilterChain{
			{Filters: []listener.Filter{filter}}},
	}, nil
}

func MakeTcpListener(listenerName string, ip string, port uint16, clusterName string) (*xdsapi.Listener, error) {
	filterTCPListenerS := &tcm.TcpProxy{
		StatPrefix: listenerName,
		ClusterSpecifier: &tcm.TcpProxy_Cluster{
			Cluster: clusterName,
		},
	}
	filterTCPListener, err := util.MessageToStruct(filterTCPListenerS)
	if err != nil {
		return nil, err
	}
	filter := listener.Filter{
		Name: util.TCPProxy,
		ConfigType: &listener.Filter_Config{
			Config: filterTCPListener,
		},
	}
	return MakeListener(listenerName, ip, port, filter)
}

func MakeHttpFilter(listenerName string, routeName string) (listener.Filter, error) {
	filterHTTPConnS := &hcm.HttpConnectionManager{
		StatPrefix: listenerName,
		RouteSpecifier: &hcm.HttpConnectionManager_Rds{
			Rds: &hcm.Rds{RouteConfigName: routeName}},
		HttpFilters: []*hcm.HttpFilter{{Name: util.Router}},
	}
	filterHTTPConn, err := util.MessageToStruct(filterHTTPConnS)
	if err != nil {
		return listener.Filter{}, err
	}
	filter := listener.Filter{
		Name: "envoy.http_connection_manager",
		ConfigType: &listener.Filter_Config{
			Config: filterHTTPConn,
		},
	}
	return filter, nil
}

func MakeHttpListener(listenerName string, ip string, port uint16, routeName string) (*xdsapi.Listener, error) {
	filter, err := MakeHttpFilter(listenerName, routeName)
	if err != nil {
		return nil, err
	}
	return MakeListener(listenerName, ip, port, filter)
}

func MakeTLSContext(certFile, keyFile, rootFile string) *auth.CommonTlsContext {
	tlsContext := &auth.CommonTlsContext{}
	if certFile != "" {
		tlsContext.TlsCertificates = []*auth.TlsCertificate{{
			CertificateChain: &core.DataSource{Specifier: &core.DataSource_Filename{Filename: certFile}},
			PrivateKey:       &core.DataSource{Specifier: &core.DataSource_Filename{Filename: keyFile}},
		}}
	}
	if rootFile != "" {
		tlsContext.ValidationContextType = &auth.CommonTlsContext_ValidationContext{
			ValidationContext: &auth.CertificateValidationContext{
				TrustedCa: &core.DataSource{Specifier: &core.DataSource_Filename{Filename: rootFile}},
			},
		}
	}
	return tlsContext
}

func MakeHttpsListener(listenerName string, ip string, port uint16, routeName string, certFile, keyFile, rootFile string, clientAuth bool) (*xdsapi.Listener, error) {
	lds, err := MakeHttpListener(listenerName, ip, port, routeName)
	if err != nil {
		return nil, err
	}
	commonTlsContext := MakeTLSContext(certFile, keyFile, rootFile)
	lds.FilterChains[0].TlsContext = &auth.DownstreamTlsContext{CommonTlsContext: commonTlsContext, RequireClientCertificate: &types.BoolValue{Value: clientAuth}}
	return lds, nil
}

func MakeTcpSslListener(listenerName string, ip string, port uint16, clusterName string, certFile, keyFile, rootFile string, clientAuth bool) (*xdsapi.Listener, error) {
	lds, err := MakeTcpListener(listenerName, ip, port, clusterName)
	if err != nil {
		return nil, err
	}
	commonTlsContext := MakeTLSContext(certFile, keyFile, rootFile)
	lds.FilterChains[0].TlsContext = &auth.DownstreamTlsContext{CommonTlsContext: commonTlsContext, RequireClientCertificate: &types.BoolValue{Value: clientAuth}}
	return lds, nil
}

type SniInfo struct {
	ServerName string
	CertFile   string
	KeyFile    string
	RootFile   string
	RouteName  string
}

func MakeHttpsSniListener(listenerName string, ip string, port uint16, sniInfos []SniInfo) (*xdsapi.Listener, error) {
	filterChains := make([]listener.FilterChain, 0)
	for _, sniInfo := range sniInfos {
		filter, err := MakeHttpFilter(listenerName, sniInfo.RouteName)
		if err != nil {
			return nil, err
		}
		tlsContext := &auth.DownstreamTlsContext{CommonTlsContext: MakeTLSContext(sniInfo.CertFile, sniInfo.KeyFile, sniInfo.RootFile)}
		filterChain := listener.FilterChain{
			Filters:          []listener.Filter{filter},
			TlsContext:       tlsContext,
			FilterChainMatch: &listener.FilterChainMatch{ServerNames: []string{sniInfo.ServerName}},
		}
		filterChains = append(filterChains, filterChain)
	}
	return &xdsapi.Listener{
		Name: listenerName,
		Address: core.Address{Address: &core.Address_SocketAddress{SocketAddress: &core.SocketAddress{
			Address:       ip,
			PortSpecifier: &core.SocketAddress_PortValue{PortValue: uint32(port)}}}},
		FilterChains: filterChains,
	}, nil
}
