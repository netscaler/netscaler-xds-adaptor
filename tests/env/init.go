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

package env

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/citrix/adc-nitro-go/resource/config/dns"
	netscaler "github.com/citrix/adc-nitro-go/service"
	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	auth "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	xdsutil "github.com/envoyproxy/go-control-plane/pkg/wellknown"
	ptypes "github.com/golang/protobuf/ptypes"
	duration "github.com/golang/protobuf/ptypes/duration"
	wrappers "github.com/golang/protobuf/ptypes/wrappers"
	"github.com/txn2/txeh"
	proto "istio.io/istio/pkg/proto"
)

const (
	EnvoyTLSSocketName = "envoy.transport_sockets.tls"
	SDSClusterName     = "sds-grpc"
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
	cpxpassfile := "/var/deviceinfo/random_id"
	if _, err := os.Stat(cpxpassfile); err == nil {
		pass, err := ioutil.ReadFile(cpxpassfile)
		if err == nil {
			return string(pass)
		}
	}
	return os.Getenv("NS_TEST_PASSWORD")
}

func GetNitroClient() *netscaler.NitroClient {
	var params netscaler.NitroParams
	params.Url = GetNetscalerURL()
	params.Username = GetNetscalerUser()
	params.Password = GetNetscalerPassword()
	params.LogLevel = "DEBUG"
	params.JSONLogFormat = true
	client, _ := netscaler.NewNitroClientFromParams(params)
	return client
}

func ClearNetscalerConfig() {
	client := GetNitroClient()
	client.ClearConfig()
	fmt.Println("Cleared netscaler config")
}

func getNameServer() (string, error) {
	b, err := ioutil.ReadFile("/etc/resolv.conf")
	if err != nil {
		return "", err
	}
	re := regexp.MustCompile("[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+")
	match := re.FindString(string(b))
	return match, nil
}

func ConfigureDNS() error {
	nameserver, err := getNameServer()
	if err != nil {
		return err
	}
	client := GetNitroClient()
	_, err = client.AddResource(netscaler.Dnsnameserver.Type(), "", &dns.Dnsnameserver{Ip: nameserver})
	return err
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
	IP     string
	Port   int
	Weight uint32
}

func MakeEndpoint(clusterName string, serviceEndpoints []ServiceEndpoint) *endpoint.ClusterLoadAssignment {
	lbEndpoints := make([]*endpoint.LbEndpoint, 0)
	for _, ep := range serviceEndpoints {
		lbEndpoint := endpoint.LbEndpoint{
			HostIdentifier: &endpoint.LbEndpoint_Endpoint{
				Endpoint: &endpoint.Endpoint{
					Address: &core.Address{
						Address: &core.Address_SocketAddress{
							SocketAddress: &core.SocketAddress{
								Protocol:      core.SocketAddress_TCP,
								Address:       ep.IP,
								PortSpecifier: &core.SocketAddress_PortValue{PortValue: uint32(ep.Port)},
							},
						},
					},
				},
			},
			LoadBalancingWeight: &wrappers.UInt32Value{
				Value: ep.Weight,
			},
		}
		lbEndpoints = append(lbEndpoints, &lbEndpoint)
	}
	return &endpoint.ClusterLoadAssignment{
		ClusterName: clusterName,
		Endpoints: []*endpoint.LocalityLbEndpoints{
			&endpoint.LocalityLbEndpoints{
				LbEndpoints: lbEndpoints,
			},
		},
	}
}

func MakeCluster(clusterName string) *cluster.Cluster {
	var to duration.Duration = duration.Duration{Seconds: 1}
	return &cluster.Cluster{
		Name:           clusterName,
		ConnectTimeout: &to,
		ClusterDiscoveryType: &cluster.Cluster_Type{
			Type: cluster.Cluster_EDS,
		},
		LbPolicy: cluster.Cluster_ROUND_ROBIN,
		EdsClusterConfig: &cluster.Cluster_EdsClusterConfig{
			ServiceName: clusterName,
		},
	}
}

func MakeClusterDNS(clusterName string, dns string, port int) *cluster.Cluster {
	var to duration.Duration = duration.Duration{Seconds: 1}
	return &cluster.Cluster{
		Name:           clusterName,
		ConnectTimeout: &to,
		ClusterDiscoveryType: &cluster.Cluster_Type{
			Type: cluster.Cluster_STRICT_DNS,
		},
		LoadAssignment: MakeEndpoint(clusterName, []ServiceEndpoint{{IP: dns, Port: port, Weight: 1}}),
	}
}

type RouteInfo struct {
	Domain      string
	ClusterName string
}

func MakeRoute(routeName string, routes []RouteInfo) *route.RouteConfiguration {
	vHosts := make([]*route.VirtualHost, 0)
	for index, inpRoute := range routes {
		vroute := route.VirtualHost{
			Name:    fmt.Sprintf("route-%v", index),
			Domains: []string{inpRoute.Domain},
			Routes: []*route.Route{
				&route.Route{
					Name:  "default",
					Match: &route.RouteMatch{PathSpecifier: &route.RouteMatch_Prefix{Prefix: "/"}},
					Action: &route.Route_Route{
						Route: &route.RouteAction{
							ClusterSpecifier: &route.RouteAction_Cluster{Cluster: inpRoute.ClusterName},
						},
					},
				},
			},
		}
		vHosts = append(vHosts, &vroute)
	}
	return &route.RouteConfiguration{
		Name:         routeName,
		VirtualHosts: vHosts,
	}
}

func MakeListener(listenerName string, ip string, port uint16, direction string, filter *listener.Filter) (*listener.Listener, error) {
	return &listener.Listener{
		Name: listenerName,
		Address: &core.Address{Address: &core.Address_SocketAddress{SocketAddress: &core.SocketAddress{
			Address:       ip,
			PortSpecifier: &core.SocketAddress_PortValue{PortValue: uint32(port)}}},
		},
		FilterChains: []*listener.FilterChain{
			&listener.FilterChain{
				Filters: []*listener.Filter{filter},
			},
		},
		TrafficDirection: core.TrafficDirection(core.TrafficDirection_value[strings.ToUpper(direction)]),
	}, nil
}

func MakeListenerFilterChains(listenerName string, ip string, port uint16, direction string, filterChains []*listener.FilterChain) *listener.Listener {
	l, _ := MakeListener(listenerName, ip, port, direction, nil)
	l.FilterChains = filterChains
	return l
}

func MakeTcpFilter(listenerName string, clusterName string) (*listener.Filter, error) {
	filterTCPListenerS := &tcm.TcpProxy{
		StatPrefix: listenerName,
		ClusterSpecifier: &tcm.TcpProxy_Cluster{
			Cluster: clusterName,
		},
	}
	filterTCPListener, err := ptypes.MarshalAny(filterTCPListenerS)
	if err != nil {
		return nil, err
	}
	return &listener.Filter{
		Name: xdsutil.TCPProxy,
		ConfigType: &listener.Filter_TypedConfig{
			TypedConfig: filterTCPListener,
		},
	}, nil
}

func MakeTcpListener(listenerName string, ip string, port uint16, direction string, clusterName string) (*listener.Listener, error) {
	filter, err := MakeTcpFilter(listenerName, clusterName)
	if err != nil {
		return nil, err
	}
	return MakeListener(listenerName, ip, port, direction, filter)
}

func MakeSniListener(listenerName string, ip string, port uint16, direction string) (*listener.Listener, error) {
	filter, err := MakeSniFilter(listenerName)
	if err != nil {
		return nil, err
	}
	return MakeListener(listenerName, ip, port, direction, filter)
}

func MakeFilterChain(prefix string, prefixLen uint32, port uint32, serverName, filterChainName string, filter *listener.Filter) *listener.FilterChain {
	fc := &listener.FilterChain{
		Name:    filterChainName,
		Filters: []*listener.Filter{filter},
		FilterChainMatch: &listener.FilterChainMatch{
			DestinationPort: &wrappers.UInt32Value{Value: port},
			PrefixRanges:    []*core.CidrRange{{AddressPrefix: prefix, PrefixLen: &wrappers.UInt32Value{Value: prefixLen}}},
		},
	}
	if serverName != "" {
		fc.FilterChainMatch.ServerNames = []string{serverName}
	}
	return fc
}

func MakeHttpFilter(listenerName string, routeName string, route *route.RouteConfiguration) (*listener.Filter, error) {
	filterHTTPConnS := &hcm.HttpConnectionManager{
		StatPrefix:  listenerName,
		HttpFilters: []*hcm.HttpFilter{{Name: xdsutil.Router}},
	}
	if route != nil {
		filterHTTPConnS.RouteSpecifier = &hcm.HttpConnectionManager_RouteConfig{
			RouteConfig: route}
	} else if routeName != "" {
		filterHTTPConnS.RouteSpecifier = &hcm.HttpConnectionManager_Rds{
			Rds: &hcm.Rds{RouteConfigName: routeName}}
	}
	filterHTTPConn, err := ptypes.MarshalAny(filterHTTPConnS)
	if err != nil {
		return nil, err
	}
	filter := listener.Filter{
		Name: xdsutil.HTTPConnectionManager,
		ConfigType: &listener.Filter_TypedConfig{
			TypedConfig: filterHTTPConn,
		},
	}
	return &filter, nil
}

func MakeSniFilter(listenerName string) (*listener.Filter, error) {
	filter := listener.Filter{
		Name: "envoy.filters.network.sni_cluster",
	}
	return &filter, nil
}

func MakeHttpListener(listenerName string, ip string, port uint16, direction string, routeName string) (*listener.Listener, error) {
	filter, err := MakeHttpFilter(listenerName, routeName, nil)
	if err != nil {
		return nil, err
	}
	return MakeListener(listenerName, ip, port, direction, filter)
}

func MakeTLSContext(certFile, keyFile, rootFile string, inline bool) *auth.CommonTlsContext {
	tlsContext := &auth.CommonTlsContext{}
	if inline == false {
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
	} else {
		if certFile != "" {
			certData, _ := ioutil.ReadFile(certFile)
			keyData, _ := ioutil.ReadFile(keyFile)
			tlsContext.TlsCertificates = []*auth.TlsCertificate{{
				CertificateChain: &core.DataSource{Specifier: &core.DataSource_InlineString{InlineString: string(certData)}},
				PrivateKey:       &core.DataSource{Specifier: &core.DataSource_InlineString{InlineString: string(keyData)}},
			}}
		}
		if rootFile != "" {
			rootCertData, _ := ioutil.ReadFile(rootFile)
			tlsContext.ValidationContextType = &auth.CommonTlsContext_ValidationContext{
				ValidationContext: &auth.CertificateValidationContext{
					TrustedCa: &core.DataSource{Specifier: &core.DataSource_InlineString{InlineString: string(rootCertData)}},
				},
			}
		}
	}
	return tlsContext
}

func CreateSDSTlsStreamSDS() *auth.CommonTlsContext {
	return &auth.CommonTlsContext{
		TlsCertificateSdsSecretConfigs: []*auth.SdsSecretConfig{
			{
				Name: "default",
				SdsConfig: &core.ConfigSource{
					InitialFetchTimeout: ptypes.DurationProto(time.Second * 0),
					ResourceApiVersion:  core.ApiVersion_V3,
					ConfigSourceSpecifier: &core.ConfigSource_ApiConfigSource{
						ApiConfigSource: &core.ApiConfigSource{
							ApiType:                   core.ApiConfigSource_GRPC,
							SetNodeOnFirstMessageOnly: true,
							TransportApiVersion:       core.ApiVersion_V3,
							GrpcServices: []*core.GrpcService{
								{
									TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
										EnvoyGrpc: &core.GrpcService_EnvoyGrpc{ClusterName: SDSClusterName},
									},
								},
							},
						},
					},
				},
			},
		},
		ValidationContextType: &auth.CommonTlsContext_CombinedValidationContext{
			CombinedValidationContext: &auth.CommonTlsContext_CombinedCertificateValidationContext{
				DefaultValidationContext: &auth.CertificateValidationContext{},
				ValidationContextSdsSecretConfig: &auth.SdsSecretConfig{
					Name: "ROOTCA",
					SdsConfig: &core.ConfigSource{
						InitialFetchTimeout: ptypes.DurationProto(time.Second * 0),
						ResourceApiVersion:  core.ApiVersion_V3,
						ConfigSourceSpecifier: &core.ConfigSource_ApiConfigSource{
							ApiConfigSource: &core.ApiConfigSource{
								ApiType:                   core.ApiConfigSource_GRPC,
								SetNodeOnFirstMessageOnly: true,
								TransportApiVersion:       core.ApiVersion_V3,
								GrpcServices: []*core.GrpcService{
									{
										TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
											EnvoyGrpc: &core.GrpcService_EnvoyGrpc{ClusterName: SDSClusterName},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		AlpnProtocols: []string{"h2", "http/1.1"},
	}

}

func MakeHttpsListener(listenerName string, ip string, port uint16, direction string, routeName string, certFile, keyFile, rootFile string, clientAuth, useTransportSocket, inline, sds bool) (*listener.Listener, error) {
	lds, err := MakeHttpListener(listenerName, ip, port, direction, routeName)
	if err != nil {
		return nil, err
	}
	commonTlsContext := MakeTLSContext(certFile, keyFile, rootFile, inline)
	downStreamTlsContextM := &auth.DownstreamTlsContext{CommonTlsContext: commonTlsContext, RequireClientCertificate: &wrappers.BoolValue{Value: clientAuth}}
	downStreamTlsContext, _ := ptypes.MarshalAny(downStreamTlsContextM)
	if useTransportSocket == true {
		if sds == true {
			sdsTlsContextM := &auth.DownstreamTlsContext{
				CommonTlsContext:         CreateSDSTlsStreamSDS(),
				RequireClientCertificate: proto.BoolTrue,
			}
			sdsTlsContext, _ := ptypes.MarshalAny(sdsTlsContextM)
			lds.FilterChains[0].TransportSocket = &core.TransportSocket{Name: EnvoyTLSSocketName, ConfigType: &core.TransportSocket_TypedConfig{TypedConfig: sdsTlsContext}}
		} else {
			lds.FilterChains[0].TransportSocket = &core.TransportSocket{Name: EnvoyTLSSocketName, ConfigType: &core.TransportSocket_TypedConfig{TypedConfig: downStreamTlsContext}}
		}
	}
	return lds, nil
}

func MakeTcpSslListener(listenerName string, ip string, port uint16, direction string, clusterName string, certFile, keyFile, rootFile string, clientAuth bool) (*listener.Listener, error) {
	lds, err := MakeTcpListener(listenerName, ip, port, direction, clusterName)
	if err != nil {
		return nil, err
	}
	commonTLSContext := MakeTLSContext(certFile, keyFile, rootFile, false)
	tlsc := &auth.DownstreamTlsContext{CommonTlsContext: commonTLSContext, RequireClientCertificate: &wrappers.BoolValue{Value: clientAuth}}
	mt, _ := ptypes.MarshalAny(tlsc)
	lds.FilterChains[0].TransportSocket = &core.TransportSocket{
		Name: EnvoyTLSSocketName,
		ConfigType: &core.TransportSocket_TypedConfig{
			TypedConfig: mt,
		},
	}
	return lds, nil
}

type SniInfo struct {
	ServerName  string
	CertFile    string
	KeyFile     string
	RootFile    string
	RouteName   string
	ClusterName string
}

func MakeHttpsSniListener(listenerName string, ip string, port uint16, sniInfos []SniInfo, transportSocket, inline bool) (*listener.Listener, error) {
	filterChains := make([]*listener.FilterChain, 0)
	for _, sniInfo := range sniInfos {
		filter, err := MakeHttpFilter(listenerName, sniInfo.RouteName, nil)
		if err != nil {
			return nil, err
		}
		tlsContextM := &auth.DownstreamTlsContext{CommonTlsContext: MakeTLSContext(sniInfo.CertFile, sniInfo.KeyFile, sniInfo.RootFile, inline)}
		tlsContext, _ := ptypes.MarshalAny(tlsContextM)

		var filterChain listener.FilterChain
		if transportSocket == false {
			filterChain = listener.FilterChain{
				Filters:          []*listener.Filter{filter},
				FilterChainMatch: &listener.FilterChainMatch{ServerNames: []string{sniInfo.ServerName}},
			}
		} else {
			filterChain = listener.FilterChain{
				Filters:          []*listener.Filter{filter},
				TransportSocket:  &core.TransportSocket{Name: EnvoyTLSSocketName, ConfigType: &core.TransportSocket_TypedConfig{TypedConfig: tlsContext}},
				FilterChainMatch: &listener.FilterChainMatch{ServerNames: []string{sniInfo.ServerName}},
			}
		}
		filterChains = append(filterChains, &filterChain)
	}
	return &listener.Listener{
		Name: listenerName,
		Address: &core.Address{Address: &core.Address_SocketAddress{SocketAddress: &core.SocketAddress{
			Address:       ip,
			PortSpecifier: &core.SocketAddress_PortValue{PortValue: uint32(port)}}}},
		FilterChains: filterChains,
	}, nil
}

func MakeTcpSniListener(listenerName string, ip string, port uint16, sniInfos []SniInfo) (*listener.Listener, error) {
	filterChains := make([]*listener.FilterChain, 0)
	for _, sniInfo := range sniInfos {
		filter, err := MakeTcpFilter(listenerName, sniInfo.ClusterName)
		if err != nil {
			return nil, err
		}
		filterChain := listener.FilterChain{
			Filters:          []*listener.Filter{filter},
			FilterChainMatch: &listener.FilterChainMatch{ServerNames: []string{sniInfo.ServerName}},
		}
		filterChains = append(filterChains, &filterChain)
	}
	return &listener.Listener{
		Name: listenerName,
		Address: &core.Address{Address: &core.Address_SocketAddress{SocketAddress: &core.SocketAddress{
			Address:       ip,
			PortSpecifier: &core.SocketAddress_PortValue{PortValue: uint32(port)}}}},
		FilterChains: filterChains,
	}, nil
}
