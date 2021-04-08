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
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	clusterserver "github.com/envoyproxy/go-control-plane/envoy/service/cluster/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	epserver "github.com/envoyproxy/go-control-plane/envoy/service/endpoint/v3"
	listenerserver "github.com/envoyproxy/go-control-plane/envoy/service/listener/v3"
	routeserver "github.com/envoyproxy/go-control-plane/envoy/service/route/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	xds "github.com/envoyproxy/go-control-plane/pkg/server/v3"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

type logger struct{}

func (logger logger) Debugf(format string, args ...interface{}) {
	log.Printf(format, args...)
}

func (logger logger) Warnf(format string, args ...interface{}) {
	log.Printf(format, args...)
}

func (logger logger) Infof(format string, args ...interface{}) {
	log.Debugf(format, args...)
}
func (logger logger) Errorf(format string, args ...interface{}) {
	log.Errorf(format, args...)
}

type GrpcADSServer struct {
	//Port: If zero value is passed, then available port will be used, and same will be populated in this field
	Port       int
	snapshot   cache.SnapshotCache
	grpcServer *grpc.Server
}

type NodeConfig struct {
	node *core.Node
}

func (n NodeConfig) ID(node *core.Node) string {
	return node.GetId()
}

// NewGrpcADSServer starts gRPC server on passed port on localhost IP.
// If port is zero, then available port will be selected to start the server
func NewGrpcADSServer(port int) (*GrpcADSServer, error) {
	grpcAdsServer := new(GrpcADSServer)
	grpcAdsServer.Port = port
	log.SetLevel(log.DebugLevel)
	grpcAdsServer.snapshot = cache.NewSnapshotCache(true, NodeConfig{}, logger{})
	server := xds.NewServer(context.Background(), grpcAdsServer.snapshot, nil)
	grpcAdsServer.grpcServer = grpc.NewServer()
	lis, err := net.Listen("tcp", ":"+fmt.Sprint(port))
	if err != nil {
		return nil, err
	}
	arr := strings.Split(lis.Addr().String(), ":")
	grpcAdsServer.Port, _ = strconv.Atoi(arr[len(arr)-1])
	log.Printf("Starting grpc server at port %d", grpcAdsServer.Port)
	discovery.RegisterAggregatedDiscoveryServiceServer(grpcAdsServer.grpcServer, server)
	epserver.RegisterEndpointDiscoveryServiceServer(grpcAdsServer.grpcServer, server)
	clusterserver.RegisterClusterDiscoveryServiceServer(grpcAdsServer.grpcServer, server)
	routeserver.RegisterRouteDiscoveryServiceServer(grpcAdsServer.grpcServer, server)
	listenerserver.RegisterListenerDiscoveryServiceServer(grpcAdsServer.grpcServer, server)
	go func() {
		if err := grpcAdsServer.grpcServer.Serve(lis); err != nil {
		}
	}()
	return grpcAdsServer, nil
}

func (grpcAdsServer *GrpcADSServer) StopGrpcADSServer() {
	grpcAdsServer.grpcServer.Stop()
}

func (grpcAdsServer *GrpcADSServer) UpdateSpanshotCache(version string, nodeID *core.Node, listener *listener.Listener,
	route *route.RouteConfiguration, cluster *cluster.Cluster, endpoint *endpoint.ClusterLoadAssignment) error {
	endpoints := []types.Resource{}
	clusters := []types.Resource{}
	routes := []types.Resource{}
	listeners := []types.Resource{}
	if endpoint != nil {
		endpoints = append(endpoints, endpoint)
	}
	if cluster != nil {
		clusters = append(clusters, cluster)
	}
	if route != nil {
		routes = append(routes, route)
	}
	if listener != nil {
		listeners = append(listeners, listener)
	}
	s := cache.NewSnapshot(version, endpoints, clusters, routes, listeners, nil, nil)
	return grpcAdsServer.snapshot.SetSnapshot(nodeID.GetId(), s)
}

func (grpcAdsServer *GrpcADSServer) UpdateSpanshotCacheMulti(version string, nodeID *core.Node, listener []*listener.Listener,
	route []*route.RouteConfiguration, cluster []*cluster.Cluster, endpoint []*endpoint.ClusterLoadAssignment) error {
	endpoints := []types.Resource{}
	clusters := []types.Resource{}
	routes := []types.Resource{}
	listeners := []types.Resource{}
	for _, endp := range endpoint {
		endpoints = append(endpoints, endp)
	}
	for _, clt := range cluster {
		clusters = append(clusters, clt)
	}
	for _, rt := range route {
		routes = append(routes, rt)
	}
	for _, lt := range listener {
		listeners = append(listeners, lt)
	}
	s := cache.NewSnapshot(version, endpoints, clusters, routes, listeners, nil, nil)
	return grpcAdsServer.snapshot.SetSnapshot(nodeID.GetId(), s)
}
