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
	api "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	xdsapi "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v2"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/cache/v2"
	xds "github.com/envoyproxy/go-control-plane/pkg/server/v2"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"net"
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
	port       int
	snapshot   cache.SnapshotCache
	grpcServer *grpc.Server
}

type NodeConfig struct {
	node *core.Node
}

func (n NodeConfig) ID(node *core.Node) string {
	return node.GetId()
}

func NewGrpcADSServer(port int) (*GrpcADSServer, error) {
	grpcAdsServer := new(GrpcADSServer)
	grpcAdsServer.port = port
	log.SetLevel(log.DebugLevel)
	log.Printf("Starting grpc server at port %d", port)
	grpcAdsServer.snapshot = cache.NewSnapshotCache(true, NodeConfig{}, logger{})
	server := xds.NewServer(context.Background(), grpcAdsServer.snapshot, nil)
	grpcAdsServer.grpcServer = grpc.NewServer()
	lis, err := net.Listen("tcp", ":"+fmt.Sprint(port))
	if err != nil {
		return nil, err
	}

	discovery.RegisterAggregatedDiscoveryServiceServer(grpcAdsServer.grpcServer, server)
	api.RegisterEndpointDiscoveryServiceServer(grpcAdsServer.grpcServer, server)
	api.RegisterClusterDiscoveryServiceServer(grpcAdsServer.grpcServer, server)
	api.RegisterRouteDiscoveryServiceServer(grpcAdsServer.grpcServer, server)
	api.RegisterListenerDiscoveryServiceServer(grpcAdsServer.grpcServer, server)
	go func() {
		if err := grpcAdsServer.grpcServer.Serve(lis); err != nil {
		}
	}()
	return grpcAdsServer, nil
}

func (grpcAdsServer *GrpcADSServer) StopGrpcADSServer() {
	grpcAdsServer.grpcServer.Stop()
}

func (grpcAdsServer *GrpcADSServer) UpdateSpanshotCache(version string, nodeID *core.Node, listener *xdsapi.Listener,
	route *xdsapi.RouteConfiguration, cluster *xdsapi.Cluster, endpoint *xdsapi.ClusterLoadAssignment) error {
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
	s := cache.NewSnapshot(version, endpoints, clusters, routes, listeners, nil)
	return grpcAdsServer.snapshot.SetSnapshot(nodeID.GetId(), s)
}

func (grpcAdsServer *GrpcADSServer) UpdateSpanshotCacheMulti(version string, nodeID *core.Node, listener []*xdsapi.Listener,
	route []*xdsapi.RouteConfiguration, cluster []*xdsapi.Cluster, endpoint []*xdsapi.ClusterLoadAssignment) error {
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
	s := cache.NewSnapshot(version, endpoints, clusters, routes, listeners, nil)
	return grpcAdsServer.snapshot.SetSnapshot(nodeID.GetId(), s)
}
