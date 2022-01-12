# Citrix ADC xDS-adaptor: A way to intgrate Citrix ADC with Istio Service Mesh

A service mesh is an infrastructure layer that handles communication between microservices and provides capabilities like service discovery, load balancing, security, and monitoring. [Istio](https://istio.io) is an open source and platform-independent service mesh that connects, monitors, and secures microservices.

Citrix ADC has advanced traffic management capabilities for enhancing application performance and provides comprehensive security. Citrix ADC integrations with Istio allow you to secure and optimize traffic for applications in the service mesh using Citrix ADC features.

The Citrix ADC xDS-adaptor is a container for integrating Citrix ADC with service mesh control plane implementations based on xDS APIs (Istio, Consul, and so on). It communicates with the service mesh control plane and listens for updates by acting as a gRPC client to the control plane API server. Based on the updates from the control plane, the Citrix ADC xDS-Adaptor generates the equivalent Citrix ADC configuration.

Citrix ADC can be integrated with Istio in the following ways:

- Citrix ADC CPX, MPX, or VPX as an Ingress Gateway to the service mesh.
- Citrix ADC CPX as a sidecar proxy with application containers in the service mesh.
- Citrix ADC CPX as an Egress Gateway for the service mesh.
- Citrix ADC VPX as an Egress Gateway

## Citrix ADC as an Ingress Gateway for Istio

An Istio ingress gateway acts as an entry point for the incoming traffic and secures and controls access to the service mesh from outside. It also performs routing and load balancing. Citrix ADC CPX, MPX, or VPX can be deployed as an ingress gateway to the Istio service mesh. For detailed instructions on how to deploy Citrix ADC as an Ingress Gateway for Istio, see [Helm charts for Citrix ADC integration with Istio](https://github.com/citrix/citrix-xds-adaptor/blob/master/docs/istio-integration/deploy-istio-adaptor-helm-chart.md).

## Citrix ADC CPX as a sidecar proxy for Istio

In an Istio service mesh, a sidecar proxy runs alongside application pods and it intercepts and manage incoming and outgoing traffic for applications. Citrix ADC CPX can be deployed as the sidecar proxy in the application pods. A sidecar proxy applies the configured routing policies or rules to the ingress and egress traffic from the pod. For detailed instructions on how to deploy Citrix ADC CPX as a sidecar proxy for Istio, see [Helm charts for Citrix ADC integration with Istio](https://github.com/citrix/citrix-xds-adaptor/blob/master/docs/istio-integration/deploy-istio-adaptor-helm-chart.md).

## Citrix ADC as an Egress Gateway for Istio

An Egress Gateway defines the traffic exit point from a service mesh. The Citrix ADC as an Egress Gateway performs load balancing, monitoring at the edge of the service mesh. It also provides routing rules to exit the Istio service mesh. For detailed instructions on how to deploy Citrix ADC as an Egress Gateway for Istio, see [Helm charts for Citrix ADC integration with Istio](https://github.com/citrix/citrix-xds-adaptor/blob/master/docs/istio-integration/deploy-istio-adaptor-helm-chart.md).

## Citrix ADC VPX as an Egress Gateway

An Egress Gateway defines the traffic exit point from a service mesh. Citrix ADC VPX can be deployed as an Egress Gateway to the Istio service mesh. In this deployment, a Kubernetes pod is deployed with a Citrix ADC xDS-adaptor container. The Citrix ADC xDS-adaptor container connects to the Istio control plane and reads the egress configuration and then configures the Citrix ADC VPX accordingly.
For detailed instructions on how to deploy Citrix ADC VPX as an Egress Gateway for Istio, see [Helm charts for Citrix ADC integration with Istio](https://github.com/citrix/citrix-xds-adaptor/blob/master/docs/istio-integration/deploy-istio-adaptor-helm-chart.md).

For information on Citrix ADC xDS-adaptor deployment architecture, see [Deployment architecture](https://developer-docs.citrix.com/projects/citrix-istio-adaptor/en/latest/istio-integration/architecture/).
