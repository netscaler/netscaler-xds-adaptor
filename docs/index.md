# Citrix ADC integration with Istio

A service mesh is an infrastructure layer that handles communication between microservices and provides capabilities like service discovery, load balancing, security, and monitoring. [Istio](https://istio.io) is an open source and platform-independent service mesh that connects, monitors, and secures microservices. Citrix ADC has advanced traffic management capabilities for enhancing application performance and provides comprehensive security. Citrix ADC integrations with Istio allow you to secure and optimize traffic for applications in the service mesh using Citrix ADC features.

Citrix ADC can be integrated with Istio in three ways:

- Citrix ADC CPX, MPX, or VPX as an Ingress Gateway to the service mesh.
- Citrix ADC CPX as a sidecar proxy with application containers in the service mesh.
- Citrix ADC CPX as an Egress Gateway for the service mesh.

## Citrix ADC as an Ingress Gateway for Istio

An Istio ingress gateway acts as an entry point for the incoming traffic and secures and controls access to the service mesh from outside. It also performs routing and load balancing. Citrix ADC CPX, MPX, or VPX can be deployed as an ingress gateway to the Istio service mesh.

## Citrix ADC CPX as a sidecar proxy for Istio

In Istio service mesh, a sidecar proxy runs alongside application pods and it intercepts and manage incoming and outgoing traffic for applications. Citrix ADC CPX can be deployed as the sidecar proxy in the application pods. A sidecar proxy applies the configured routing policies or rules to the ingress and egress traffic from the pod.

## Citrix ADC CPX as an Egress Gateway for Istio

An Egress Gateway defines the traffic exit point from a service mesh. The Citrix ADC CPX as an Egress Gateway performs load balancing, monitoring at the edge of the service mesh, and provides routing rules to exit the Istio service mesh.
