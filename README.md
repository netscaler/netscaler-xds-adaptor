![Citrix Logo](docs/media/Citrix_icon.png)

# Citrix ADC integration with Istio

[![Docker Repository on Quay](https://quay.io/repository/citrix/citrix-istio-adaptor/status "Docker Repository on Quay")](https://quay.io/repository/citrix/citrix-istio-adaptor)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./license/LICENSE)
[![GitHub issues](https://img.shields.io/github/issues/citrix/citrix-istio-adaptor.svg)](https://github.com/citrix/citrix-istio-adaptor/issues)
[![GitHub stars](https://img.shields.io/github/stars/citrix/citrix-istio-adaptor.svg)](https://github.com/citrix/citrix-istio-adaptor/stargazers)
[![HitCount](http://hits.dwyl.io/citrix/citrix-istio-adaptor.svg)](http://hits.dwyl.io/citrix/citrix-istio-adaptor)

---

## Description

This repository contains various integrations of [Citrix ADC](https://www.citrix.com/products/citrix-adc/platforms.html) with [Istio 1.3.0](https://istio.io/).

# Table of Contents

1. [Introduction](#introduction)
2. [Citrix ADC as an Ingress Gateway for Istio](#citrix-adc-as-an-ingress-gateway)
3. [Citrix ADC as a Sidecar Proxy for Istio](#citrix-adc-as-a-sidecar)
4. [Architecture](#architecture)
4. [Deployment Options](#deployment-options)
5. [Features](#features)
6. [Example: Deploying Bookinfo with Citrix ADC](#example)
7. [Blogs](#blogs)
8. [Release Notes](#release-notes)
9. [Contributions](#contributions)
10. [Questions](#questions)
11. [Issues](#issues)
12. [Code of Conduct](#code-of-conduct)
13. [Licensing](#licensing)

## <a name="introduction">Introduction</a>

A service mesh is an infrastructure layer that handles communication between microservices and provides capabilities like service discovery, load balancing, security, and monitoring. [Istio](https://istio.io/docs/concepts/what-is-istio/) is an open source and platform-independent service mesh that connects, monitors, and secures microservices. [Citrix ADC](https://www.citrix.com/products/citrix-adc/platforms.html) has advanced traffic management capabilities for enhancing application performance and provides comprehensive security. Citrix ADC integrations with Istio allow you to secure and optimize traffic for applications in the service mesh using Citrix ADC features.

Citrix ADC can be integrated with Istio in two ways:

-  Citrix ADC CPX, MPX, or VPX as an [Istio Ingress Gateway](https://istio.io/docs/tasks/traffic-management/ingress/ingress-control/) to the service mesh.
-  Citrix ADC CPX as a [sidecar proxy](https://istio.io/docs/concepts/what-is-istio/#architecture) with application containers in the service mesh.
Both modes can be combined to have a unified data plane solution.

## <a name="citrix-adc-as-an-ingress-gateway">Citrix ADC as an Ingress Gateway for Istio</a>

An Istio ingress gateway acts as an entry point for the incoming traffic and secures and controls access to the service mesh from outside. It also performs routing and load balancing. Citrix ADC CPX, MPX, or VPX can be deployed as an ingress gateway to the Istio service mesh.

## <a name="citrix-adc-as-a-sidecar">Citrix ADC as a Sidecar Proxy for Istio</a>

In Istio service mesh, a sidecar proxy runs alongside application pods and it intercepts and manages incoming and outgoing traffic for applications. Citrix ADC CPX can be deployed as the sidecar proxy in application pods. A sidecar proxy applies the configured routing policies or rules to the ingress and egress traffic from the pod. This [Citrix ADC CPX](https://www.citrix.com/blogs/2020/02/25/citrix-adc-cpx-for-service-mesh-memory-footprint-and-microservices/) is designed to consume less resources.


## <a name="architecture">Architecture</a>

For detailed information on the integration of Citrix ADC with Istio Servicemesh, see [Architecture](docs/architecture.md). The primary component that enables the integration is `istio-adaptor`. `istio-adaptor` translates [xDS API](https://www.envoyproxy.io/docs/envoy/latest/api-docs/xds_protocol) calls from the Istio control plane into [NITRO API](https://developer-docs.citrix.com/projects/citrix-adc-nitro-api-reference/en/latest/) calls to the Citrix ADC.

## <a name="deployment-options">Deployment Options</a>

In Istio service mesh, Citrix ADC can act as an Ingress and/or sidecar proxy in the data plane. Citrix ADC can act as an Ingress Gateway for services deployed with or without sidecar (sidecar can be Citrix CPX or Envoy). Below table gives a glimpse about working combinations of Citrix ADC and Envoy proxy.

| Ingress Gateway | Sidecar Proxy | Supported |
|-----------------|---------------|-----------|
| Citrix ADC | Citrix ADC CPX | Yes|
| Citrix ADC | Envoyproxy | Yes |
| Envoyproxy | Citrix ADC CPX | Yes |

To deploy Citrix ADC with Istio using Helm charts, see the following links:

- [Deploy Citrix ADC as an Ingress Gateway using Helm charts](https://github.com/citrix/citrix-helm-charts/blob/master/citrix-adc-istio-ingress-gateway/README.md)
- [Deploy Citrix ADC CPX as a sidecar using Helm charts](https://github.com/citrix/citrix-helm-charts/blob/master/citrix-cpx-istio-sidecar-injector/README.md)

## <a name="features">Features</a>

Features supported on Citrix ADC in Istio Servicemesh can be broadly categorized in below sections.
1. Traffic Management
2. Security
3. Observability

### Traffic Management

Citrix ADC supports following traffic management features in Istio.

-  Service discovery
-  Load balancing
-  Secure Ingress
-  Weighted clusters
-  HTTP rewrite
-  HTTP redirect
-  HTTP fault injection

### Security

SSL/TLS Certificates required for applications are maintained and managed by Citadel in Istio control plane.
Few important features supported on Citrix ADC are:

#### Authentication policy

-  End user authentication or origin authentication using JWT authentication
-  Transport authentication or service-to-service authentication using mutual TLS

#### Monitoring of Istio certificates and keys

Istio-adaptor monitors the folder where Istio deploys certificates and keys for mutual TLS authentication between Citrix ADC proxies. After an update of certificate and key, Istio-adaptor loads the new certificate and key to Citrix ADC.

### Observability

When a service is deployed in the mesh, users are interested in getting insights about service behaviour. Citrix ADC proxy provides a rich set of in-built metrics. When Citrix ADC CPX is deployed as a sidecar, these metrics will represent telemetry data for an application. It helps in reducing the burden of an application developer to program lots of instrumentation code in the application, and instead she can focus on the core application logic. 

Citrix has built couple of auxiliary tools such as [Citrix ADC Metrics Exporter](https://github.com/citrix/citrix-adc-metrics-exporter) and [Citrix Observability Exporter](https://github.com/citrix/citrix-observability-exporter) which help in exporting metrics and/or transactional data to observability tools such as Prometheus, Zipkin, Kafta etc.

Statistical data of Citrix ADC Ingress device can be exported to the Prometheus using [Citrix ADC Metrics Exporter](https://github.com/citrix/citrix-adc-metrics-exporter). 

[Citrix Observability Exporter](https://github.com/citrix/citrix-observability-exporter) (COE) is a microservice designed to collect metrics from Citrix ADCs, and export to observability tools such as Zipkin, Kafka, Prometheus etc.
To know more about COE, kindly refer this [link](https://github.com/citrix/citrix-observability-exporter).


#### Telemetry in Ingress Gateway

[Prometheus](https://prometheus.io) is usually already installed as a part of Istio package. By default, Citrix ADC Metrics Exporter is also deployed along with Citrix ADC Ingress Gateway. Citrix ADC Metrics Exporter fetches statistical data from Citrix ADC and exports it to Prometheus running in Istio service mesh. When you add Prometheus as a data source in Grafana, you can visualize this statistical data in the Grafana dashboard. 


#### Telemetry and Distributed Tracing in Sidecar proxies

Citrix ADC CPX in conjunction with the Citrix Observability Exporter (COE) can export metrics to Prometheus deployed in Istio service mesh. This data can also be visualized in Grafana. 

Citrix ADC CPX sends transactional data to COE which eventually exports these trace spans to [Zipkin](https://zipkin.io). This distributed tracing enables users to track a service to service communication within a mesh. It helps in getting deeper understanding about request latency, serialization and parallelism via visualization.


The detailed list of fields supported on Citrix ADC as per the Istio CRDs (Destination Rule, Virtual Service, Policy, Gateway, Service Entry) can be found [here](docs/features.md).

## <a name="example">Example: Deploying Bookinfo with Citrix ADC</a>
Follow this [link](https://github.com/citrix/citrix-helm-charts/blob/master/examples/citrix-adc-in-istio/README.md) to deploy Bookinfo application with Citrix ADC acting as an Istio Ingress Gateway and Citrix ADC CPX as sidecar in application pods.

## <a name="blogs">Blogs</a>

1. [Citrix ADC as an Istio Ingress Gateway: Part 1 Deployment](https://www.citrix.com/blogs/2019/11/13/citrix-adc-as-an-istio-ingress-gateway-part-1-deployment/)
2. [Citrix ADC as an Istio Ingress Gateway: Part 2 Configuration](https://www.citrix.com/blogs/2019/11/14/citrix-adc-as-an-istio-ingress-gateway-part-2-configuration/)
3. [Citrix ADC in OpenShift Service Mesh](https://blog.openshift.com/citrix-adc-in-openshift-service-mesh/)
4. [Traffic Mirroring: Risk-free app upgrades in Istio with Citrix ADC](https://www.citrix.com/blogs/2020/04/29/traffic-mirroring-risk-free-app-upgrades-in-istio-with-citrix-adc/)
5. [End-user authentication in Istio Service Mesh with Citrix](https://www.citrix.com/blogs/2020/03/19/end-user-authentication-in-istio-service-mesh-with-citrix/)

## <a name="release-notes">Release Notes</a>

Click [here](docs/release-notes.md) for the release notes of the latest Citrix `istio-adaptor`.

## <a name="contributions">Contributions</a>

Contributions are always welcome! Please read the [Developer Guide](docs/developer_guide.md).

## <a name="questions">Questions</a>

For questions and support, the following channels are available:

-  [Citrix Discussion Forum](https://discussions.citrix.com/)
-  [Citrix ADC CPX Slack Channel](https://citrixadccloudnative.slack.com/)
  
To request an invitation to participate in the Slack channel, provide your email address using this form: [https://podio.com/webforms/22979270/1633242](https://podio.com/webforms/22979270/1633242)

## <a name="issues">Issues</a>

 Please report issues in detail. Use the following command to collect the logs:

    Get Logs: kubectl logs <podname> -c istio-adaptor -n <namespace> > log_file

## <a name="code-of-conduct">Code of Conduct</a>

This project adheres to the [Kubernetes Community Code of Conduct](https://github.com/kubernetes/community/blob/master/code-of-conduct.md). By participating in this project, you agree to abide by its terms.

## <a name="licensing">Licensing</a>

`citrix-istio-adaptor` is licensed with [Apache License 2.0](license/LICENSE)
