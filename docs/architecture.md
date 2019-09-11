# Table of Contents
1. [Deployment architecture](#deployment-architecture)
2. [Deploy Citrix ADC as an Ingress Gateway](#deploy-citrix-adc-as-an-ingress-gateway)
3. [Deploy Citrix ADC CPXs as sidecars](#deploy-citrix-adc-cpxs-as-sidecars)

# <a name="deployment-architecture">Deployment architecture</a>

The Istio service mesh can be logically divided into control plane and data plane components. The data plane is composed of a set of proxies which manage the network traffic between instances of the service mesh. The control plane generates and deploys the configuration that controls the data plane's behavior.
For detailed information on Istio architecture and different components, see [Istio docs](https://istio.io/docs/concepts/what-is-istio/#architecture).

## Integration with Istio Control Plane Components

The Istio control plane is a set of gRPC based services and it pushes configuration changes to clients listening at the data plane. Pilot, Mixer, Galley and Citadel are important control plane components. Out of these, data plane proxy primarily needs to interact with Pilot, Mixer and Citadel.
 
**Pilot** is a gRRPC based xDS server and provides configuration data to proxies. Citrix provides an xDS client called `istio-adaptor` to communicate with this Istio control plane component for installing Citrix ADCs in Istio service mesh. `istio-adaptor` acts as a gRPC client to the control plane API server and listens to updates. Based on the updates from the control plane, `istio-adaptor` generates the equivalent Citrix ADC configuration. Then, it configures the Citrix ADC ingress or proxy device accordingly.

**Citadel** is a control plane service which provides key and certificate management. It is responsible for providing TLS certificates to data plane proxies. `istio-adaptor` monitors secrets managed by Citadel, and updates the Citrix ADC proxy with relevant details.

**Mixer** primarily performs two tasks:

i) Collecting telemetry data from services 

ii) Policy checks and access control across the mesh

Citrix service mesh solution does not interact with the Mixer component. It provides its own [Citrix ADC Metrics Exporter](https://github.com/citrix/citrix-adc-metrics-exporter) which collects the statistical data from Citrix ADC Ingress Gateway device and exports to the [Prometheus](https://prometheus.io). Citrix is working on a solution to perform telemetry collection from Citrix CPX sidecar proxies, and it will be available in future releases. 

As of now, Citrix service mesh solution lacks the support of policy check. It will also be part of future releases.


Citrix ADC can be integrated with Istio in two ways:

-  Citrix ADC CPX, MPX, or VPX as an Ingress Gateway to the service mesh
-  Citrix ADC CPX as a sidecar proxy with application containers in the service mesh
Both modes can be combined to have a unified data plane solution.


  
## <a name="deploy-citrix-adc-as-an-ingress-gateway">Deploy Citrix ADC as an Ingress Gateway</a>

An Istio Ingress Gateway acts as an entry point for the incoming traffic to the service mesh. It secures and controls access to the service mesh from outside. You can deploy a Citrix ADC CPX, MPX, or VPX as an ingress Gateway to the Istio service mesh.

### Citrix ADC CPX as an Ingress Gateway

The Citrix ADC CPX Ingress Gateway is deployed as a set of horizontal scaling Kubernetes pods. Each pod runs a Citrix ADC CPX that controls and routes the incoming requests.
Each pod also runs an `istio-adaptor` container as a sidecar to the Citrix ADC. The Istio-adaptor container establishes a connection with Istio control plane components, reads the ingress policies applied, and configures the Citrix ADC CPX accordingly.

The following diagram shows a sample deployment of Citrix ADC CPX as an Ingress Gateway.

![CPX-ingress](media/CPX-ingress.jpeg)

For detailed instructions on how to deploy Citrix ADC CPX as an Ingress Gateway, see [Deploying Citrix ADC with Istio](../deployment/README.md).

### Citrix ADC MPX or VPX as an Ingress Gateway

Citrix ADC VPX or MPX can be deployed as an Ingress Gateway to the Istio service mesh. In this deployment, a Kubernetes pod is deployed with an `istio-adaptor` container. The `istio-adaptor` container connects to the Istio control pane and reads the ingress configuration and then configures the Citrix ADC VPX or MPX accordingly. For this deployment, <b>you should establish the connectivity between the concerned Citrix ADC and the cluster nodes</b>.

The following diagram shows a sample deployment of Citrix ADC VPX/MPX as an ingress Gateway.

![vpx-ingress](media/vpx-ingress.jpeg)

For detailed instructions on how to deploy Citrix ADC VPX or MPX as an Ingress Gateway, see [Deploying Citrix ADC with Istio](../deployment/README.md).

## <a name="deploy-citrix-adc-cpxs-as-sidecars">Deploy Citrix ADC CPXs as sidecars</a>

Citrix ADC CPX can be deployed as a sidecar proxy in application pods. It intercepts all the incoming and outgoing traffic from the application pod and applies the configured routing policies or rules.

In this deployment, each application pod contains a Citrix ADC CPX and an `istio-adaptor` container along with the application container.
The `istio-adaptor` container listens to updates from the Istio control plane and configures the Citrix ADC CPX instance accordingly.

The following diagram shows a sample deployment of Citrix ADC CPXs as sidecars.

![cpx-proxy](media/cpx-proxy.jpeg)

For detailed instructions on how to deploy Citrix ADC CPX as a sidecar, see [Deploying Citrix ADC with Istio](../deployment/README.md).
