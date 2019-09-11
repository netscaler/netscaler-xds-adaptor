# Citrix ADC as Ingress Gateway and Sidecar Proxy for Bookinfo Application

Bookinfo application is the Helloworld of Istio environment. This application displays information about a book such as brief description, book details and couple of reviews. Details of the bookinfo app can be found on [Istio examples](https://istio.io/docs/examples/bookinfo/).

# Table of Contents
1. [Deploying Citrix ADC as Ingress Gateway](#citrix-ingress-gateway)
2. [Deploying Citrix ADC Sidecar Injector](#citrix-sidecar-injector)
3. [Deploying Bookinfo](#deploying-bookinfo)
4. [Verification](#verification)
5. [Clean Up](#cleanup)


## <a name="citrix-ingress-gateway">A) Deploying Citrix ADC as Ingress Gateway</a>

Follow the link "Deploy Citrix ADC as an Ingress Gateway using Helm charts" in [deployment guide](../../README.md#deployment-options). Citrix ADC can either be CPX or VPX/MPX. The given bookinfo deployment should work fine in both cases. 

## <a name="citrix-sidecar-injector">B) Deploying Citrix ADC Sidecar Injector </a>

Follow the link "Deploy Citrix ADC CPX as a sidecar using Helm charts" in [deployment guide](../../README.md#deployment-options). Citrix ADC CPX will be injected as a sidecar on the labeled namespace. If you do not wish to inject sidecar, this step can be skipped. In that case, Citrix ADC will only act as an Ingress Gateway. 

## <a name="deploying-bookinfo">C) Deploying Bookinfo</a>

In this example, bookinfo application is deployed and exposed to the cluster-external world using Istio Gateway resource. This deployment can be done either manually by using yaml files or it can be deployed using Helm. Step-by-step guide to deploy all necessary resources related to bookinfo application is given below.

### C.1) Generate certificate and key for application

There are multiple tools available to generate certificates and keys. User is encouraged to use her favourite tool to generate the same in PEM format. 
Make sure names of key and certificate are *bookinfo_key.pem* and *bookinfo_cert.pem*. These will be used to generate a Kubernetes secret *citrix-ingressgateway-certs* which is used by the Citrix ADC acting as Ingress Gateway.

Steps to generate certificate and key using openssl utility are given below.

#### Generate Private Key 

```
openssl genrsa -out bookinfo_key.pem 2048
```

#### Generate Certificate Signing Request 

Make sure to **provide Common Name(CN/Server FQDN) as "www.bookinfo.com"** on CSR information prompt.

```
openssl req -new -key bookinfo_key.pem -out bookinfo_csr.pem
```

#### Generate Self-Signed Certificate

```
openssl x509 -req -in bookinfo_csr.pem -sha256 -days 365 -extensions v3_ca -signkey bookinfo_key.pem -CAcreateserial -out bookinfo_cert.pem
```

### C.2) Create a Kubernetes secret

Create a secret `citrix-ingressgateway-certs` using certificate and key generated in earlier step. Make sure that this secret is created in the same namespace where Ingress Gateway is deployed.

```
kubectl create -n citrix-system secret tls citrix-ingressgateway-certs --key bookinfo_key.pem --cert bookinfo_cert.pem
```

### C.3) Deploy Bookinfo application 

Bookinfo application can either be deployed using helm chart or deployment yaml files. If you want to deploy bookinfo along with Citrix ADC CPX as sidecar proxies, then make sure that [Citrix ADC Sidecar Injector](../../charts/stable/citrix-cpx-istio-sidecar-injector/README.md) is deployed, and the namespace is labeled with `cpx-injection=enabled`.

#### Enable Namespace for Sidecar Injection

```
kubectl create namespace bookinfo

kubectl label namespace bookinfo cpx-injection=enabled

```

_**NOTE:** If you do not wish to launch bookinfo application without any sidecar proxy, then skip above commands._


Follow *any one of these two methods* to deploy the application. 

### Deploy using Helm Chart

*Helm Chart Name:* bookinfo-citrix-ingress

Ensure that the namespace of Citrix ADC Ingress gateway is provided correctly.

```
helm install bookinfo-citrix-ingress --name bookinfo-citrix-ingress --namespace bookinfo --set citrixIngressGateway.namespace=citrix-system
```

By default, this bookinfo application is deployed with TLS mode disabled. 

To deploy it with the mTLS, use `mtlsEnabled=true` option in helm chart.

```
helm install bookinfo-citrix-ingress --name bookinfo-citrix-ingress --namespace bookinfo --set citrixIngressGateway.namespace=citrix-system --set mtlsEnabled=true
```

### Deploy Bookinfo using Yaml

```

kubectl apply -n bookinfo -f https://raw.githubusercontent.com/citrix/citrix-istio-adaptor/master/examples/citrix-adc-in-istio/bookinfo/deployment-yaml/bookinfo.yaml  

```



Once bookinfo application is deployed using Helm, proceed to Verification section.


#### Configuring Ingress Gateway for Bookinfo 

Ingress Gateway can be configured using Istio Gateway resource for secure (https) as well as plain http traffic. 

##### Configure HTTPS Gateway

```
kubectl apply -n bookinfo -f https://raw.githubusercontent.com/citrix/citrix-istio-adaptor/master/examples/citrix-adc-in-istio/bookinfo/deployment-yaml/bookinfo_https_gateway.yaml

```

##### Configure HTTP Gateway

```
kubectl apply -n bookinfo -f https://raw.githubusercontent.com/citrix/citrix-istio-adaptor/master/examples/citrix-adc-in-istio/bookinfo/deployment-yaml/bookinfo_http_gateway.yaml
```

#### Traffic Management using VirtualService and DestinationRule

Create [VirtualService](https://istio.io/docs/reference/config/istio.networking.v1alpha3/#VirtualService) for productpage service which is a frontend microservice of bookinfo app.

```
kubectl apply -n bookinfo -f https://raw.githubusercontent.com/citrix/citrix-istio-adaptor/master/examples/citrix-adc-in-istio/bookinfo/deployment-yaml/productpage_vs.yaml

```

Create [DestinationRule](https://istio.io/docs/reference/config/istio.networking.v1alpha3/#DestinationRule) for productpage.

```
kubectl apply -n bookinfo -f https://raw.githubusercontent.com/citrix/citrix-istio-adaptor/master/examples/citrix-adc-in-istio/bookinfo/deployment-yaml/productpage_dr.yaml

```

#### Authentication Policy for Bookinfo

##### Without mTLS 

If mTLS is enabled, non-istio services in which sidecar is not running won't be able to communicate with istio services. To enable such inter-service communication, TLS policy should be disabled. This is usually needed when some services are yet to be migrated to Service Mesh and we need to keep the communication between services active during transition to fully enabled service mesh application deployment.

```
kubectl apply -n bookinfo -f https://raw.githubusercontent.com/citrix/citrix-istio-adaptor/master/examples/citrix-adc-in-istio/bookinfo/deployment-yaml/bookinfo_policy_tls_disabled.yaml

```

##### Enabling the mTLS

Once all services are migrated to servicemesh, i.e. sidecar is deployed in all services, mTLS can be enabled by reconfiguring the policy.

```
kubectl apply -n bookinfo -f https://raw.githubusercontent.com/citrix/citrix-istio-adaptor/master/examples/citrix-adc-in-istio/bookinfo/deployment-yaml/bookinfo_policy_istio_mutual.yaml

```


## <a name="verification">D) Verification</a>

### I) If Citrix ADC VPX/MPX is running as an Ingress Gateway Device

1. Determine the Virtual Server's IP.

```

export INGRESS_IP=$(kubectl get pods -l app=citrix-ingressgateway -n citrix-system -o 'jsonpath={.items[0].spec.containers[?(@.name=="istio-adaptor")].args}' | awk '{ for(i=1;i<=NF;++i) { if ($i=="-vserver-ip") print $(i+1) } }')

```

2. Access bookinfo's frontend application using curl. 200 OK response should be returned by the productpage.

```
curl -kv https://$INGRESS_IP/productpage

curl -v http://$INGRESS_IP/productpage
```

3. Visit https://www.bookinfo.com/productpage from browser. Make sure that **DNS entry for www.bookinfo.com is created with $INGRESS_IP on client device** (Usually an entry in /etc/hosts on Unix flavoured machines). 

One can also visit https://$INGRESS_IP/productpage from browser. Make sure that $INGRESS_IP is replaced by the actual Vserver IP obtained in Step C.I.1.


### II) If Citrix ADC CPX is running as Ingress Gateway Device

1. Determine the Ingress IP and port

```
export INGRESS_HOST=$(kubectl get pods -l app=citrix-ingressgateway -n citrix-system -o 'jsonpath={.items[0].status.hostIP}')

export INGRESS_PORT=$(kubectl -n citrix-system get service citrix-ingressgateway -o jsonpath='{.spec.ports[?(@.name=="http2")].nodePort}')

export SECURE_INGRESS_PORT=$(kubectl -n citrix-system get service citrix-ingressgateway -o jsonpath='{.spec.ports[?(@.name=="https")].nodePort}')
```

2. Access bookinfo's frontend application using curl. 200 OK response should be returned by the productpage.

```
curl -kv https://$INGRESS_HOST:$SECURE_INGRESS_PORT/productpage

curl -v http://$INGRESS_HOST:$INGRESS_PORT/productpage
```

3. Visit https://$INGRESS_HOST:$SECURE_INGRESS_PORT/productpage from browser. Bookinfo page should be loaded. Make sure that $INGRESS_HOST and $SECURE_INGRESS_PORT are replaced by IP and port value.

### III) Verification of mTLS using istioctl tool

```
istioctl authn tls-check -n bookinfo <pod-name> | grep bookinfo
```

## <a name="cleanup">E) Clean Up </a>

### Cleanup using Helm

```
helm delete --purge bookinfo-citrix-ingress

kubectl delete secret citrix-ingressgateway-certs -n citrix-system

```


### Cleanup using yaml files

Delete the Gateway configuration, VirtualService, DestinationRule and the secret, and shutdown the bookinfo application.

```
kubectl delete -n bookinfo -f https://raw.githubusercontent.com/citrix/citrix-istio-adaptor/master/examples/citrix-adc-in-istio/bookinfo/deployment-yaml/bookinfo_http_gateway.yaml

kubectl delete -n bookinfo -f https://raw.githubusercontent.com/citrix/citrix-istio-adaptor/master/examples/citrix-adc-in-istio/bookinfo/deployment-yaml/bookinfo_https_gateway.yaml

kubectl delete -n bookinfo -f https://raw.githubusercontent.com/citrix/citrix-istio-adaptor/master/examples/citrix-adc-in-istio/bookinfo/deployment-yaml/productpage_vs.yaml

kubectl delete -n bookinfo -f https://raw.githubusercontent.com/citrix/citrix-istio-adaptor/master/examples/citrix-adc-in-istio/bookinfo/deployment-yaml/productpage_dr.yaml

kubectl delete -n bookinfo -f https://raw.githubusercontent.com/citrix/citrix-istio-adaptor/master/examples/citrix-adc-in-istio/bookinfo/deployment-yaml/bookinfo_policy_istio_mutual.yaml

kubectl delete secret -n citrix-system citrix-ingressgateway-certs

kubectl delete -n bookinfo -f https://raw.githubusercontent.com/citrix/citrix-istio-adaptor/master/examples/citrix-adc-in-istio/bookinfo/deployment-yaml/bookinfo.yaml

kubectl delete namespace bookinfo
```
