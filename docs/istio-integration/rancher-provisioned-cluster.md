**Certificate Signing Request Issue in an RKE cluster hosted on a cloud provider**


Sometimes, an issue is reported in which even though the certificate signing request (CSR) is approved by the certificate controller, the certificate is not shown in the status. This topic explains how to troubleshoot this issue in a Rancher managed Kubernetes cluster.

- Environment: Kubernetes cluster created by RKE in a cloud provider.

- Issue: Controller approved the Kubernetes certificate signing request, but the certificate is not shown as "Issued" in the status.

    **Expected Behaviour**:
    ```
     kubectl get csr -n citrix-cpx-istio-sidecar-injector

     NAME      AGE   SIGNERNAME   REQUESTOR   CONDITION

    cpx-sidecar-injector.citrix-system   51s   kubernetes.io/legacy-unknown   system:serviceaccount:citrix-cpx-istio-sidecar-injector:cpx-sidecar-injector-service-account   Approved, Issued
  ```
    
    **Outcome in RKE based Cluster**:
    
        kubectl get csr -n citrix-cpx-istio-sidecar-injector

        NAME   AGE   SIGNERNAME   REQUESTOR   CONDITION

        cpx-sidecar-injector.citrix-system   51s   kubernetes.io/legacy-unknown   system:serviceaccount:citrix-cpx-istio-sidecar-injector:cpx-sidecar-injector-service-account   Approved

Following is a workaround suggested in the Kubernetes documentation to resolve the issue:
1.	Enable the Kubernetes controller manager’s default certificate [signer](https://kubernetes.io/docs/tasks/tls/managing-tls-in-a-cluster/#a-note-to-cluster-administrators) using the following steps.
    1.	Edit your cluster in Rancher.
    2.	Click the Edit as YAML button and edit as the following (See the [Rancher cluster configuration](https://rancher.com/docs/rancher/v2.x/en/cluster-admin/editing-clusters/) for information to edit the YAML file).
    ```
 	   services:
     kube-controller: 
       extra_args: 
        cluster-signing-cert-file: "/etc/kubernetes/ssl/kube-ca.pem"
        cluster-signing-key-file: "/etc/kubernetes/ssl/kube-ca-key.pem"
 	```
For more details of kube-controllers services default options in RKE, Please follow the link of [Rancher documentation](https://rancher.com/docs/rke/latest/en/config-options/services/#kubernetes-controller-manager).

