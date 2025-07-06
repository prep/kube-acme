# kube-acme
This repository contains `kube-acme`, a service that performs [Let's Encrypt](https://letsencrypt.org/) certificate updates in Kubernetes. It accepts ACME challenges routed from `nginx` and stores the certificate as a `Secret`. On top of that, if you're running on Oracle Cloud Kubernetes Engine (OKE), `kube-acme` can update your `Service` if your setup [terminates SSL/TLS at the load balancer](https://docs.oracle.com/en-us/iaas/Content/ContEng/Tasks/contengcreatingloadbalancers-subtopic.htm#creatinglbhttps).

**Note**: This is only useful for the above-mentioned setup where [cert-manager](https://cert-manager.io/) doesn't fit. In all other cases, you should probably use that.

## Installation
This service can be used in a couple different configurations but they all require the following:

* Whatever is serving your HTTP requests, it needs to be able to relay the `/.well-known/acme-challenge/` path to the `kube-acme` pod.
* Whatever is providing your SSL/TLS service, it needs to be able to load it from a Kubernetes `Secret`.

### Install `kube-acme`
To install `kube-acme` in your cluster, download the [deployment.yaml](k8s/deployment.yaml) and edit the environment variables. The commented out ones are optional and will have their default values.

```shell
curl -O https://github.com/prep/kube-acme/blob/k8s/deployment.yaml
```

Load your `deployment.yaml` once it's been edited:

```shell
kubectl apply -f deployment.yaml
```
Check that a single pod is running:

```shell
kubectl -n kube-acme get pods
```

### Relay ACME challenges
The `kube-acme` pod needs the ability to receive ACME challenges from all the configured domains. Here are 2 ways to relay them based on what setup you are running.

#### Relay from nginx
If your setup uses nginx then you need add a `location` rule in your nginx configuration for every domain who will be part of the certificate.

```nginx
server {
    server_name example.com;
    
    location /.well-known/acme-challenge/ {
        proxy_pass http://kube-acme.kube-acme.svc.cluster.local:80;
    }
}
```

Apply this change to your configuration and restart your `nginx` pods:

```shell
kubectl -n nginx rollout restart deploy nginx
```

### Create or update your certificate
To request `kube-acme` to create or update the certificate, send the following request to the running pod:

```shell
kubectl exec -n kube-acme $(kubectl get pod -n kube-acme -l app=kube-acme -o jsonpath='{.items[0].metadata.name}') -- /kubeacme request
```

Keep an eye out on the logs to see if it succeeded:

```shell
kubectl logs -f -n kube-acme -l app=kube-acme
```

Ideally, this should be done automatically, but that's not implemented yet. A typical log should look like this:

```
time=2025-07-06T16:22:55.432Z level=INFO msg="Requesting certificate update" app.name=kube-acme app.revision=19 app.commit=df08ca2
time=2025-07-06T16:23:00.390Z level=INFO msg="Secret stored" k8s.namespace=nginx k8s.name=ssl-cert-20250706 app.name=kube-acme app.revision=19 app.commit=df08ca2
time=2025-07-06T16:23:00.391Z level=INFO msg="Updating service annotation" key=service.beta.kubernetes.io/oci-load-balancer-tls-secret value=ssl-cert-20250706 k8s.name=ingress k8s.namespace=nginx app.name=kube-acme app.revision=19 app.commit=df08ca2
time=2025-07-06T16:23:00.398Z level=INFO msg="Certificate update finished" k8s.name=ssl-cert-20250706 k8s.namespace=nginx app.name=kube-acme app.revision=19 app.commit=df08ca2
```

## Update
To pull the latest image in and update the service, simply restart the deployment.

```shell
kubectl -n kube-acme rollout restart deploy
```
