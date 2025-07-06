# kube-acme
This repository contains `kube-acme`: a service that performs [Let's Encrypt](https://letsencrypt.org/) certificate updates in Kubernetes. It accepts ACME challenges routed from `nginx` and stores the certificate as a `Secret`.

On top of that, if you're running on Oracle Cloud Kubernetes Engine (OKE), `kube-acme` can update your `Service` if your setup [terminates SSL/TLS at the load balancer](https://docs.oracle.com/en-us/iaas/Content/ContEng/Tasks/contengcreatingloadbalancers-subtopic.htm#creatinglbhttps).

**Note**: This is only useful for the above-mentioned setup where [cert-manager](https://cert-manager.io/) doesn't fit. In all other cases, you should probably use that.

## Installation
This service can be used in a couple different configurations but they all require the following:

* Whatever is serving your HTTP requests, it needs to be able to relay the `/.well-known/acme-challenge/` path to the `kube-acme` pod.
* Whatever is providing your SSL/TLS service, it needs to be able to load it from a Kubernetes `Secret`.

### Install `kube-acme`
To install `kube-acme` in your cluster, download the [deployment.yaml](k8s/deployment.yaml) and edit the environment variables. The commented out ones are optional and will have their default values.

```shell
curl -O https://github.com/prep/kubeacme/blob/k8s/deployment.yaml
```


> ⚠️ The `kube-acme` pod requires some permissive roles, most notably creating secrets and patching services. Check out the deployment configuration to see if they apply to your use-case and if you're comfortable with them.

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

### Requesting a new certificate
To request `kubeacme` to create or update the certificate, send the following request to the running pod:

```shell
kubectl -n kube-acme exec kube-acme-<rest of pod ID> -- /kubeacme request
```

Observe the logs of the pod to see what's happening. Ideally, this should be done automatically but it doesn't at the moment.

## Backups
To back up your ACME account key and TLS certificate:

```shell
kubectl -n kube-acme get secret account-key -o yaml > kube-acme-account-key.yaml
kubectl -n nginx get secret ssl-cert-20250629 -o yaml > nginx-ssl-cert.yaml
```

To put a backup back:

```shell
kubectl -n kube-acme apply -f kube-acme-account-key.yaml
kubectl -n nginx apply -f nginx-ssl-cert.yaml
```
