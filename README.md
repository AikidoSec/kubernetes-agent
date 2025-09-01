# Kubernetes Agent

The **Kubernetes Agent** runs inside your cluster and listens for Kubernetes resource events.  
It uses the controller-runtime library to create controllers that watch for changes in resources (e.g., Pods, Deployments, Jobs).  
Whenever an event occurs, the agent forwards the details to our backend service for further processing and analysis.

---

## Features

- Runs as a lightweight pod inside your Kubernetes cluster
- Watches Kubernetes resources using `controller-runtime` controllers
- Sends create/update/delete events to the backend

---

## Local Debugging

You can run the agent locally against your current Kubernetes context (`~/.kube/config`).

### Required Environment Variables

Before running the agent, set the following:

```bash
export AGENT_NAME="kubernetes-agent-rs001-001"
export AGENT_NAMESPACE="aikido"
export ENVIRONMENT="local"
```

### Config File

The agent expects a config file (YAML) containing authentication and backend information:

```yaml
apiToken: "<your-api-token>"
apiEndpoint: "https://backend.example.com/api/events"
```

Save this file as config.yaml (the name needs to match the `config` parameter send to the program).

### Running Locally

Run the agent with the config file path as a program argument:

```bash
go run cmd/main.go --config=config.yaml
```

## Local Deployment with Minikube

Deploy the agent to a local **Minikube** cluster using a locally built image and the Helm chart.

> Prerequisites: Minikube is installed and running (`minikube start`), Docker is installed.

### 1) Point Docker to Minikube’s Docker daemon

This ensures the image you build is placed **inside** Minikube’s Docker registry, so the cluster can pull it without pushing to a remote registry.

```bash
eval $(minikube docker-env)
```

After this, all docker commands run against the Docker daemon inside the Minikube VM.

### 2) Build the agent image for the cluster

Build (and tag) the container image used by the Helm release. The --platform flag ensures compatibility with the Minikube node’s architecture.

```bash
docker buildx build --platform linux/amd64 -t kubernetes-agent:$imageTag .
```

### 3) Install the chart with your API settings

Use Helm to install the [chart](https://github.com/AikidoSec/helm-charts), passing your API endpoint and token at install time.
This command will create a new namespace called `aikido` if it doesn’t already exist and install the agent components.

```bash
helm install kubernetes-agent ./kubernetes-agent -n aikido \
  --set image.repository=kubernetes-agent:$imageTag \
  --set config.apiEndpoint=$endpoint \
  --set config.apiToken=$token \
  --create-namespace
```
