package manager

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// restartDeployment fetches the deployment and updates the `kubectl.kubernetes.io/restartedAt` annotation to trigger
// a restart.
func (s *Service) restartDeployment(ctx context.Context, deploymentName string) error {
	if isLocalEnvironment() {
		return nil
	}

	deployment, err := s.kubernetesClientSet.AppsV1().Deployments(s.GetAgentNamespace()).Get(ctx, deploymentName, v1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting deployment: %w", err)
	}

	if deployment.Spec.Template.Annotations == nil {
		deployment.Spec.Template.Annotations = map[string]string{}
	}
	deployment.Spec.Template.Annotations["kubectl.kubernetes.io/restartedAt"] = time.Now().Format(time.RFC3339Nano)

	if _, err := s.kubernetesClientSet.AppsV1().Deployments(s.GetAgentNamespace()).Update(ctx, deployment, v1.UpdateOptions{}); err != nil {
		return fmt.Errorf("error updating deployment: %w", err)
	}

	return nil
}

// restartDaemonSet fetches the daemonSet and updates the `kubectl.kubernetes.io/restartedAt` annotation to trigger
// a restart.
func (s *Service) restartDaemonSet(ctx context.Context, dsName string) error {
	if isLocalEnvironment() {
		return nil
	}

	deployment, err := s.kubernetesClientSet.AppsV1().DaemonSets(s.GetAgentNamespace()).Get(ctx, dsName, v1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting daemonSet: %w", err)
	}

	if deployment.Spec.Template.Annotations == nil {
		deployment.Spec.Template.Annotations = map[string]string{}
	}
	deployment.Spec.Template.Annotations["kubectl.kubernetes.io/restartedAt"] = time.Now().Format(time.RFC3339Nano)

	if _, err := s.kubernetesClientSet.AppsV1().DaemonSets(s.GetAgentNamespace()).Update(ctx, deployment, v1.UpdateOptions{}); err != nil {
		return fmt.Errorf("error updating daemonSet: %w", err)
	}

	return nil
}

// updateAgentVersion updates the agent deployment with a new image version and updates the version labels
func (s *Service) updateAgentVersion(ctx context.Context, newVersion string) error {
	if isLocalEnvironment() {
		return nil
	}

	deployment, err := s.kubernetesClientSet.AppsV1().Deployments(s.GetAgentNamespace()).Get(ctx, s.GetAgentName(), v1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting agent deployment: %w", err)
	}

	image := deployment.Spec.Template.Spec.Containers[0].Image
	imageParts := strings.Split(image, ":")
	if len(imageParts) != 2 {
		return fmt.Errorf("invalid image format: %s", image)
	}

	newImage := fmt.Sprintf("%s:%s", imageParts[0], newVersion)
	deployment.Spec.Template.Spec.Containers[0].Image = newImage
	deployment.Labels["app.kubernetes.io/version"] = newVersion
	deployment.Spec.Template.Labels["app.kubernetes.io/version"] = newVersion

	if _, err := s.kubernetesClientSet.AppsV1().Deployments(s.GetAgentNamespace()).Update(ctx, deployment, v1.UpdateOptions{}); err != nil {
		return fmt.Errorf("update deployment: %w", err)
	}

	// We're setting the agent version to prevent multiple updates of the deployment if the heartbeat interval is
	// shorter than the time it takes for the deployment to roll out
	s.SetAgentVersion(newVersion)
	return nil
}

func (s *Service) getDeploymentAndChartsVersions(ctx context.Context, ns, deploymentName string) (string, string, error) {
	if val, ok := os.LookupEnv("ENVIRONMENT"); ok && val == "local" {
		return defaultAgentVersion, defaultAgentVersion, nil
	}

	deployment, err := s.kubernetesClientSet.AppsV1().Deployments(ns).Get(ctx, deploymentName, v1.GetOptions{})
	if err != nil {
		return "", "", fmt.Errorf("error getting deployment: %w", err)
	}

	agentVersion, ok := deployment.Labels["app.kubernetes.io/version"]
	if !ok {
		return "", "", fmt.Errorf("agent version label not found on deployment")
	}

	chartsVersion, ok := deployment.Labels["helm.sh/chart"]
	if !ok {
		return "", "", fmt.Errorf("helm chart version label not found on deployment")
	}

	return agentVersion, chartsVersion, nil
}

// loadDeploymentVersion gets the deployment details from the API server and extracts the version from the labels
func loadDeploymentVersion(ctx context.Context, clientSet *kubernetes.Clientset, ns, deploymentName string) (string, error) {
	if val, ok := os.LookupEnv("ENVIRONMENT"); ok && val == "local" {
		return defaultAgentVersion, nil
	}

	deployment, err := clientSet.AppsV1().Deployments(ns).Get(ctx, deploymentName, v1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("error getting deployment: %w", err)
	}

	agentVersion, ok := deployment.Labels["app.kubernetes.io/version"]
	if !ok {
		return "", fmt.Errorf("agent version label not found on deployment")
	}

	return agentVersion, nil
}

// loadDaemonSetVersion gets the daemonSet details from the API server and extracts the version from the labels
func loadDaemonSetVersion(ctx context.Context, clientSet *kubernetes.Clientset, ns, dsName string) (string, error) {
	if val, ok := os.LookupEnv("ENVIRONMENT"); ok && val == "local" {
		return defaultAgentVersion, nil
	}

	deployment, err := clientSet.AppsV1().DaemonSets(ns).Get(ctx, dsName, v1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("error getting daemonSet: %w", err)
	}

	agentVersion, ok := deployment.Labels["app.kubernetes.io/version"]
	if !ok {
		return "", fmt.Errorf("agent version label not found on deployment")
	}

	return agentVersion, nil
}
