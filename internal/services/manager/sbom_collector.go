package manager

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"aikidoSec.kubernetesAgent/pkg/models"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func (s *Service) ConfigureSBOMCollector(ctx context.Context, enabled bool, enabledInCharts bool) error {
	if s.GetRunSBOMCollectorAsDaemonSet() {
		return s.configureSBOMCollectorDaemonSet(ctx, enabled, enabledInCharts)
	}

	return s.configureSBOMCollectorDeployment(ctx, enabled, enabledInCharts)
}

func (s *Service) configureSBOMCollectorDaemonSet(ctx context.Context, enabled, enabledInCharts bool) error {
	if IsLocalEnvironment() {
		return nil
	}

	if !enabledInCharts {
		return nil
	}

	ds, err := s.kubernetesClientSet.AppsV1().DaemonSets(s.GetAgentNamespace()).Get(ctx, s.GetSBOMCollectorName(), v1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting SBOM collector daemonset: %w", err)
	}

	if enabled {
		if len(ds.Spec.Template.Spec.NodeSelector) > 0 {
			delete(ds.Spec.Template.Spec.NodeSelector, "aikidoSecurity.disable-sbom-collector")
		}
	} else {
		ds.Spec.Template.Spec.NodeSelector = map[string]string{
			"aikidoSecurity.disable-sbom-collector": "true",
		}
	}

	if _, err := s.kubernetesClientSet.AppsV1().DaemonSets(s.GetAgentNamespace()).Update(ctx, ds, v1.UpdateOptions{}); err != nil {
		return fmt.Errorf("error updating SBOM collector daemonset: %w", err)
	}
	return nil
}

func (s *Service) configureSBOMCollectorDeployment(ctx context.Context, enabled, enabledInCharts bool) error {
	if IsLocalEnvironment() {
		return nil
	}

	if !enabledInCharts {
		return nil
	}

	dep, err := s.kubernetesClientSet.AppsV1().Deployments(s.GetAgentNamespace()).Get(ctx, s.GetSBOMCollectorName(), v1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting SBOM collector deployment: %w", err)
	}

	if enabled {
		replicas := int32(1)
		dep.Spec.Replicas = &replicas
	} else {
		replicas := int32(0)
		dep.Spec.Replicas = &replicas
	}

	if _, err := s.kubernetesClientSet.AppsV1().Deployments(s.GetAgentNamespace()).Update(ctx, dep, v1.UpdateOptions{}); err != nil {
		return fmt.Errorf("error updating SBOM collector deployment: %w", err)
	}
	return nil
}

func (s *Service) RestartSBOMCollector(ctx context.Context) error {
	if s.GetRunSBOMCollectorAsDaemonSet() {
		return s.RestartDaemonSet(ctx, s.GetSBOMCollectorName())
	}

	return s.RestartDeployment(ctx, s.GetSBOMCollectorName())
}

func (s *Service) UpdateSBOMCollectorVersion(ctx context.Context, newVersion string) error {
	if s.GetRunSBOMCollectorAsDaemonSet() {
		return s.UpdateSBOMCollectorDaemonSetVersion(ctx, newVersion)
	}

	return s.UpdateSBOMCollectorDeploymentVersion(ctx, newVersion)
}

// UpdateSBOMCollectorDeploymentVersion updates the sbom collector deployment with a new image version and updates the version labels
func (s *Service) UpdateSBOMCollectorDeploymentVersion(ctx context.Context, newVersion string) error {
	if IsLocalEnvironment() {
		return nil
	}

	deployment, err := s.kubernetesClientSet.AppsV1().Deployments(s.GetAgentNamespace()).Get(ctx, s.GetSBOMCollectorName(), v1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting sbom collector deployment: %w", err)
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
		return fmt.Errorf("error updating sbom collector deployment: %w", err)
	}

	// We're setting the sbom collector version to prevent multiple updates of the deployment if the heartbeat interval is
	// shorter than the time it takes for the deployment to roll out
	s.SetSBOMCollectorVersion(newVersion)
	return nil
}

// UpdateSBOMCollectorDaemonSetVersion updates the sbom collector daemonSet with a new image version and updates the version labels
func (s *Service) UpdateSBOMCollectorDaemonSetVersion(ctx context.Context, newVersion string) error {
	if IsLocalEnvironment() {
		return nil
	}

	daemonSet, err := s.kubernetesClientSet.AppsV1().DaemonSets(s.GetAgentNamespace()).Get(ctx, s.GetSBOMCollectorName(), v1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting sbom collector deployment: %w", err)
	}

	image := daemonSet.Spec.Template.Spec.Containers[0].Image
	imageParts := strings.Split(image, ":")
	if len(imageParts) != 2 {
		return fmt.Errorf("invalid image format: %s", image)
	}

	newImage := fmt.Sprintf("%s:%s", imageParts[0], newVersion)
	daemonSet.Spec.Template.Spec.Containers[0].Image = newImage
	daemonSet.Labels["app.kubernetes.io/version"] = newVersion
	daemonSet.Spec.Template.Labels["app.kubernetes.io/version"] = newVersion

	if _, err := s.kubernetesClientSet.AppsV1().DaemonSets(s.GetAgentNamespace()).Update(ctx, daemonSet, v1.UpdateOptions{}); err != nil {
		return fmt.Errorf("error updating sbom collector deployment: %w", err)
	}

	// We're setting the sbom collector version to prevent multiple updates of the deployment if the heartbeat interval is
	// shorter than the time it takes for the deployment to roll out
	s.SetSBOMCollectorVersion(newVersion)
	return nil
}

func LoadSBOMCollectorVersion(ctx context.Context, clientSet *kubernetes.Clientset, ns, ownerName string, isDaemonSet bool) (string, error) {
	if isDaemonSet {
		return LoadDaemonSetVersion(ctx, clientSet, ns, ownerName)
	}
	return LoadDeploymentVersion(ctx, clientSet, ns, ownerName)
}

func (s *Service) ListCollectorScannedImages(ctx context.Context) ([]models.ScannedImage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/api/sbom/list-scanned-images", s.GetAPIEndpoint()), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+s.GetAPIToken())

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request to get collector scanned images: %w", err)
	}
	defer func() {
		if err := res.Body.Close(); err != nil {
			s.logger.ReportError(ctx, err, "error closing list collector scanned images body", "managerError")
		}
	}()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error listing collector scanned images, status code: %d", res.StatusCode)
	}

	var response []models.ScannedImage
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		return nil, err
	}

	return response, nil
}

func (s *Service) GetSBOMCollectorServiceAccount(ctx context.Context) (*corev1.ServiceAccount, error) {
	if s.GetRunSBOMCollectorAsDaemonSet() {
		return s.getDaemonsetServiceAccount(ctx, s.GetSBOMCollectorName())
	}

	return s.getDeploymentServiceAccount(ctx, s.GetSBOMCollectorName())
}

func (s *Service) GetServiceAccountByName(ctx context.Context, name string) (*corev1.ServiceAccount, error) {
	sa, err := s.kubernetesClientSet.CoreV1().ServiceAccounts(s.GetAgentNamespace()).Get(ctx, name, v1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("error getting service account by name: %w", err)
	}

	return sa, nil
}

func (s *Service) getDaemonsetServiceAccount(ctx context.Context, dsName string) (*corev1.ServiceAccount, error) {
	ds, err := s.kubernetesClientSet.AppsV1().DaemonSets(s.GetAgentNamespace()).Get(ctx, dsName, v1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("error getting SBOM collector daemonset: %w", err)
	}

	if ds.Spec.Template.Spec.ServiceAccountName == "" {
		return nil, nil
	}

	return s.GetServiceAccountByName(ctx, ds.Spec.Template.Spec.ServiceAccountName)
}

func (s *Service) getDeploymentServiceAccount(ctx context.Context, depName string) (*corev1.ServiceAccount, error) {
	dep, err := s.kubernetesClientSet.AppsV1().Deployments(s.GetAgentNamespace()).Get(ctx, depName, v1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("error getting SBOM collector deployment: %w", err)
	}

	if dep.Spec.Template.Spec.ServiceAccountName == "" {
		return nil, nil
	}

	return s.GetServiceAccountByName(ctx, dep.Spec.Template.Spec.ServiceAccountName)
}
