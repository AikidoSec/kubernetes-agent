package format

import (
	"strings"

	"aikidoSec.kubernetesAgent/pkg/models"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func FormatPod(obj client.Object, state *models.AgentState) client.Object {
	if !state.IsImageMappingEnabled() {
		return obj
	}

	podObj, ok := obj.(*v1.Pod)
	if !ok {
		return obj
	}

	// Update the image sources in the pod spec
	updateContainersImagesSources(podObj.Spec.Containers, state)
	updateContainersImagesSources(podObj.Spec.InitContainers, state)
	updateEphemeralContainersImagesSources(podObj.Spec.EphemeralContainers, state)
	// Update the image sources in the pod status
	updateContainerStatusesImagesSources(podObj.Status.ContainerStatuses, state)
	updateContainerStatusesImagesSources(podObj.Status.InitContainerStatuses, state)
	updateContainerStatusesImagesSources(podObj.Status.EphemeralContainerStatuses, state)

	return podObj
}

func GetMirrorRepositoryForImage(image string, state *models.AgentState) (string, string) {
	imageRef, err := name.ParseReference(image)
	if err != nil {
		return "", ""
	}

	var repository string
	switch r := imageRef.(type) {
	case name.Tag:
		repository = r.Repository.Name()
	case name.Digest:
		repository = r.Repository.Name()
	}

	mirrorRepository := state.GetImageMirrorMapping(repository)

	return repository, mirrorRepository
}

func updateContainersImagesSources(containers []v1.Container, state *models.AgentState) {
	for i := range containers {
		repository, mirrorRepository := GetMirrorRepositoryForImage(containers[i].Image, state)
		if mirrorRepository == "" {
			continue
		}

		containers[i].Image = strings.Replace(containers[i].Image, repository, mirrorRepository, 1)
	}
}

func updateEphemeralContainersImagesSources(containers []v1.EphemeralContainer, state *models.AgentState) {
	for i := range containers {
		repository, mirrorRepository := GetMirrorRepositoryForImage(containers[i].Image, state)
		if mirrorRepository == "" {
			continue
		}

		containers[i].Image = strings.Replace(containers[i].Image, repository, mirrorRepository, 1)
	}
}

func updateContainerStatusesImagesSources(statuses []v1.ContainerStatus, state *models.AgentState) {
	for i := range statuses {
		repository, mirrorRepository := GetMirrorRepositoryForImage(statuses[i].ImageID, state)
		if mirrorRepository == "" {
			continue
		}

		statuses[i].ImageID = strings.Replace(statuses[i].ImageID, repository, mirrorRepository, 1)
		statuses[i].Image = strings.Replace(statuses[i].Image, repository, mirrorRepository, 1)
	}
}
