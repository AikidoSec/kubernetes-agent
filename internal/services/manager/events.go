package manager

import (
	"context"
	"fmt"
	"slices"

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var ignoredEventsReasons = []string{
	"Pulled",
	"Created",
	"Started",
	"Scheduled",
	"ScalingReplicaSet",
	"SuccessfulCreate",
	"SuccessfulDelete",
}

func (s *Service) ListEventsByFieldSelector(ctx context.Context, fieldSelector string) ([]corev1.Event, error) {
	opts := v1.ListOptions{}
	if fieldSelector != "" {
		opts.FieldSelector = fieldSelector
	}
	eventsList, err := s.kubernetesClientSet.CoreV1().Events(s.GetAgentNamespace()).List(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("error listing resource events: %w", err)
	}

	events := make([]corev1.Event, 0, len(eventsList.Items))
	// Filter out irrelevant events by reason.
	for _, event := range eventsList.Items {
		if slices.Contains(ignoredEventsReasons, event.Reason) {
			continue
		}

		events = append(events, event)
	}

	return events, nil
}

func (s *Service) GenerateAgentPodEvent(ctx context.Context) (*corev1.Event, error) {
	agentPodDetails, err := s.GetPodByName(ctx, s.GetAgentPodName())
	if err != nil {
		return nil, fmt.Errorf("error getting agent pod: %w", err)
	}

	if len(agentPodDetails.Status.ContainerStatuses) == 0 {
		return nil, nil
	}

	event := &corev1.Event{
		TypeMeta: agentPodDetails.TypeMeta,
		InvolvedObject: corev1.ObjectReference{
			Kind:            "Pod",
			Namespace:       agentPodDetails.Namespace,
			Name:            agentPodDetails.Name,
			UID:             agentPodDetails.UID,
			APIVersion:      "v1",
			ResourceVersion: agentPodDetails.ResourceVersion,
		},
		Reason:  "AgentInformation",
		Message: agentPodDetails.Status.ContainerStatuses[0].LastTerminationState.String(),
		Count:   1,
		Type:    "AgentStatusInformation",
	}

	return event, nil
}

func (s *Service) GetPodByName(ctx context.Context, name string) (*corev1.Pod, error) {
	pod, err := s.kubernetesClientSet.CoreV1().Pods(s.GetAgentNamespace()).Get(ctx, name, v1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("error getting pod by name: %w", err)
	}

	return pod, nil
}
