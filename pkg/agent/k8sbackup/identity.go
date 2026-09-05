package k8sbackup

import (
	"context"
	"fmt"
	"time"

	"github.com/osshield/fallbck/pkg/config"
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// identityKey is the Secret key holding the full agent configuration
const identityKey = "agent.yaml"

// LoadIdentity reads the enrolled agent configuration from the identity Secret;
// (nil, nil) when the Secret does not exist yet.
func LoadIdentity(ctx context.Context, core kubernetes.Interface, namespace, name string) (*config.AgentConfig, error) {
	secret, err := core.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading identity secret %s/%s: %w", namespace, name, err)
	}
	data, ok := secret.Data[identityKey]
	if !ok || len(data) == 0 {
		return nil, nil
	}
	var cfg config.AgentConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing identity secret %s/%s: %w", namespace, name, err)
	}
	return &cfg, nil
}

// SaveIdentity writes the agent configuration into the identity Secret (create or update)
func SaveIdentity(ctx context.Context, core kubernetes.Interface, namespace, name string, cfg *config.AgentConfig) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("serialising agent configuration: %w", err)
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: namespace,
			Labels: map[string]string{labelManagedBy: labelValue},
		},
		Data: map[string][]byte{identityKey: data},
	}
	_, err = core.CoreV1().Secrets(namespace).Create(ctx, secret, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		existing, getErr := core.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
		if getErr != nil {
			return getErr
		}
		if existing.Data == nil {
			existing.Data = map[string][]byte{}
		}
		existing.Data[identityKey] = data
		_, err = core.CoreV1().Secrets(namespace).Update(ctx, existing, metav1.UpdateOptions{})
	}
	if err != nil {
		return fmt.Errorf("writing identity secret %s/%s: %w", namespace, name, err)
	}
	return nil
}

// IdentityPersist adapts SaveIdentity for runtime.TokenStore.Persist (token rotations)
func IdentityPersist(core kubernetes.Interface, namespace, name string) func(cfg *config.AgentConfig) error {
	return func(cfg *config.AgentConfig) error {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return SaveIdentity(ctx, core, namespace, name, cfg)
	}
}
