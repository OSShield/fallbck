package k8sbackup

import (
	"context"
	"encoding/json"
	"fmt"

	dbspec "github.com/osshield/fallbck/pkg/dbbackup"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Database jobs keep their chain state (last binlog position, WAL LSN) between runs.
// The dump pod is ephemeral, so the agent stores every job's state in one Secret in
// its own namespace, keyed by job id.

func stateKey(jobID string) string { return jobID + ".json" }

// CredentialsLabel must be "true" on a Secret before a database job may read it
const CredentialsLabel = "fallbck.io/allow-db-credentials"

// LoadDBState returns the job's previous state from the state Secret, or nil
func LoadDBState(ctx context.Context, core kubernetes.Interface, namespace, secretName, jobID string) (*dbspec.JobState, error) {
	secret, err := core.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading state secret %s/%s: %w", namespace, secretName, err)
	}
	data, ok := secret.Data[stateKey(jobID)]
	if !ok || len(data) == 0 {
		return nil, nil
	}
	var st dbspec.JobState
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("parsing job state in %s/%s: %w", namespace, secretName, err)
	}
	return &st, nil
}

// SaveDBState writes the job's state into the state Secret (create or update)
func SaveDBState(ctx context.Context, core kubernetes.Interface, namespace, secretName, jobID string, st *dbspec.JobState) error {
	data, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("serialising job state: %w", err)
	}
	secret := &corev1.Secret{
		Name: secretName, Namespace: namespace,
		Labels: map[string]string{labelManagedBy: labelValue},
		Data:   map[string][]byte{stateKey(jobID): data},
	}
	_, err = core.CoreV1().Secrets(namespace).Create(ctx, secret, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		existing, getErr := core.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
		if getErr != nil {
			return getErr
		}
		if existing.Data == nil {
			existing.Data = map[string][]byte{}
		}
		existing.Data[stateKey(jobID)] = data
		_, err = core.CoreV1().Secrets(namespace).Update(ctx, existing, metav1.UpdateOptions{})
	}
	if err != nil {
		return fmt.Errorf("writing state secret %s/%s: %w", namespace, secretName, err)
	}
	return nil
}

// ReadSecretCredentials reads the database password (and optionally the user) from a
// Secret in the database's namespace
func ReadSecretCredentials(ctx context.Context, core kubernetes.Interface, namespace, secretName, passwordKey, userKey string) (password, user string, err error) {
	secret, err := core.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		return "", "", fmt.Errorf("reading credentials secret %s/%s: %w", namespace, secretName, err)
	}
	// The ClusterRole can read every Secret (resource backups need that); a job may
	// only use the ones somebody labelled for it, so a compromised server cannot
	// turn a database job into a Secret exfiltration path
	if secret.Labels[CredentialsLabel] != "true" {
		return "", "", fmt.Errorf("credentials secret %s/%s is not labelled %s=true", namespace, secretName, CredentialsLabel)
	}
	pw, ok := secret.Data[passwordKey]
	if !ok {
		return "", "", fmt.Errorf("credentials secret %s/%s has no key %q", namespace, secretName, passwordKey)
	}
	if userKey != "" {
		u, ok := secret.Data[userKey]
		if !ok {
			return "", "", fmt.Errorf("credentials secret %s/%s has no key %q", namespace, secretName, userKey)
		}
		user = string(u)
	}
	return string(pw), user, nil
}
