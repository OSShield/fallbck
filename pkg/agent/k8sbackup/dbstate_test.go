package k8sbackup

import (
	"context"
	"testing"

	dbspec "github.com/osshield/fallbck/pkg/dbbackup"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

func TestDBStateSecretRoundTrip(t *testing.T) {
	core := k8sfake.NewSimpleClientset()
	ctx := context.Background()
	if st, err := LoadDBState(ctx, core, "fallbck", "state", "job-1"); err != nil || st != nil {
		t.Fatalf("missing secret must be (nil, nil): %v %v", st, err)
	}
	first := &dbspec.JobState{JobID: "job-1", Engine: "mysql", LastSuccess: &dbspec.JobStateRecord{RunID: "r1", MySQL: &dbspec.MySQLState{BinlogFile: "bin.000007", BinlogPos: 1234}}}
	if err := SaveDBState(ctx, core, "fallbck", "state", "job-1", first); err != nil {
		t.Fatal(err)
	}
	second := &dbspec.JobState{JobID: "job-2", Engine: "postgres", LastSuccess: &dbspec.JobStateRecord{RunID: "r9"}}
	if err := SaveDBState(ctx, core, "fallbck", "state", "job-2", second); err != nil {
		t.Fatal(err)
	}
	back, err := LoadDBState(ctx, core, "fallbck", "state", "job-1")
	if err != nil || back == nil || back.LastSuccess.MySQL.BinlogFile != "bin.000007" {
		t.Fatalf("job-1 state: %+v %v", back, err)
	}
	back2, _ := LoadDBState(ctx, core, "fallbck", "state", "job-2")
	if back2 == nil || back2.LastSuccess.RunID != "r9" {
		t.Fatalf("job-2 state lost when job-1 was saved: %+v", back2)
	}
	if st, err := LoadDBState(ctx, core, "fallbck", "state", "job-3"); err != nil || st != nil {
		t.Fatalf("unknown job must be (nil, nil): %v %v", st, err)
	}
}

func TestReadSecretCredentials(t *testing.T) {
	core := k8sfake.NewSimpleClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "pg-creds", Namespace: "clusterdb", Labels: map[string]string{CredentialsLabel: "true"}},
		Data:       map[string][]byte{"password": []byte("s3cret"), "username": []byte("backup")},
	}, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "unlabelled", Namespace: "clusterdb"},
		Data:       map[string][]byte{"password": []byte("s3cret")},
	})
	ctx := context.Background()
	pw, user, err := ReadSecretCredentials(ctx, core, "clusterdb", "pg-creds", "password", "username")
	if err != nil || pw != "s3cret" || user != "backup" {
		t.Fatalf("got %q %q %v", pw, user, err)
	}
	pw, user, err = ReadSecretCredentials(ctx, core, "clusterdb", "pg-creds", "password", "")
	if err != nil || pw != "s3cret" || user != "" {
		t.Fatalf("without user key: %q %q %v", pw, user, err)
	}
	if _, _, err := ReadSecretCredentials(ctx, core, "clusterdb", "pg-creds", "pass", ""); err == nil {
		t.Error("missing password key must fail")
	}
	if _, _, err := ReadSecretCredentials(ctx, core, "clusterdb", "nope", "password", ""); err == nil {
		t.Error("missing secret must fail")
	}
	if _, _, err := ReadSecretCredentials(ctx, core, "clusterdb", "unlabelled", "password", ""); err == nil {
		t.Error("secret without the opt-in label must fail")
	}
}
