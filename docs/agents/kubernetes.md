# Kubernetes

`fallbck-k8s-agent` runs **inside** the cluster you're backing up, one install per cluster. It grabs every API resource plus the data in your PVCs, and it can dump databases running in the cluster too.

## Install

```bash
helm install fallbck-k8s-agent deploy/helm/fallbck-k8s-agent \
  --namespace fallbck --create-namespace \
  --set server.url=https://backup.example.com \
  --set clusterName=prod \
  --set enrollment.key=<enrollment token>
```

It enrolls as `k8s-<clusterName>` and keeps its identity in a Secret. `helm upgrade` never touches that Secret. Delete it if you want to re-enroll. All chart values are in the [Helm reference](../reference/helm.md).

## Cluster jobs

Set them up in onboarding. They show up on Backup Jobs under the *Kubernetes* filter. Knobs:

- namespace, label and resource selection
- Secrets in or out
- volume mode: all, labeled, or none
- storage-class filters and snapshot-class overrides
- live-mount fallback
- parallelism

### Volumes

If the CSI driver supports snapshots, the agent takes a `VolumeSnapshot`, clones it into a temporary PVC and uploads the files from the clone. If it doesn't, the agent mounts the live volume read-only, which gets you crash-consistent and no better.

Uploads run in short-lived worker pods in each volume's namespace, in parallel. To skip a volume:

- annotate the PVC `fallbck.io/skip: "true"`, or
- set *Skip PVCs matching label selector* on the job (`volumes.skip_label_selector`, e.g. `fallbck.io/skip-backup=true`).

### What lands on PBS

- One snapshot per volume: `host/k8s-<cluster>-pvc-<ns>-<name>`
- One resources snapshot: `host/k8s-<cluster>`, with every selected object as YAML plus `k8s-manifest.blob` (plan, how each volume went, restore commands)

A PBS prune job on the datastore covers all of these groups. Groups for PVCs that no longer exist stick around until you forget them on PBS yourself.

## Databases in the cluster

Same agent. Create a *Database* job for the `k8s-<cluster>` agent (onboarding → *Existing agent*). Besides the usual engine settings, you give it:

- the namespace,
- the Service to connect to (or an explicit host),
- optionally a Secret holding the password (and user). The Secret must carry the label `fallbck.io/allow-db-credentials: "true"`, and a job that uses one has to name a Service, not a host. The agent can read every Secret in the cluster, so this label is what keeps a database job from shipping any other Secret somewhere else,
- optionally a tools-image override.

Each run starts a dump pod in that namespace. The main container is the **engine's own image** (`postgres:<major>`, `mariadb:<major>`, `mysql:<major>`, `mongo:<major>`), and an init container drops the agent binary into it. The agent probes the server version to pick the tag, so `pg_dump` always matches. MongoDB can't be probed and uses `latest`. The dump spools to an emptyDir (`worker.db.spoolSizeLimit`) and uploads exactly like a [regular DB backup](databases.md#what-lands-on-pbs).

WAL/binlog chain state is kept per job in the `stateSecretName` Secret, so continuation works across runs. Credential profiles and TLS cert files aren't available for in-cluster targets.

## Security, the honest version

- The ClusterRole reads **everything, Secrets included**. That's what a DR backup needs. It can also create pods, PVCs, VolumeSnapshots and Secrets cluster-wide, because workers have to run in each volume's namespace.
- Worker pods get their short-lived credentials (2h ticket, 6h token) from a per-run Secret in their namespace, not from `Pod.spec`, and have no Kubernetes API access. The Secret is deleted with the pod.
- A database job may only read Secrets labelled `fallbck.io/allow-db-credentials: "true"`, and only to reach a Service in the same namespace.

## Restore

It's manual:

```bash
proxmox-backup-client restore host/k8s-<cluster>/<time> resources.pxar ./out
# kubectl apply in the order the manifest describes
```

For each volume, restore `pvc.pxar` from its group into a pod that mounts the recreated PVC.
