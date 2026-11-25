# Helm chart

The chart for [`fallbck-k8s-agent`](../agents/kubernetes.md) is published to the Helm repository at `https://helm.osshield.eu` with every release (`helm repo add osshield https://helm.osshield.eu`, then `osshield/fallbck-k8s-agent`). The source is in [`deploy/helm/fallbck-k8s-agent`](https://github.com/osshield/fallbck/tree/main/deploy/helm/fallbck-k8s-agent). You **have to** set `server.url`, `clusterName` and an enrollment key. Everything else has a sane default.

## Connection and identity

| Value | Default | What it does |
|---|---|---|
| `server.url` | | Server (reverse proxy) URL. **Required.** |
| `server.caCert` | | Inline PEM of a private CA. Used by the agent and its worker pods. |
| `server.insecureSkipVerify` | `false` | Testing only. |
| `clusterName` | | **Required.** The agent shows up as `k8s-<clusterName>` and its PBS groups get the prefix `host/k8s-<clusterName>`. |
| `enrollment.key` | | One-time token. Ignored once enrolled. |
| `enrollment.existingSecret` | | Or point at a Secret with key `enrollment-key`. |
| `identitySecretName` | `fallbck-k8s-agent-identity` | Owned by the agent. Upgrades and uninstalls leave it alone. Delete it to re-enroll. |
| `stateSecretName` | `fallbck-k8s-agent-state` | Per-job WAL/binlog chain state for DB jobs. |

## Agent pod

| Value | Default | What it does |
|---|---|---|
| `image.repository` | `cr.osshield.eu/fallbck/k8s-agent` | |
| `image.tag` | `latest` | Pin this to your server's version. |
| `image.pullPolicy` | `Always` | |
| `resources` | 100m / 256Mi, limit 1Gi | |
| `spool.sizeLimit` | `2Gi` | emptyDir for the resource dump. |
| `spool.existingClaim` | | Use a PVC instead. |
| `logLevel` | `info` | |
| `nodeSelector`, `tolerations`, `affinity`, `priorityClassName` | | The usual. |

## Volume worker pods

One per volume, in the volume's namespace.

| Value | Default | What it does |
|---|---|---|
| `worker.image` | the agent image | |
| `worker.pullPolicy` | `Always` | |
| `worker.resources` | 100m / 256Mi, limit 2Gi | |
| `worker.maxProcs` | `2` | Caps upload concurrency (`GOMAXPROCS`). Without it, peak memory grows with the node's CPU count and big volumes get OOM-killed. Only raise it together with the memory limit. |
| `worker.securityContext` | root, all caps dropped except `DAC_OVERRIDE`, read-only rootfs | Passes Pod Security `baseline`. Leave it empty: setting it applies to every namespace and turns off the `restricted` fallback below. |

In a `restricted` namespace the root worker gets rejected, so the agent retries as the app's own user. See [Restricted namespaces](../agents/kubernetes.md#restricted-namespaces).

## Database dump pods

| Value | Default | What it does |
|---|---|---|
| `worker.db.images.postgres` | `postgres:{major}` | `{major}` gets replaced with the detected server version. |
| `worker.db.images.mysql` | `mysql:{major}` | |
| `worker.db.images.mariadb` | `mariadb:{major}` | |
| `worker.db.images.mongodb` | `mongo:{major}` | MongoDB can't be probed, so it ends up as `latest`. |
| `worker.db.spoolSizeLimit` | `20Gi` | Size it for your biggest dump. |
| `worker.db.resources` | 100m / 256Mi, limit 2Gi | |
| `worker.db.securityContext` | uid/gid 999, all caps dropped, read-only rootfs, `RuntimeDefault` seccomp | Passes Pod Security `restricted`. 999 is the engine user in the official images. |

A job can also pin its own image with its *tools image* setting.

## Worker priority class

| Value | Default | What it does |
|---|---|---|
| `workerPriorityClass.create` | `true` | Creates the PriorityClass. It's cluster-scoped, so a second agent release in the same cluster sets this to `false`. |
| `workerPriorityClass.name` | `fallbck-backup` | Set on every volume worker and dump pod. Empty means no priority class at all. |

It has value 0 and `preemptionPolicy: Never`, so workers get no scheduling edge. It's there so your cluster policy can pick out our pods. The usual case is a namespace ResourceQuota that would otherwise demand `limits.cpu` and squeeze workers into the site's leftover budget:

```yaml
spec:
  hard: {limits.cpu: "4", limits.memory: 4Gi}
  scopeSelector:
    matchExpressions:
      - {scopeName: PriorityClass, operator: NotIn, values: [fallbck-backup]}
```

Pods without a priority class still count, so the quota keeps working for everything else. Kyverno and Gatekeeper exclusions can match on `spec.priorityClassName` the same way. Heads-up: nothing stops other pods from naming the class too, so anything that sets it skips that quota as well.

## Admission policy

| Value | Default | What it does |
|---|---|---|
| `admissionPolicy.enabled` | `false` | Installs a `ValidatingAdmissionPolicy` (Kubernetes 1.30+) that limits the pods the agent's service account can create to what workers need. Turn it on if you exempt the agent from Pod Security admission. |
