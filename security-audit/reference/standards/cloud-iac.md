# Module: cloud-iac - CIS Benchmarks, OWASP Kubernetes Top 10 2025, containers

Apply to Terraform/OpenTofu, CloudFormation/SAM/CDK (synth output), Bicep/ARM, Pulumi, Kubernetes
manifests/Helm, Dockerfiles, docker-compose, serverless configs, Wrangler. Cite
`CIS AWS Foundations v7.1.0 <rec>`, `CIS Azure Foundations v6.0.0`, `CIS GCP Foundations v5.0.0`,
`CIS Kubernetes v2.1.0` (CIS-CAT lists 2.0.1 - note it), `CIS EKS / AKS / GKE v2.0.0` for managed
clusters, `CIS Docker v1.9.0`, `OWASP Non-Human Identities Top 10 2025` for workload identities,
`OWASP Kubernetes Top 10 2025 K0x`. Scanner: Checkov (+ Trivy misconfig) - findings carry a
`CKV_*` / `AVD-*` ID; map them to the CIS recommendation when the scanner provides it, else cite the
control family. Recommendation numbers shift between CIS versions - never copy a number from an older
benchmark. Checkov does not emit CIS numbers: cite the benchmark + version + control theme
(e.g. `CIS AWS Foundations v7.1.0 - storage: S3 public access`) plus the `CKV_*` id, never an invented number.

## Contents
- IaC is design-time evidence only
- Cloud checks (provider-agnostic, with AWS/Azure/GCP hints)
- Kubernetes (OWASP K8s Top 10 2025)
- Containers (Dockerfile / compose)
- Cross-repo drift

## IaC is design-time evidence only
IaC shows what *would* be deployed. Console changes, other repos, and drift are invisible. State it.
Reachability matters: a public bucket holding public assets is Info; one holding exports is P0.

## Cloud checks

| Area | What to verify | Hints (AWS / Azure / GCP) |
|------|----------------|---------------------------|
| Identity | No wildcard admin policies for workloads; no long-lived user access keys for CI (use OIDC federation); MFA on root/break-glass; no inline `*:*` | `"Action": "*"`, `aws_iam_access_key`, `AdministratorAccess` on roles; Azure Owner at subscription scope; GCP `roles/owner` / primitive roles, SA keys |
| Storage exposure | Buckets/blobs private by default, public-access block on, encryption at rest (KMS/CMK for sensitive), versioning + object lock where integrity matters | `aws_s3_bucket_public_access_block`, `acl = "public-read"`; `allow_blob_public_access`; `allUsers` IAM bindings |
| Data stores | Databases not publicly accessible, encrypted, backups encrypted, deletion protection, TLS required | `publicly_accessible = true`, `storage_encrypted = false`, `require_secure_transport` |
| Network | No 0.0.0.0/0 on admin ports (22, 3389, DB ports); private subnets for data tiers; egress restricted for app tiers (a compromised server must not download payloads, join a DDoS or reach C2) | security groups (`sg-egress-any`), NSGs, firewall rules, NetworkPolicy (`k8s-no-networkpolicy`) |
| Logging | CloudTrail/Activity Log/Audit Logs on, multi-region, log-file validation, retention; flow logs on sensitive VPCs | `aws_cloudtrail`, `is_multi_region_trail`, diagnostic settings |
| Secrets | No secrets in IaC variables/defaults, user-data, task definitions, or state files committed; use Secrets Manager / Key Vault / Secret Manager | `default = "..."` on secret vars, `environment` blocks with keys, `*.tfstate` in git |
| Key management | KMS key rotation enabled; key policies least-privilege | `enable_key_rotation` |
| Compute | IMDSv2 required; no public IPs on internal instances; serverless functions least-privilege and with reserved concurrency for cost-bearing paths | `http_tokens = "required"`, `associate_public_ip_address` |
| Edge | TLS >= 1.2, HSTS, WAF on public apps, origin not directly reachable | CloudFront/ALB/App Gateway/Front Door config |

## Kubernetes - OWASP Kubernetes Top 10 2025

| ID | Risk | What to verify in manifests/Helm |
|----|------|----------------------------------|
| K01 | Insecure Workload Configurations | `runAsNonRoot`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, drop capabilities, no `privileged`, no `hostPath`/`hostNetwork`/`hostPID`, resource limits |
| K02 | Overly Permissive Authorization Configurations | RBAC: no `cluster-admin` bindings for apps, no `*` verbs/resources, no default SA token automount where unneeded |
| K03 | Secrets Management Failures | Secrets not in plain ConfigMaps/manifests/values.yaml; external secrets / sealed secrets; encryption at rest |
| K04 | Lack of Cluster Level Policy Enforcement | Pod Security Admission labels / Kyverno / Gatekeeper policies present |
| K05 | Missing Network Segmentation Controls | NetworkPolicies default-deny per namespace |
| K06 | Overly Exposed Kubernetes Components | Dashboard, kubelet, etcd, API server not exposed publicly; `LoadBalancer` services intended |
| K07 | Misconfigured and Vulnerable Cluster Components | Pinned, supported versions of ingress controllers, CNI, operators |
| K08 | Cluster to Cloud Lateral Movement | Workload identity (IRSA / Workload Identity) scoped; node IAM roles minimal; metadata access restricted |
| K09 | Broken Authentication Mechanisms | No static tokens/client certs in repo; OIDC for humans |
| K10 | Inadequate Logging and Monitoring | Audit logging enabled; runtime detection |

## Containers (Dockerfile / compose) - CIS Docker v1.9.0 section 4 themes
- Base images pinned by digest (or at least exact tag), minimal (distroless/slim), from trusted registries.
- Non-root `USER`; no secrets in `ENV`/`ARG`/`COPY` (they persist in layers - committed = compromised).
- No `curl | sh` without checksum; `ADD` from URLs avoided; `HEALTHCHECK` present (Info).
- compose: no `privileged: true`, no Docker socket mounts (`/var/run/docker.sock` = host root), no
  default DB passwords, `no-new-privileges`.
- Exposure: datastores (`5432`, `3306`, `6379`, `27017`, `9200`) not published on all interfaces;
  admin / BI tools (Metabase, Grafana, Kibana, phpMyAdmin, Adminer, Jenkins) not reachable from
  outside without auth (`platform.md` signals `datastore-port-published`, `admin-tool-image`).
- Blast radius: runtime image without shell / download tools (`download-tools-in-runtime-image`),
  read-only root filesystem, `.dockerignore` excludes `.env*`, `.git` and keys before `COPY . .`.
- Patch level: base images at a supported cycle and current patch (`intel.md`), digest-pinned with
  automated updates (Renovate / Dependabot `docker`) or a scheduled rebuild.

## Cross-repo drift
Compare deploy pipelines, IaC, and what the app expects (hostnames, buckets, queues). A host deployed
by CI but absent from IaC, or two pipelines deploying the same service differently, is a finding
(CICD-SEC-1/7, see `reference/standards/supply-chain.md`).
