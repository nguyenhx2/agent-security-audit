# モジュール：cloud-iac - CIS Benchmarks、OWASP Kubernetes Top 10 2025、コンテナ

Terraform/OpenTofu、CloudFormation/SAM/CDK（synth 出力）、Bicep/ARM、Pulumi、Kubernetes
マニフェスト/Helm、Dockerfile、docker-compose、サーバーレス設定、Wrangler に適用する。引用：
`CIS AWS Foundations v7.1.0 <rec>`、`CIS Azure Foundations v6.0.0`、`CIS GCP Foundations v5.0.0`、
`CIS Kubernetes v2.1.0`（CIS-CAT の掲載は 2.0.1 - その旨を記載）、マネージドクラスタには `CIS EKS / AKS / GKE v2.0.0`、
`CIS Docker v1.9.0`、ワークロードアイデンティティには `OWASP Non-Human Identities Top 10 2025`、
`OWASP Kubernetes Top 10 2025 K0x`。スキャナ：Checkov（+ Trivy misconfig）- 指摘事項は
`CKV_*` / `AVD-*` の ID を持つ。スキャナが CIS 推奨事項を提供する場合はそれに対応付け、提供しない場合は
コントロールファミリーを引用する。推奨事項の番号は CIS のバージョン間で変わる - 古い
ベンチマークの番号を決して流用しない。Checkov は CIS 番号を出力しない：ベンチマーク + バージョン + コントロールのテーマ
（例：`CIS AWS Foundations v7.1.0 - storage: S3 public access`）に `CKV_*` の id を添えて引用し、番号を捏造しない。

## 目次
- IaC は設計時の根拠にすぎない
- クラウドのチェック（プロバイダ非依存、AWS/Azure/GCP のヒント付き）
- Kubernetes（OWASP K8s Top 10 2025）
- コンテナ（Dockerfile / compose）
- リポジトリ間のドリフト

## IaC は設計時の根拠にすぎない
IaC が示すのはデプロイされる「はず」のものである。コンソールでの変更、他のリポジトリ、ドリフトは見えない。その旨を明記する。
到達可能性が重要：公開資産を置いた公開バケットは Info、エクスポートデータを置いたものは P0。

## クラウドのチェック

| 領域 | 検証内容 | ヒント（AWS / Azure / GCP） |
|------|----------------|---------------------------|
| アイデンティティ | ワークロードにワイルドカードの管理者ポリシーがない。CI に長期有効なユーザーアクセスキーがない（OIDC フェデレーションを使用）。root/緊急用アカウントに MFA。インラインの `*:*` がない | `"Action": "*"`、`aws_iam_access_key`、ロールへの `AdministratorAccess`。Azure のサブスクリプションスコープの Owner。GCP の `roles/owner` / 基本ロール、SA キー |
| ストレージの露出 | バケット/BLOB が既定で非公開、パブリックアクセスブロック有効、保存時暗号化（機微データには KMS/CMK）、整合性が重要な箇所ではバージョニング + オブジェクトロック | `aws_s3_bucket_public_access_block`、`acl = "public-read"`。`allow_blob_public_access`。`allUsers` の IAM バインディング |
| データストア | データベースが公開アクセス不可、暗号化、バックアップの暗号化、削除保護、TLS 必須 | `publicly_accessible = true`、`storage_encrypted = false`、`require_secure_transport` |
| ネットワーク | 管理ポート（22、3389、DB ポート）に 0.0.0.0/0 を許可しない。データ層はプライベートサブネット。アプリ層の外向き通信を制限する（侵害されたサーバーがペイロードをダウンロードしたり、DDoS に加担したり、C2 に到達したりしてはならない） | セキュリティグループ（`sg-egress-any`）、NSG、ファイアウォールルール、NetworkPolicy（`k8s-no-networkpolicy`） |
| ロギング | CloudTrail/Activity Log/Audit Logs が有効、マルチリージョン、ログファイル検証、保持期間。機微な VPC ではフローログ | `aws_cloudtrail`、`is_multi_region_trail`、診断設定 |
| シークレット | IaC の変数/既定値、user-data、タスク定義、コミットされた state ファイルにシークレットがない。Secrets Manager / Key Vault / Secret Manager を使用 | シークレット変数の `default = "..."`、キーを含む `environment` ブロック、git 内の `*.tfstate` |
| 鍵管理 | KMS 鍵のローテーションが有効。キーポリシーは最小権限 | `enable_key_rotation` |
| コンピュート | IMDSv2 必須。内部インスタンスにパブリック IP がない。サーバーレス関数は最小権限で、コストの発生する経路には予約済み同時実行数を設定 | `http_tokens = "required"`、`associate_public_ip_address` |
| エッジ | TLS >= 1.2、HSTS、公開アプリに WAF、オリジンに直接到達できない | CloudFront/ALB/App Gateway/Front Door の設定 |

## Kubernetes - OWASP Kubernetes Top 10 2025

| ID | リスク | マニフェスト/Helm で検証する内容 |
|----|------|----------------------------------|
| K01 | Insecure Workload Configurations | `runAsNonRoot`、`readOnlyRootFilesystem`、`allowPrivilegeEscalation: false`、capabilities の削除、`privileged` なし、`hostPath`/`hostNetwork`/`hostPID` なし、リソース制限 |
| K02 | Overly Permissive Authorization Configurations | RBAC：アプリに `cluster-admin` バインディングがない、`*` の verbs/resources がない、不要な箇所で既定 SA トークンを自動マウントしない |
| K03 | Secrets Management Failures | シークレットが平文の ConfigMap/マニフェスト/values.yaml にない。external secrets / sealed secrets。保存時暗号化 |
| K04 | Lack of Cluster Level Policy Enforcement | Pod Security Admission のラベル / Kyverno / Gatekeeper のポリシーが存在 |
| K05 | Missing Network Segmentation Controls | namespace ごとに既定拒否の NetworkPolicy |
| K06 | Overly Exposed Kubernetes Components | Dashboard、kubelet、etcd、API サーバーが公開されていない。`LoadBalancer` サービスが意図したものである |
| K07 | Misconfigured and Vulnerable Cluster Components | Ingress コントローラー、CNI、オペレーターが固定（ピン留め）されたサポート対象バージョン |
| K08 | Cluster to Cloud Lateral Movement | ワークロードアイデンティティ（IRSA / Workload Identity）の範囲が限定。ノードの IAM ロールが最小限。メタデータへのアクセスを制限 |
| K09 | Broken Authentication Mechanisms | リポジトリに静的トークン/クライアント証明書がない。人間には OIDC |
| K10 | Inadequate Logging and Monitoring | 監査ログが有効。ランタイム検知 |

## コンテナ（Dockerfile / compose）- CIS Docker v1.9.0 セクション 4 のテーマ
- ベースイメージはダイジェストで固定（少なくとも正確なタグ）、最小構成（distroless/slim）、信頼できるレジストリから取得。
- root 以外の `USER`。`ENV`/`ARG`/`COPY` にシークレットを入れない（レイヤーに残る - コミット済み = 漏えい済み）。
- チェックサムなしの `curl | sh` を使わない。URL からの `ADD` を避ける。`HEALTHCHECK` がある（Info）。
- compose：`privileged: true` なし、Docker ソケットのマウントなし（`/var/run/docker.sock` = ホストの root）、
  既定の DB パスワードなし、`no-new-privileges`。
- 露出：データストア（`5432`、`3306`、`6379`、`27017`、`9200`）をすべてのインターフェースで公開しない。
  管理 / BI ツール（Metabase、Grafana、Kibana、phpMyAdmin、Adminer、Jenkins）に外部から認証なしで到達できない
  （`platform.md` のシグナル `datastore-port-published`、`admin-tool-image`）。
- 侵害時の影響範囲：実行イメージにシェル / ダウンロードツールがない（`download-tools-in-runtime-image`）、
  ルートファイルシステムが読み取り専用、`COPY . .` の前に `.dockerignore` で `.env*`、`.git`、鍵を除外する。
- パッチ適用状況：ベースイメージがサポート中のサイクルの最新パッチである（`intel.md`）。ダイジェストで固定し、
  自動更新（Renovate / Dependabot の `docker`）または定期的な再ビルドを行う。

## リポジトリ間のドリフト
デプロイパイプライン、IaC、アプリが前提とするもの（ホスト名、バケット、キュー）を比較する。CI でデプロイされているのに
IaC に存在しないホストや、同じサービスを異なる方法でデプロイする 2 本のパイプラインは指摘事項となる
（CICD-SEC-1/7、`reference/standards/supply-chain.md` を参照）。
