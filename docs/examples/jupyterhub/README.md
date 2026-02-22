# JupyterHub Egress Integration with Virus Scanner

JupyterHubからデプロイされるEgress Gatewayにおいて、Virus Scanner (External Processing) を有効にするための設定例です。

## 修正のポイント

一部のEnvoyバージョンでは `ext_proc` フィルタの `processing_timeout` フィールドがサポートされていない、あるいはスキーマ定義が異なるために `INVALID_ARGUMENT` エラーでPodが起動しない場合があります。

本サンプルでは、安定性のために `processing_timeout` を除外し、基本的な `ext_proc` 設定のみを記述しています。

## 設定ファイルの適用

`envoy-config.yaml` の内容を、JupyterHubが管理する ConfigMap または Helm テンプレートに反映してください。

### 主要な設定項目

- **grpc_service**: Virus Scanner Producer の gRPC 端点を指定します。
- **failure_mode_allow**: `true` に設定することで、スキャナーが一時的に停止していても通信を遮断しない（フェイルオープン）設定になります。
- **processing_mode**: リクエスト/レスポンスのボディ全体をバッファリングしてスキャンするために `BUFFERED` を指定しています。
