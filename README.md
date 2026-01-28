# Virus Scanner Request Handler

## Overview

このコンポーネントは、Redisキューからウイルススキャンタスクを取得し、Pod内の ClamAV (clamd) サイドカーへリクエストを転送する **Request Handler** です。

## Role

- **Task Retrieval**: Redisの `scan_priority` および `scan_normal` キューを監視します。
- **ClamAV Proxy**: 取得したタスクに含まれるファイルパスを clamd ネットワークソケット経由でスキャン依頼します。
- **Result Logging**: スキャン結果（感染の有無、詳細、実行時間）を構造化ログとして出力します。

## Setup

- Pod内では ClamAV コンテナと同一ネットワーク空間（localhost）で通信します。
- スキャン対象のファイルは共有されたボリュームを通じて読み取ります。
