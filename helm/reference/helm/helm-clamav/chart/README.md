# ClamAV Helm Chart

![Pipeline status](https://gitlab.com/xrow-public/helm-clamav/badges/main/pipeline.svg?ignore_skipped=true)
![Current release](https://gitlab.com/xrow-public/helm-clamav/-/badges/release.svg)
[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/clamav)](https://artifacthub.io/packages/search?repo=clamav)

The ClamAV Helm Chart provides a convenient way to deploy ClamAV, an open-source antivirus engine, on a Kubernetes cluster. This chart allows users to easily configure and manage ClamAV instances for scanning files and directories for viruses, malware, and other malicious threats. It includes features for customizing the ClamAV configuration, updating virus definitions, and integrating with other services within the Kubernetes ecosystem.

Features

* Scan files via a ClamAV server over network
* Daily updates for virus definitions via the always up to date image (tag `latest` from repository).

## Install

```bash
helm upgrade --install clamav oci://registry.gitlab.com/xrow-public/helm-clamav/charts/clamav \
  --version $CI_DOCUMENTATION_LATEST_TAG \
  --create-namespace \
  -n clamav 
```

## Test

Includes a test on a sample test virus signature. 

```bash
helm test clamav
```

## Use with container a engine

### Podman or Docker
```bash
podman run --replace --network bridge -it --name clamav -p 3310:3310 registry.gitlab.com/xrow-public/helm-clamav/clamav:latest
```

### Docker compose
```yaml
clamav:
    image: ${CLAMAV_IMAGE:-registry.gitlab.com/xrow-public/helm-clamav/clamav:latest}
    ports:
      - ${CLAMAV_PORT:-3310}:3310
```

## Integration examples

### PHP

[Complete example script](https://gitlab.com/xrow-public/helm-clamav/-/tree/main/container/test?ref_type=heads)

```php
<?php

use Appwrite\ClamAV\Network;

$host = 'clamav';
$clam = new Network( $host, 3310);
$clam->fileScanInStream(__FILE__);
```