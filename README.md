# F5 Mock

A simple mock of F5 configuration APIs.

As of now, this is centered around certificate handling for Client SSL profiles, on both AS3 and IControl APIs.

## Installation

This is distributed through a docker image.

    docker run ghcr.io/iilun/f5-mock:latest

## Configuration

Parameters are given through env variables.

| Parameter name       | Default              | Description                                    |
|----------------------|----------------------|------------------------------------------------|
| F5_DEBUG             | false                | Enable debug logs                              |
| F5_SEED_FILE         |                      | Path to a seed file. See [seeding](#seeding)   |
| F5_CERT_PATH         | /etc/ssl/f5/cert.pem | Path to the server certificate                 |
| F5_KEY_PATH          | /etc/ssl/f5/cert.pem | Path to the server certificate key             |
| F5_PORT              | 443                  | Port to listen on                              |
| F5_HOST              | *                    | Host to listen on                              |
| F5_LOGIN_PROVIDER    |                      | External login provider to use                 |
| F5_ADMIN_USERNAME    | admin                | Administrator username                         |
| F5_ADMIN_PASSWORD    | password             | Administrator password                         |
| F5_DEFAULT_PARTITION |                      | Default partition to use when routing requests |

## Seeding

A file to seed data on startup can be given. Here is an example of the contents

```yaml
client_ssl_profiles:
  - name: A1
    partition: Sample_02
    cert: newCert22
    key: key1.pem
    cert_key_chain:
      - name: chain1
        cert: chain-cert1.pem
        key: chain-key1.pem
      - name: chain2
        cert: chain-cert2.pem
        key: chain-key2.pem

  - name: profile2
    partition: Common
    cert: cert2.pem
    key: key2.pem
```