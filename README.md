# sps3c

A lightweight, static C client for S3-compatible storage services.

## Overview

`sps3c` (Simple S3 Client) is a minimal command-line tool for interacting with S3-compatible object storage services. It provides a simple interface for listing, uploading, and downloading files with AWS Signature Version 4 authentication.

## Features

- **AWS Signature Version 4 Authentication** - Full support for AWS S3 authentication
- **Dual Bucket Addressing Styles** - Supports both domain-style and path-style bucket addressing
- **Environment Variable Configuration** - Easy configuration via environment variables
- **Static Binary** - Produces a statically linked executable for easy deployment

## Building

### Prerequisites

- CMake 3.18 or higher
- C compiler with C99 support
- Git (for submodules)

### Build Steps

```bash
# Clone the repository with submodules
git clone --recurse-submodules <repository-url>
cd sps3c

# Build the project
mkdir build && cd build
cmake ..
make

# The binary will be available at build/sps3c
```

## Configuration

Configure `sps3c` using environment variables:

| Variable | Required | Description | Default |
|----------|----------|-------------|---------|
| `SPS3_ENDPOINT_URL` | Yes | S3 endpoint URL (e.g., `s3.amazonaws.com` or `minio.example.com`) | - |
| `SPS3_BUCKET_NAME` | Yes | Name of the S3 bucket | - |
| `SPS3_BUCKET_STYLE` | No | Bucket addressing style: `domain` or `path` | `path` |
| `SPS3_ACCESS_KEY` | Yes | Access key ID | - |
| `SPS3_SECRET_KEY` | Yes | Secret access key | - |
| `SPS3_SESSION_TOKEN` | No | AWS session token (for temporary credentials) | - |
| `SPS3_CERT_BUNDLE` | No | Path to custom CA certificate bundle | Embedded certs |
| `SPS3_DEBUG` | No | Enable debug output (set to any non-zero value) | Disabled |

### Bucket Addressing Styles

- **Domain Style**: `bucket.endpoint.com` - Used by AWS S3 and most S3-compatible services
- **Path Style**: `endpoint.com/bucket` - Used by some S3-compatible services

## Usage

```bash
sps3c <command> [args]
```

### Commands

#### List Files

List files and directories in an S3 path:

```bash
sps3c ls <path>
```

Examples:
```bash
# List root directory
sps3c ls /

# List a specific directory
sps3c ls /photos

# List nested directory
sps3c ls /photos/2024
```

#### Upload File

Upload a local file to S3:

```bash
sps3c put <local_path> <remote_path>
```

Example:
```bash
sps3c put ./myfile.txt /documents/myfile.txt
```

> **Note**: This feature is currently a placeholder and not fully implemented.

#### Download File

Download a file from S3:

```bash
sps3c get <remote_path> [local_path]
```

Examples:
```bash
# Download to current directory with original filename
sps3c get /documents/myfile.txt

# Download to specific path
sps3c get /documents/myfile.txt ./downloaded.txt
```

> **Note**: This feature is currently a placeholder and not fully implemented.

#### Diagnostics

Print current configuration for troubleshooting:

```bash
sps3c diag
```

## Examples

### AWS S3

```bash
export SPS3_ENDPOINT_URL="s3.amazonaws.com"
export SPS3_BUCKET_NAME="my-bucket"
export SPS3_BUCKET_STYLE="domain"
export SPS3_ACCESS_KEY="AKIAIOSFODNN7EXAMPLE"
export SPS3_SECRET_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

sps3c ls /
```

### MinIO

```bash
export SPS3_ENDPOINT_URL="minio.example.com"
export SPS3_BUCKET_NAME="my-bucket"
export SPS3_BUCKET_STYLE="path"
export SPS3_ACCESS_KEY="minioadmin"
export SPS3_SECRET_KEY="minioadmin"

sps3c ls /
```

### With Debug Output

```bash
export SPS3_DEBUG=1
sps3c ls /
```

### With Custom CA Certificate

```bash
export SPS3_CERT_BUNDLE="/etc/ssl/certs/ca-certificates.crt"
sps3c ls /
```

### With Temporary Credentials

```bash
export SPS3_ENDPOINT_URL="s3.amazonaws.com"
export SPS3_BUCKET_NAME="my-bucket"
export SPS3_ACCESS_KEY="ASIAIOSFODNN7EXAMPLE"
export SPS3_SECRET_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
export SPS3_SESSION_TOKEN="FwoGZXIvYXdzEGMaDNu5EXAMPLE/SESSION_TOKEN"

sps3c ls /
```

## Dependencies

- **MbedTLS** - Cryptography library for TLS and SHA-256/HMAC operations
- **Mongoose** - Embedded HTTP client library
- **Expat** - XML parsing library for S3 list responses

## License

This project is licensed under the GNU General Public License v2.0. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## Roadmap

- [ ] Complete `put` command implementation
- [ ] Complete `get` command implementation
- [ ] Add `rm` command for deleting files
- [ ] Add `cp` command for copying files
- [ ] Add `sync` command for directory synchronization
- [ ] Add multipart upload support for large files
- [ ] Add progress indicators for transfers
