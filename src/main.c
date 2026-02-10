#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *endpoint_url;
    const char *access_key;
    const char *secret_key;
} s3_config_t;

int s3_list_files(const s3_config_t *config, const char *path) {
    printf("Listing files in: %s\n", path);
    // TODO: Implement S3 list operation
    return 0;
}

int s3_put_file(const s3_config_t *config, const char *local_path, const char *remote_path) {
    printf("Uploading %s to %s\n", local_path, remote_path);
    // TODO: Implement S3 put operation
    return 0;
}

int s3_get_file(const s3_config_t *config, const char *remote_path, const char *local_path) {
    if (local_path) {
        printf("Downloading %s to %s\n", remote_path, local_path);
    } else {
        printf("Downloading %s to current directory\n", remote_path);
    }
    // TODO: Implement S3 get operation
    return 0;
}

void print_diagnostics(const s3_config_t *config) {
    printf("S3 Configuration Diagnostics:\n");
    printf("  Endpoint URL: %s\n", config->endpoint_url);
    printf("  Access Key: %s\n", config->access_key);
    printf("  Secret Key: %s\n", config->secret_key);
}

void print_usage(const char *program_name) {
    fprintf(stderr, "Usage: %s <command> [args]\n", program_name);
    fprintf(stderr, "Commands:\n");
    fprintf(stderr, "  ls <path>              List files in S3 path\n");
    fprintf(stderr, "  put <local> <remote>   Upload local file to S3\n");
    fprintf(stderr, "  get <remote> [local]   Download file from S3\n");
    fprintf(stderr, "  diag                   Print configuration diagnostics\n");
}

int main(int argc, char **argv)
{
    const char *bucket_endpoint_url = getenv("S3_BUCKET_ENDPOINT_URL");
    const char *access_key = getenv("S3_ACCESS_KEY");
    const char *secret_key = getenv("S3_SECRET_KEY");

    if (!bucket_endpoint_url || !access_key || !secret_key) {
        fprintf(stderr, "Error: Missing required environment variables:\n");
        if (!bucket_endpoint_url) fprintf(stderr, "  - S3_BUCKET_ENDPOINT_URL\n");
        if (!access_key) fprintf(stderr, "  - S3_ACCESS_KEY\n");
        if (!secret_key) fprintf(stderr, "  - S3_SECRET_KEY\n");
        return 1;
    }

    s3_config_t config = {
        .endpoint_url = bucket_endpoint_url,
        .access_key = access_key,
        .secret_key = secret_key
    };

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *command = argv[1];

    if (strcmp(command, "ls") == 0) {
        if (argc != 3) {
            fprintf(stderr, "Usage: %s ls <path>\n", argv[0]);
            return 1;
        }
        return s3_list_files(&config, argv[2]);
    } else if (strcmp(command, "put") == 0) {
        if (argc != 4) {
            fprintf(stderr, "Usage: %s put <local_path> <remote_path>\n", argv[0]);
            return 1;
        }
        return s3_put_file(&config, argv[2], argv[3]);
    } else if (strcmp(command, "get") == 0) {
        if (argc < 3 || argc > 4) {
            fprintf(stderr, "Usage: %s get <remote_path> [local_path]\n", argv[0]);
            return 1;
        }
        const char *local_path = (argc == 4) ? argv[3] : NULL;
        return s3_get_file(&config, argv[2], local_path);
    } else if (strcmp(command, "diag") == 0) {
        if (argc != 2) {
            fprintf(stderr, "Usage: %s diag\n", argv[0]);
            return 1;
        }
        print_diagnostics(&config);
        return 0;
    } else {
        fprintf(stderr, "Unknown command: %s\n", command);
        print_usage(argv[0]);
        return 1;
    }
}