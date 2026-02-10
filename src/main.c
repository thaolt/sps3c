#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <expat.h>
#include "mongoose.h"
#include "mbedtls/sha256.h"
#include "mbedtls/md.h"

typedef struct {
    const char *endpoint_url;
    const char *bucket_name;
    const char *bucket_style;  // "domain" or "path"
    const char *access_key;
    const char *secret_key;
    const char *session_token;
} s3_config_t;

// Helper function for HMAC-SHA256
static int hmac_sha256(const char *key, size_t key_len, const char *data, size_t data_len, 
                      unsigned char *output) {
    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    
    mbedtls_md_init(&ctx);
    if (mbedtls_md_setup(&ctx, md_info, 1) != 0) {
        mbedtls_md_free(&ctx);
        return -1;
    }
    
    if (mbedtls_md_hmac_starts(&ctx, (const unsigned char *)key, key_len) != 0 ||
        mbedtls_md_hmac_update(&ctx, (const unsigned char *)data, data_len) != 0 ||
        mbedtls_md_hmac_finish(&ctx, output) != 0) {
        mbedtls_md_free(&ctx);
        return -1;
    }
    
    mbedtls_md_free(&ctx);
    return 0;
}

// Helper function for SHA256
static void sha256_hash(const char *data, size_t data_len, unsigned char *output) {
    mbedtls_sha256((const unsigned char *)data, data_len, output, 0);
}

// Convert hex to string
static void hex_to_string(const unsigned char *hash, size_t len, char *output) {
    const char *hex_chars = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        output[i * 2] = hex_chars[hash[i] >> 4];
        output[i * 2 + 1] = hex_chars[hash[i] & 0x0F];
    }
    output[len * 2] = '\0';
}

// Simple URL encoding function
static void url_encode(const char *src, char *dest, size_t dest_size) {
    size_t i = 0, j = 0;
    while (src[i] && j < dest_size - 1) {
        if ((src[i] >= 'a' && src[i] <= 'z') || 
            (src[i] >= 'A' && src[i] <= 'Z') || 
            (src[i] >= '0' && src[i] <= '9') || 
            src[i] == '-' || src[i] == '_' || src[i] == '.' || src[i] == '~') {
            dest[j++] = src[i];
        } else {
            if (j + 3 < dest_size) {
                snprintf(dest + j, 4, "%%%02X", (unsigned char)src[i]);
                j += 3;
            }
        }
        i++;
    }
    dest[j] = '\0';
}

static int s3_debug_enabled(void) {
    const char *v = getenv("SPS3_DEBUG");
    return v && v[0] != '\0' && strcmp(v, "0") != 0;
}

static void canonical_uri_encode(const char *src, char *dest, size_t dest_size) {
    size_t i = 0, j = 0;
    while (src[i] && j < dest_size - 1) {
        if (src[i] == '/') {
            dest[j++] = '/';
        } else if ((src[i] >= 'a' && src[i] <= 'z') ||
                   (src[i] >= 'A' && src[i] <= 'Z') ||
                   (src[i] >= '0' && src[i] <= '9') ||
                   src[i] == '-' || src[i] == '_' || src[i] == '.' || src[i] == '~') {
            dest[j++] = src[i];
        } else {
            if (j + 3 < dest_size) {
                snprintf(dest + j, 4, "%%%02X", (unsigned char) src[i]);
                j += 3;
            }
        }
        i++;
    }
    dest[j] = '\0';
}

typedef struct {
    char key[128];
    char val[512];
} kv_pair_t;

static int from_hex(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static void url_decode(const char *src, char *dest, size_t dest_size) {
    size_t i = 0, j = 0;
    while (src[i] && j < dest_size - 1) {
        if (src[i] == '%' && src[i + 1] && src[i + 2]) {
            int hi = from_hex(src[i + 1]);
            int lo = from_hex(src[i + 2]);
            if (hi >= 0 && lo >= 0) {
                dest[j++] = (char) ((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        if (src[i] == '+') {
            dest[j++] = ' ';
        } else {
            dest[j++] = src[i];
        }
        i++;
    }
    dest[j] = '\0';
}

static int kv_pair_cmp(const void *a, const void *b) {
    const kv_pair_t *ka = (const kv_pair_t *) a;
    const kv_pair_t *kb = (const kv_pair_t *) b;
    int rc = strcmp(ka->key, kb->key);
    if (rc != 0) return rc;
    return strcmp(ka->val, kb->val);
}

static void build_canonical_query(const char *query, char *out, size_t out_size) {
    out[0] = '\0';
    if (query == NULL || query[0] == '\0') return;

    kv_pair_t pairs[32];
    size_t n = 0;

    const char *p = query;
    while (*p && n < (sizeof(pairs) / sizeof(pairs[0]))) {
        const char *amp = strchr(p, '&');
        size_t part_len = amp ? (size_t) (amp - p) : strlen(p);

        char part[1024];
        if (part_len >= sizeof(part)) part_len = sizeof(part) - 1;
        memcpy(part, p, part_len);
        part[part_len] = '\0';

        char *eq = strchr(part, '=');
        const char *k_raw = part;
        const char *v_raw = "";
        if (eq) {
            *eq = '\0';
            v_raw = eq + 1;
        }

        char k_dec[512], v_dec[1024];
        url_decode(k_raw, k_dec, sizeof(k_dec));
        url_decode(v_raw, v_dec, sizeof(v_dec));

        url_encode(k_dec, pairs[n].key, sizeof(pairs[n].key));
        url_encode(v_dec, pairs[n].val, sizeof(pairs[n].val));
        n++;

        if (!amp) break;
        p = amp + 1;
    }

    qsort(pairs, n, sizeof(pairs[0]), kv_pair_cmp);

    size_t j = 0;
    for (size_t i = 0; i < n; i++) {
        char piece[1024];
        snprintf(piece, sizeof(piece), "%s%s=%s", (i == 0) ? "" : "&", pairs[i].key, pairs[i].val);
        size_t need = strlen(piece);
        if (j + need >= out_size) break;
        memcpy(out + j, piece, need);
        j += need;
        out[j] = '\0';
    }
}

// Create AWS Signature Version 4 string
static char* create_aws_auth_header(const s3_config_t *config, const char *method, 
                                   const char *path, const char *host, const char *date_str,
                                   const char *timestamp) {
    const char *region = "us-east-1";  // Default region for S3-compatible services
    const char *service = "s3";
    
    // Extract query parameters from path
    char path_only[512], query_params[512];
    const char *query_start = strchr(path, '?');
    if (query_start) {
        size_t path_len = query_start - path;
        if (path_len >= sizeof(path_only)) path_len = sizeof(path_only) - 1;
        strncpy(path_only, path, path_len);
        path_only[path_len] = '\0';
        strncpy(query_params, query_start + 1, sizeof(query_params) - 1);
        query_params[sizeof(query_params) - 1] = '\0';
    } else {
        strncpy(path_only, path, sizeof(path_only) - 1);
        path_only[sizeof(path_only) - 1] = '\0';
        query_params[0] = '\0';
    }

    char canonical_uri[512];
    canonical_uri_encode(path_only, canonical_uri, sizeof(canonical_uri));

    char canonical_query[1024];
    build_canonical_query(query_params, canonical_query, sizeof(canonical_query));
    
    if (s3_debug_enabled()) printf("DEBUG: path_only='%s', query_params='%s'\n", path_only, query_params);
    
    // 1. Create canonical request
    char canonical_request[1024];
    if (config->session_token && config->session_token[0] != '\0') {
        snprintf(canonical_request, sizeof(canonical_request),
                 "%s\n%s\n%s\nhost:%s\nx-amz-content-sha256:UNSIGNED-PAYLOAD\nx-amz-date:%s\nx-amz-security-token:%s\n\nhost;x-amz-content-sha256;x-amz-date;x-amz-security-token\nUNSIGNED-PAYLOAD",
                 method, canonical_uri, canonical_query, host, timestamp, config->session_token);
    } else {
        snprintf(canonical_request, sizeof(canonical_request),
                 "%s\n%s\n%s\nhost:%s\nx-amz-content-sha256:UNSIGNED-PAYLOAD\nx-amz-date:%s\n\nhost;x-amz-content-sha256;x-amz-date\nUNSIGNED-PAYLOAD",
                 method, canonical_uri, canonical_query, host, timestamp);
    }
    
    if (s3_debug_enabled()) printf("DEBUG: Canonical Request:\n%s\n", canonical_request);
    
    // 2. Hash canonical request
    unsigned char canonical_hash[32];
    sha256_hash(canonical_request, strlen(canonical_request), canonical_hash);
    char canonical_hash_hex[65];
    hex_to_string(canonical_hash, 32, canonical_hash_hex);
    
    // 3. Create string to sign
    char string_to_sign[512];
    snprintf(string_to_sign, sizeof(string_to_sign),
             "AWS4-HMAC-SHA256\n%s\n%s/%s/%s/aws4_request\n%s",
             timestamp, date_str, region, service, canonical_hash_hex);
    
    // 4. Calculate signature
    // 4.1 Derive signing key
    char k_date[65], k_region[65], k_service[65], k_signing[65];
    unsigned char k_date_bin[32], k_region_bin[32], k_service_bin[32], k_signing_bin[32];
    
    // AWS4 secret key prefix
    char aws4_secret_key[128];
    snprintf(aws4_secret_key, sizeof(aws4_secret_key), "AWS4%s", config->secret_key);
    
    // kDate = HMAC_SHA256("AWS4" + SecretKey, Date)
    hmac_sha256(aws4_secret_key, strlen(aws4_secret_key), date_str, strlen(date_str), k_date_bin);
    hex_to_string(k_date_bin, 32, k_date);
    
    // kRegion = HMAC_SHA256(kDate, Region)
    hmac_sha256(k_date_bin, 32, region, strlen(region), k_region_bin);
    hex_to_string(k_region_bin, 32, k_region);
    
    // kService = HMAC_SHA256(kRegion, Service)
    hmac_sha256(k_region_bin, 32, service, strlen(service), k_service_bin);
    hex_to_string(k_service_bin, 32, k_service);
    
    // kSigning = HMAC_SHA256(kService, "aws4_request")
    hmac_sha256(k_service_bin, 32, "aws4_request", 12, k_signing_bin);
    hex_to_string(k_signing_bin, 32, k_signing);
    
    // 4.2 Calculate final signature
    unsigned char signature_bin[32];
    hmac_sha256(k_signing_bin, 32, string_to_sign, strlen(string_to_sign), signature_bin);
    char signature_hex[65];
    hex_to_string(signature_bin, 32, signature_hex);
    
    // 5. Create authorization header
    char *auth_header = malloc(512);
    if (config->session_token && config->session_token[0] != '\0') {
        snprintf(auth_header, 512,
                 "AWS4-HMAC-SHA256 Credential=%s/%s/%s/%s/aws4_request, "
                 "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token, Signature=%s",
                 config->access_key, date_str, region, service, signature_hex);
    } else {
        snprintf(auth_header, 512,
                 "AWS4-HMAC-SHA256 Credential=%s/%s/%s/%s/aws4_request, "
                 "SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=%s",
                 config->access_key, date_str, region, service, signature_hex);
    }
    
    return auth_header;
}

typedef struct {
    char *base_prefix;
    char **entries;
    size_t n;
    size_t cap;

    int in_common_prefixes;
    int in_contents;
    int collect_text;
    char text[2048];
    size_t text_len;
} s3_ls_xml_ctx_t;

static void s3_ls_add_entry(s3_ls_xml_ctx_t *ctx, const char *value) {
    if (value == NULL || value[0] == '\0') return;

    const char *rel = value;
    if (ctx->base_prefix) {
        size_t bl = strlen(ctx->base_prefix);
        if (strncmp(value, ctx->base_prefix, bl) == 0) rel = value + bl;
    }
    if (rel[0] == '\0') return;

    if (ctx->n == ctx->cap) {
        size_t new_cap = ctx->cap ? (ctx->cap * 2) : 16;
        char **p = (char **) realloc(ctx->entries, new_cap * sizeof(char *));
        if (!p) return;
        ctx->entries = p;
        ctx->cap = new_cap;
    }
    ctx->entries[ctx->n++] = strdup(rel);
}

static void s3_ls_xml_start(void *ud, const char *name, const char **atts) {
    (void) atts;
    s3_ls_xml_ctx_t *ctx = (s3_ls_xml_ctx_t *) ud;
    if (strcmp(name, "CommonPrefixes") == 0) ctx->in_common_prefixes = 1;
    else if (strcmp(name, "Contents") == 0) ctx->in_contents = 1;

    if (strcmp(name, "Prefix") == 0 || strcmp(name, "Key") == 0) {
        ctx->collect_text = 1;
        ctx->text_len = 0;
        ctx->text[0] = '\0';
    }
}

static void s3_ls_xml_end(void *ud, const char *name) {
    s3_ls_xml_ctx_t *ctx = (s3_ls_xml_ctx_t *) ud;

    if ((strcmp(name, "Prefix") == 0 || strcmp(name, "Key") == 0) && ctx->collect_text) {
        ctx->text[ctx->text_len] = '\0';
        if (strcmp(name, "Prefix") == 0) {
            if (ctx->in_common_prefixes) {
                s3_ls_add_entry(ctx, ctx->text);
            } else if (!ctx->in_contents && ctx->base_prefix == NULL) {
                ctx->base_prefix = strdup(ctx->text);
            }
        } else if (strcmp(name, "Key") == 0) {
            if (ctx->in_contents) s3_ls_add_entry(ctx, ctx->text);
        }
        ctx->collect_text = 0;
    }

    if (strcmp(name, "CommonPrefixes") == 0) ctx->in_common_prefixes = 0;
    else if (strcmp(name, "Contents") == 0) ctx->in_contents = 0;
}

static void s3_ls_xml_text(void *ud, const XML_Char *s, int len) {
    s3_ls_xml_ctx_t *ctx = (s3_ls_xml_ctx_t *) ud;
    if (!ctx->collect_text || len <= 0) return;
    size_t avail = sizeof(ctx->text) - 1 - ctx->text_len;
    size_t n = (size_t) len;
    if (n > avail) n = avail;
    if (n > 0) {
        memcpy(ctx->text + ctx->text_len, s, n);
        ctx->text_len += n;
        ctx->text[ctx->text_len] = '\0';
    }
}

static int s3_entry_cmp(const void *a, const void *b) {
    const char *sa = *(const char * const *) a;
    const char *sb = *(const char * const *) b;
    return strcmp(sa, sb);
}

static void s3_print_ls_from_xml(const char *xml, size_t xml_len) {
    s3_ls_xml_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    XML_Parser p = XML_ParserCreate(NULL);
    if (!p) return;
    XML_SetUserData(p, &ctx);
    XML_SetElementHandler(p, s3_ls_xml_start, s3_ls_xml_end);
    XML_SetCharacterDataHandler(p, s3_ls_xml_text);

    if (XML_Parse(p, xml, (int) xml_len, 1) == XML_STATUS_ERROR) {
        XML_ParserFree(p);
        for (size_t i = 0; i < ctx.n; i++) free(ctx.entries[i]);
        free(ctx.entries);
        free(ctx.base_prefix);
        return;
    }
    XML_ParserFree(p);

    if (ctx.n > 1) qsort(ctx.entries, ctx.n, sizeof(ctx.entries[0]), s3_entry_cmp);
    for (size_t i = 0; i < ctx.n; i++) {
        printf("%s\n", ctx.entries[i]);
        free(ctx.entries[i]);
    }
    free(ctx.entries);
    free(ctx.base_prefix);
}

// Structure to pass config and path to event handler
typedef struct {
    const s3_config_t *config;
    char path[512];
    char host[512];
} s3_request_data_t;

// Event handler for S3 HTTP requests
static void s3_event_handler(struct mg_connection *c, int ev, void *ev_data) {
    bool *done = (bool *) c->fn_data;
    s3_request_data_t *req_data = (s3_request_data_t *) c->mgr->userdata;
    
    if (ev == MG_EV_CONNECT) {
        // Connection established, send S3 request
        const s3_config_t *config = req_data->config;
        const char *path = req_data->path;
        const char *host = req_data->host;
        
        struct mg_str host_str = mg_str(host);
        
        // Initialize TLS if needed
        if (c->is_tls) {
            struct mg_tls_opts opts = {.ca = mg_str(""), .name = host_str};
            mg_tls_init(c, &opts);
        }
        
        // Get current timestamp for AWS auth
        time_t now = time(NULL);
        char date_str[9], timestamp[17];
        strftime(date_str, sizeof(date_str), "%Y%m%d", gmtime(&now));
        strftime(timestamp, sizeof(timestamp), "%Y%m%dT%H%M%SZ", gmtime(&now));
        
        // Create authorization header using the exact path that will be sent
        char *auth_header = create_aws_auth_header(config, "GET", path, host, date_str, timestamp);
        
        // Send S3 GET request with AWS headers and query parameters
        if (config->session_token && config->session_token[0] != '\0') {
            mg_printf(c,
                      "GET %s HTTP/1.1\r\n"
                      "Host: %s\r\n"
                      "Authorization: %s\r\n"
                      "x-amz-date: %s\r\n"
                      "x-amz-content-sha256: UNSIGNED-PAYLOAD\r\n"
                      "x-amz-security-token: %s\r\n"
                      "\r\n",
                      path, host, auth_header, timestamp, config->session_token);
        } else {
            mg_printf(c,
                      "GET %s HTTP/1.1\r\n"
                      "Host: %s\r\n"
                      "Authorization: %s\r\n"
                      "x-amz-date: %s\r\n"
                      "x-amz-content-sha256: UNSIGNED-PAYLOAD\r\n"
                      "\r\n",
                      path, host, auth_header, timestamp);
        }
        
        free(auth_header);
    } else if (ev == MG_EV_HTTP_MSG) {
        // Received HTTP response
        struct mg_http_message *hm = (struct mg_http_message *) ev_data;
        int status = mg_http_status(hm);
        if (status == 200) {
            s3_print_ls_from_xml(hm->body.buf, hm->body.len);
        } else {
            printf("HTTP Response Status: %d\n", status);
            printf("Response Body:\n%.*s\n", (int) hm->body.len, hm->body.buf);
        }
        *done = true;
    } else if (ev == MG_EV_ERROR) {
        printf("Connection error: %s\n", (char *) ev_data);
        *done = true;
    }
}

int s3_list_files(const s3_config_t *config, const char *path) {
    if (s3_debug_enabled()) printf("Listing files in: %s\n", path);
    
    struct mg_mgr mgr;
    bool done = false;
    
    mg_mgr_init(&mgr);
    mg_log_set(MG_LL_ERROR);  // Reduce debug output
    
    // Create request data structure
    s3_request_data_t req_data;
    req_data.config = config;
    
    // Build host based on bucket style
    if (strcmp(config->bucket_style, "domain") == 0) {
        // Domain style: bucket.endpoint.com
        if (strstr(config->endpoint_url, "://") == NULL) {
            snprintf(req_data.host, sizeof(req_data.host), "%s.%s", config->bucket_name, config->endpoint_url);
        } else {
            char protocol[16], domain[256];
            sscanf(config->endpoint_url, "%15[^://]://%255[^/]", protocol, domain);
            snprintf(req_data.host, sizeof(req_data.host), "%s.%s", config->bucket_name, domain);
        }
    } else {
        // Path style: endpoint.com
        if (strstr(config->endpoint_url, "://") == NULL) {
            snprintf(req_data.host, sizeof(req_data.host), "%s", config->endpoint_url);
        } else {
            char protocol[16], domain[256];
            sscanf(config->endpoint_url, "%15[^://]://%255[^/]", protocol, domain);
            snprintf(req_data.host, sizeof(req_data.host), "%s", domain);
        }
    }
    
    // Process the requested path
    char full_path[256];
    if (path[0] != '/') {
        snprintf(full_path, sizeof(full_path), "/%s", path);
    } else {
        snprintf(full_path, sizeof(full_path), "%s", path);
    }
    
    // Remove trailing slash if present (except for root)
    size_t len = strlen(full_path);
    if (len > 1 && full_path[len-1] == '/') {
        full_path[len-1] = '\0';
    }
    
    // Add prefix for directory listing
    char prefix_param[300];
    if (strcmp(full_path, "/") == 0) {
        prefix_param[0] = '\0';  // No prefix for root
    } else {
        snprintf(prefix_param, sizeof(prefix_param), "%s/", full_path + 1);  // Skip leading slash
    }
    
    // Build the exact path that will be used in the HTTP request
    if (strcmp(config->bucket_style, "domain") == 0) {
        // Domain style: path starts with /, bucket is in hostname
        if (prefix_param[0] != '\0') {
            char encoded_prefix[600];
            url_encode(prefix_param, encoded_prefix, sizeof(encoded_prefix));
            snprintf(req_data.path, sizeof(req_data.path), "/?list-type=2&prefix=%s&delimiter=/", encoded_prefix);
        } else {
            snprintf(req_data.path, sizeof(req_data.path), "/?list-type=2&delimiter=/");
        }
    } else {
        // Path style: path includes bucket name
        if (prefix_param[0] != '\0') {
            char encoded_prefix[600];
            url_encode(prefix_param, encoded_prefix, sizeof(encoded_prefix));
            snprintf(req_data.path, sizeof(req_data.path), "/%s?list-type=2&prefix=%s&delimiter=/", config->bucket_name, encoded_prefix);
        } else {
            snprintf(req_data.path, sizeof(req_data.path), "/%s?list-type=2&delimiter=/", config->bucket_name);
        }
    }
    
    // Build the URL for connection
    char url[512];
    if (strcmp(config->bucket_style, "domain") == 0) {
        // Domain style: URL is bucket.endpoint.com/path
        if (strstr(config->endpoint_url, "://") == NULL) {
            snprintf(url, sizeof(url), "https://%s.%s%s", config->bucket_name, config->endpoint_url, req_data.path);
        } else {
            char protocol[16], domain[256];
            sscanf(config->endpoint_url, "%15[^://]://%255[^/]", protocol, domain);
            snprintf(url, sizeof(url), "%s://%s.%s%s", protocol, config->bucket_name, domain, req_data.path);
        }
    } else {
        // Path style: URL is endpoint.com/bucket/path
        if (strstr(config->endpoint_url, "://") == NULL) {
            snprintf(url, sizeof(url), "https://%s%s", req_data.host, req_data.path);
        } else {
            char protocol[16];
            sscanf(config->endpoint_url, "%15[^://]", protocol);
            snprintf(url, sizeof(url), "%s://%s%s", protocol, req_data.host, req_data.path);
        }
    }
    
    if (s3_debug_enabled()) printf("Request URL: %s\n", url);  // Debug output
    
    mgr.userdata = &req_data;  // Store request data for event handler
    
    // Connect to S3 endpoint
    struct mg_connection *c = mg_http_connect(&mgr, url, s3_event_handler, &done);
    if (c == NULL) {
        fprintf(stderr, "Failed to create connection\n");
        mg_mgr_free(&mgr);
        return 1;
    }
    
    // Run event loop until done
    while (!done) {
        mg_mgr_poll(&mgr, 100);
    }
    
    mg_mgr_free(&mgr);
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
    printf("  Bucket Name: %s\n", config->bucket_name);
    printf("  Bucket Style: %s\n", config->bucket_style);
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
    const char *endpoint_url = getenv("S3_ENDPOINT_URL");
    const char *bucket_name = getenv("S3_BUCKET_NAME");
    const char *bucket_style = getenv("S3_BUCKET_STYLE");
    const char *access_key = getenv("S3_ACCESS_KEY");
    const char *secret_key = getenv("S3_SECRET_KEY");
    const char *session_token = getenv("S3_SESSION_TOKEN");

    // Default to path style if not specified
    if (!bucket_style) {
        bucket_style = "path";
    }

    if (!endpoint_url || !bucket_name || !access_key || !secret_key) {
        fprintf(stderr, "Error: Missing required environment variables:\n");
        if (!endpoint_url) fprintf(stderr, "  - S3_ENDPOINT_URL\n");
        if (!bucket_name) fprintf(stderr, "  - S3_BUCKET_NAME\n");
        if (!access_key) fprintf(stderr, "  - S3_ACCESS_KEY\n");
        if (!secret_key) fprintf(stderr, "  - S3_SECRET_KEY\n");
        return 1;
    }

    // Validate bucket_style
    if (strcmp(bucket_style, "domain") != 0 && strcmp(bucket_style, "path") != 0) {
        fprintf(stderr, "Error: S3_BUCKET_STYLE must be 'domain' or 'path'\n");
        return 1;
    }

    s3_config_t config = {
        .endpoint_url = endpoint_url,
        .bucket_name = bucket_name,
        .bucket_style = bucket_style,
        .access_key = access_key,
        .secret_key = secret_key,
        .session_token = session_token
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