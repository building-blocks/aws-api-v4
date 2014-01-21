#include "httpd.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_log.h"
#include "apr_escape.h"
#include "apr_strings.h"



typedef struct {
	const char* access;
	const char* enc_secret;
} aws_keys;

typedef struct {
	const char* headers;
	const char* body;
	apr_size_t body_len;
} response_params;

typedef struct {
	const char* service;
	const char* region;
	const char* host;
	const char* message;
	const char* payload;
	apr_socket_t* sock;
	response_params* resp;
} request_params;


module AP_MODULE_DECLARE_DATA aws_module;


const char* get_x_amz_date(apr_pool_t* pool)
{
	apr_time_exp_t tm;
	apr_time_t t = apr_time_now();

	apr_time_exp_gmt(&tm, t);

	const char* timestamp = apr_psprintf(pool, "%d%.2d%.2dT%.2d%.2d%.2dZ", (tm.tm_year + 1900),
			(tm.tm_mon + 1), tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

	return timestamp;
}


char* external_command(apr_pool_t* pool, const char* input, const char* command, apr_size_t nbytes)
{
	apr_procattr_t *pattr;
	apr_proc_t proc;

	char** argv = NULL;
	apr_tokenize_to_argv(command, &argv, pool);

	apr_procattr_create(&pattr, pool);
	apr_procattr_io_set(pattr, APR_CHILD_BLOCK, APR_FULL_BLOCK, APR_NO_PIPE);
	apr_procattr_cmdtype_set(pattr, APR_PROGRAM_ENV);
	
	apr_proc_create(&proc, argv[0], (const char* const*) argv, NULL, (apr_procattr_t*) pattr, pool);
	apr_file_puts(input, proc.in);
	apr_file_close(proc.in);

	char* output = apr_pcalloc(pool, sizeof(char) * nbytes);
	apr_file_read(proc.out, output, &nbytes);
	output[nbytes] = '\0';

	apr_file_close(proc.out);

	int exit_code;
	apr_exit_why_e why;

	apr_proc_wait(&proc, &exit_code, &why, APR_WAIT);

	return output;
}


char* hmac_hash(apr_pool_t* pool, const char* input, char* hexkey)
{
	const char* command = apr_pstrcat(pool, "/usr/bin/openssl dgst -sha256 -mac HMAC -macopt ", hexkey, NULL);
	char* hash = external_command(pool, input, command, 128);

	int i;
	int hash_len = strlen(hash);
	for (i = 0; i < hash_len - 1; i++) {
		if (hash[i] == ' ') {
			hash = &hash[i + 1];
			hash_len -= (i + 1);
			break;
		}
	}
	
	hash[hash_len - 1] = '\0';

	return hash;
}


char* sha256(apr_pool_t* pool, const char* input)
{
	const char* command = apr_pstrcat(pool, "/usr/bin/sha256sum", NULL);
	char *output = apr_pstrcat(pool, external_command(pool, input, command, 64), NULL);

	return output;
}


const char* derive_signing_key(apr_pool_t* pool, const char* enc_secret_key, const char* date, const char* region, const char* service)
{
	char* hexkey = NULL;
	char* digest = NULL;

	hexkey = apr_pstrcat(pool, "hexkey:", enc_secret_key, NULL);
	digest = hmac_hash(pool, date, hexkey);

	hexkey = apr_pstrcat(pool, "hexkey:", digest, NULL);
	digest = hmac_hash(pool, region, hexkey);

	hexkey = apr_pstrcat(pool, "hexkey:", digest, NULL);
	digest = hmac_hash(pool, service, hexkey);

	hexkey = apr_pstrcat(pool, "hexkey:", digest, NULL);
	const char* aws4_request = apr_pstrcat(pool, "aws4_request", NULL);
	digest = hmac_hash(pool, aws4_request, hexkey);

	return (const char*) digest;
}


const char* make_signature(apr_pool_t *pool, const char* signing_key, const char* string_to_sign)
{
	char* hexkey = NULL;
	hexkey = apr_pstrcat(pool, "hexkey:", signing_key, NULL);

	const char* command = apr_pstrcat(pool, "/usr/bin/openssl dgst -binary -hex -sha256 -mac HMAC -macopt ", hexkey, NULL);
	char* output = external_command(pool, string_to_sign, command, 128);
	int i;
	int len = strlen(output);
	for (i = 0; i < len - 1; i++) {
		if (output[i] == ' ') {
			output = &output[i + 1];
			len -= (i + 1);
			break;
		}
	}

	output[len - 1] = '\0';

	return output;
}


void send_request(request_rec *r, request_params* req)
{
	apr_sockaddr_t *sockaddr;
	apr_pool_t* pool = r->pool;
	apr_interval_time_t timeout = 500000;
	apr_size_t item_size;

	apr_sockaddr_info_get(&sockaddr, req->host, APR_INET, 80, 0, pool);
	apr_socket_create(&req->sock, sockaddr->family, SOCK_STREAM, APR_PROTO_TCP, pool);
	apr_socket_opt_set(req->sock, APR_SO_NONBLOCK, 1);
	apr_socket_timeout_set(req->sock, timeout);
	apr_socket_connect(req->sock, sockaddr);
	// setting options again, ref ariel-networks.com
	apr_socket_opt_set(req->sock, APR_SO_NONBLOCK, 0);
	apr_socket_timeout_set(req->sock, timeout);
	item_size = strlen(req->message);
	apr_socket_send(req->sock, req->message, &item_size);
}


void make_signed_request_message(request_rec* r, request_params* req)
{
	apr_pool_t* pool = r->pool;

	aws_keys* keys = ap_get_module_config(r->server->module_config, &aws_module);

	const char* content_type = apr_pstrcat(pool, "application/x-www-form-urlencoded; charset=utf-8", NULL);

	const char* x_amz_date_sec = get_x_amz_date(pool); // 20140115T143316Z
	const char* x_amz_date_day = apr_pstrndup(pool, x_amz_date_sec, 8); // 20140115

	const char* canonical_headers = apr_pstrcat(pool, "content-type:", content_type, "\n", "host:", req->host, "\nx-amz-date:", x_amz_date_sec, NULL);
	const char* signed_headers = apr_pstrcat(pool, "content-type;host;x-amz-date", NULL);

	const char* hashed_payload = sha256(pool, req->payload);

	const char* canonical_request = apr_pstrcat(pool, "POST\n/\n\n", canonical_headers, "\n\n", signed_headers, "\n", hashed_payload, NULL);
	const char* hashed_canonical_request = sha256(pool, canonical_request);

	const char* string_to_sign = apr_pstrcat(pool, "AWS4-HMAC-SHA256\n", x_amz_date_sec, "\n", x_amz_date_day, "/", req->region, "/", req->service, "/aws4_request\n", hashed_canonical_request, NULL);
	const char* signing_key = derive_signing_key(pool, keys->enc_secret, x_amz_date_day, req->region, req->service);
	const char* signature = make_signature(pool, signing_key, string_to_sign);

	const char* authorization_header = apr_pstrcat(pool, "AWS4-HMAC-SHA256 Credential=", keys->access, "/", x_amz_date_day, "/", req->region, "/", req->service, "/aws4_request, SignedHeaders=", signed_headers, ", Signature=", signature, NULL);

	req->message = apr_pstrcat(pool,
			"POST / HTTP/1.1\r\n",
			"Host: ", req->host, "\r\n",
			"X-Amz-Date: ", x_amz_date_sec, "\r\n",
			"Content-Type: ", content_type, "\r\n",
			"Authorization: ", authorization_header, "\r\n",
			"Content-Length: ", apr_itoa(pool, strlen(req->payload)), "\r\n",
			"\r\n",
			req->payload,
			NULL);
}


void response_as_string(apr_pool_t* pool, request_params* req, apr_bucket_alloc_t* bucket_alloc)
{
	apr_bucket* bucket = NULL;
	bucket = apr_bucket_socket_create(req->sock, bucket_alloc);

	const char *buff = apr_palloc(pool, 2048);
	apr_size_t len;
	int i;
	// Failsafe, to avoid it running indefinitely
	for (i = 0; i < 5; i++) {
		if (apr_bucket_read(bucket, &buff, &len, APR_BLOCK_READ != APR_SUCCESS || len == 0)) {
			break;
		}

		char* content = apr_pstrndup(pool, buff, len);
		if (i == 0) {
			req->resp->body = content;
		} else {
			req->resp->body = apr_pstrcat(pool, req->resp->body, content, NULL);
		}

		req->resp->body_len = req->resp->body_len + len;
		bucket = APR_BUCKET_NEXT(bucket);
	}

	apr_bucket_destroy(bucket);
}


void make_aws_request(request_rec *r, request_params* req)
{
	apr_pool_t* pool = r->pool;

	make_signed_request_message(r, req);
	send_request(r, req);

	req->resp = (response_params*) apr_pcalloc(pool, sizeof(response_params));
	response_as_string(pool, req, r->connection->bucket_alloc);

	apr_socket_close(req->sock);

	int i;
	for (i = 10; i < req->resp->body_len - 5; i++) {
		if (req->resp->body[i] == '\r' && req->resp->body[i + 1] == '\n'
					&& req->resp->body[i + 2] == '\r' && req->resp->body[i + 3] == '\n') {
			req->resp->headers = apr_pstrndup(pool, req->resp->body, i);
			req->resp->body = &req->resp->body[i + 4];
			break;
		}
	}
}


void make_list_queues_request(request_rec* r)
{
	apr_pool_t* pool = r->pool;

	request_params* req = (request_params*) apr_pcalloc(pool, sizeof(request_params));

	req->region = apr_pstrcat(pool, "eu-west-1", NULL);
	req->service = apr_pstrcat(pool, "sqs", NULL);
	req->host = apr_pstrcat(pool, req->service, ".", req->region, ".amazonaws.com", NULL);
	req->payload = apr_pstrcat(pool, "Action=ListQueues&Version=2012-11-05", NULL);

	make_aws_request(r, req);

	ap_rputs(req->resp->body, r);
}


static int aws_handler(request_rec* r)
{
	if (!r->handler || strcmp(r->handler, "aws-handler")) {
		return (DECLINED);
	}

	ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL, "aws_handler");

	make_list_queues_request(r);

	return OK;
}


static const char* set_aws_access_key(cmd_parms *parms, void *mconfig, const char *arg)
{
	aws_keys* keys = ap_get_module_config(parms->server->module_config, &aws_module);
	keys->access = arg;
	return NULL;
}


static const char* set_aws_enc_secret_key(cmd_parms *parms, void *mconfig, const char *arg)
{
	aws_keys* keys = ap_get_module_config(parms->server->module_config, &aws_module);
	const char* aws4_key = apr_pstrcat(parms->pool, "AWS4", arg, NULL);
	keys->enc_secret = apr_pescape_hex(parms->pool, aws4_key, strlen(aws4_key), 0);
	return NULL;
}


static void *create_server_conf(apr_pool_t *p, server_rec *s)
{
	aws_keys* keys;
	keys = (aws_keys*) apr_pcalloc(p, sizeof(aws_keys));
	return (void *) keys;
}


static const command_rec directives[] =
{
	AP_INIT_TAKE1("AwsAccessKey", set_aws_access_key, NULL, RSRC_CONF, "Set access key"),
	AP_INIT_TAKE1("AwsSecretKey", set_aws_enc_secret_key, NULL, RSRC_CONF, "Set secret key"),
	{ NULL }
};


static void register_hooks(apr_pool_t *pool)
{
	ap_hook_handler(aws_handler, NULL, NULL, APR_HOOK_LAST);
}


module AP_MODULE_DECLARE_DATA   aws_module =
{
	STANDARD20_MODULE_STUFF,
	NULL,            // Per-directory configuration handler
	NULL,            // Merge handler for per-directory configurations
	create_server_conf,// Per-server configuration handler
	NULL,            // Merge handler for per-server configurations
	directives,      // Any directives we may have for httpd
	register_hooks   // Our hook registering function
};
