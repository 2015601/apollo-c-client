#include <stddef.h>
#include <stdint.h>
#include <malloc.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <memory.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <sys/fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <cjson/cJSON.h>
#include "apollo.h"

#define HTTP_TOK_LEN (sizeof("\r\n")-1)

#define FREE_PTR(ptr) do { \
	if (ptr) {			   \
		free(ptr);		   \
		ptr = NULL;		   \
	}					   \
} while(0)
#define FREE(ptr) do { \
	if (ptr) {		   \
		free(ptr);	   \
	}				   \
} while(0)

#define cjson_object_walk(json, item) \
	for(item = json->child; item; item = item->next)

#define CALL(func, ...) ({ \
	if (func) {			   \
		func(__VA_ARGS__); \
	}					   \
})

struct apollo_ctx {
	int config_status;
	int config_cache;

	const char *namespace;
	const char *appId;
	const char *cluster;

	struct {
		char *current_resp_string;
		int len;
		int body_offset;
		int chunk_length;
	};

	struct {
		char *current_config_string;
		int current_config_len;
		int config_buffer_total_len;
	};

	cJSON *json;

	struct apollo_config_item *items;
	Apollo_config_item_check_cb default_item_check_cb;
	Apollo_config_item_apply_cb default_item_apply_cb;
};

struct apollo_ctx * Apollo_ctx_create(const char *namespace, const char *appId, const char *cluster)
{
	struct apollo_ctx *ctx;

	ctx = calloc(1, sizeof(struct apollo_ctx));
	if (ctx == NULL) {
		return ctx;
	}

	ctx->namespace = namespace;
	ctx->appId = appId;
	ctx->cluster = cluster;

	return ctx;
}

void Apollo_ctx_free(struct apollo_ctx * ctx)
{
	FREE(ctx->current_resp_string);
	FREE(ctx->current_config_string);
	cJSON_Delete(ctx->json);
	FREE(ctx);
}

void Apollo_config_item_reigster(struct apollo_ctx * ctx, struct apollo_config_item *items,
	Apollo_config_item_apply_cb default_apply_cb, Apollo_config_item_check_cb default_check_cb)
{
	ctx->items = items;
	ctx->default_item_apply_cb = default_apply_cb;
	ctx->default_item_check_cb = default_check_cb;
}

static void __apollo_config_item_apply (struct apollo_ctx *ctx, const char *name, const char *value) {
	for (struct apollo_config_item *item = ctx->items; item; item++) {
		if (!item->name) {
			break;
		}
		if (strcmp(item->name, name)) {
			continue;
		}
		CALL(item->apply_cb, name, value);
		return;
	}

	CALL(ctx->default_item_apply_cb, name, value);
}

static int __apollo_config_item_check (struct apollo_ctx *ctx, const char *name, const char *value) {
	for (struct apollo_config_item *item = ctx->items; item; item++) {
		if (!item->name) {
			break;
		}
		if (strcmp(item->name, name)) {
			continue;
		}
		if (item->check_cb) {
			return item->check_cb(name, value);
		}
		return 0;
	}

	if (ctx->default_item_check_cb) {
		return ctx->default_item_check_cb(name, value);
	}

	return 0;
}

int Apollo_server_config_launch(struct apollo_ctx * ctx)
{
	cJSON *json;

	switch (ctx->config_status) {
		case APOLLO_CONFIG_BEGIN:
			return -ENODATA;
		case APOLLO_CONFIG_READBODY:
		case APOLLO_CONFIG_READHEADER:
			return EAGAIN;
		case APOLLO_CONFIG_BAD:
			return EBADMSG;
		case APOLLO_CONFIG_LAUNCHED:
			goto launch;
		case APOLLO_CONFIG_READED:
		default:
			break;
	}

	// cleanup old config json object
	if (ctx->json) {
		cJSON_Delete(ctx->json);
	}

	json = cJSON_Parse(ctx->current_config_string);
	if (!cJSON_IsObject(json)) {
		goto msg_bad;
	}

	if (ctx->config_cache) {
		ctx->json = json;
	} else {
		ctx->json = cJSON_DetachItemFromObject(json, "configurations");
		cJSON_Delete(json);
	}
	if (!cJSON_IsObject(ctx->json)) {
		goto msg_bad;
	}

	// check all config item
	cjson_object_walk(ctx->json, json) {
		if (!cJSON_IsString(json)) {
			goto msg_bad;
		}
		if (__apollo_config_item_check(ctx, json->string, json->valuestring)) {
			goto msg_bad;
		}
	}

launch:
	cjson_object_walk(ctx->json, json) {
		__apollo_config_item_apply(ctx, json->string, json->valuestring);
	}

	ctx->config_status = APOLLO_CONFIG_LAUNCHED;
	return 0;

msg_bad:
	ctx->config_status = APOLLO_CONFIG_BAD;
	return EBADMSG;
}

char * Apollo_server_config_request(struct apollo_ctx *ctx)
{
	const char *apollo_http_request =
	"GET /configfiles/json/%s/%s/%s HTTP/1.1\r\n"
	"Host: apollo-server\r\n"
	"User-Agent: apollo-c-client/1.0\r\n"
	"Connection: close\r\n"
	"Accept: */*\r\n\r\n";
	const char *apollo_http_no_cache_request =
	"GET /configs/%s/%s/%s HTTP/1.1\r\n"
	"Host: apollo-server\r\n"
	"User-Agent: apollo-c-client/1.0\r\n"
	"Connection: close\r\n"
	"Accept: */*\r\n\r\n";
	size_t req_length;
	char *req_buffer;

	if (ctx->config_cache) {
		req_length = strlen(apollo_http_request)
			+ strlen(ctx->appId)
			+ strlen(ctx->cluster)
			+ strlen(ctx->namespace) + 4;
		req_buffer = calloc(1, req_length);
		if (!req_buffer) {
			return NULL;
		}
		snprintf(req_buffer, req_length, apollo_http_request, ctx->appId, ctx->cluster, ctx->namespace);
	} else {
		req_length = strlen(apollo_http_no_cache_request)
			+ strlen(ctx->appId)
			+ strlen(ctx->cluster)
			+ strlen(ctx->namespace) + 4;
		req_buffer = calloc(1, req_length);
		if (!req_buffer) {
			return NULL;
		}
		snprintf(req_buffer, req_length, apollo_http_no_cache_request, ctx->appId, ctx->cluster, ctx->namespace);
	}

	return req_buffer;
}


//[chunk_length][CRLF][chunk_data[CRLF].....[0][CRLF][footer][CRLF]
static int __apollo_read_server_resp_body (struct apollo_ctx *ctx) {
	char *chunk_data;
	char *body, *end;
	int chunk_length;

begin:
	if (ctx->len <= ctx->body_offset + HTTP_TOK_LEN/*\r\n*/) {
		return APOLLO_CONFIG_READBODY;
	}

	body = ctx->current_resp_string + ctx->body_offset;
	end = ctx->current_resp_string + ctx->len;

	chunk_length = ctx->chunk_length;
	// first chunk
	if (chunk_length < 0) {
		chunk_length = strtol(body, &chunk_data, 16);
		chunk_data += HTTP_TOK_LEN; /* \r\n */
	} else if (chunk_length == 0) {
		body += HTTP_TOK_LEN /*\r\n*/;
		if (body >= end) {
			return APOLLO_CONFIG_READBODY;
		}
		chunk_length = strtol(body, &chunk_data, 16);
		chunk_data += HTTP_TOK_LEN;
	} else {
		chunk_data = body;
	}

	if (chunk_length >= UINT16_MAX) {
		return APOLLO_CONFIG_BAD;
	} else if (chunk_length == 0) {
		return APOLLO_CONFIG_READED;
	}

	if (chunk_data >= end) {
		return APOLLO_CONFIG_READBODY;
	}

	ctx->chunk_length = chunk_length;
	ctx->body_offset = chunk_data - ctx->current_resp_string;

	if (ctx->config_buffer_total_len - ctx->current_config_len <= ctx->chunk_length) {
		char *new_string = calloc(1, ctx->current_config_len + ctx->chunk_length + 1);
		if (!new_string) {
			return APOLLO_CONFIG_BAD;
		}
		memcpy(new_string, ctx->current_config_string, ctx->current_config_len);
		FREE(ctx->current_config_string);
		ctx->current_config_string = new_string;
	}

	while (chunk_data < end && ctx->chunk_length > 0) {
		ctx->current_config_string[ctx->current_config_len++] = chunk_data[0];
		chunk_data++;
		ctx->chunk_length--;
	}
	ctx->current_config_string[ctx->current_config_len] = '\0';
	ctx->body_offset = chunk_data - ctx->current_resp_string;
	if (ctx->chunk_length == 0) {
		goto begin;
	}

	return 0;
}

static int __apollo_read_server_resp_header (struct apollo_ctx *ctx) {
	char *body;

	body = strstr(ctx->current_resp_string, "\r\n\r\n");
	if (!body) {
		return APOLLO_CONFIG_READHEADER;
	}
	ctx->body_offset = body + 2*HTTP_TOK_LEN - ctx->current_resp_string;

	return __apollo_read_server_resp_body(ctx);
}

int Apollo_server_response_read (struct apollo_ctx *ctx, char *buffer, int len, int reread)
{
	char *resp;

	if (reread) {
		ctx->config_status = APOLLO_CONFIG_BEGIN;
	}

	if (ctx->config_status == APOLLO_CONFIG_BAD
		|| ctx->config_status == APOLLO_CONFIG_READED
		|| ctx->config_status == APOLLO_CONFIG_LAUNCHED) {
		return ctx->config_status;
	}

	if (ctx->config_status == APOLLO_CONFIG_BEGIN) {
		// free old config string
		FREE(ctx->current_resp_string);
		FREE(ctx->current_config_string);

		ctx->len = 0;
		ctx->current_resp_string = malloc(len+1);
		if (!ctx->current_resp_string) {
			return ENOMEM;
		}
		memcpy(ctx->current_resp_string, buffer, len);
		ctx->current_resp_string[len] = '\0';
		ctx->len += len;
		ctx->chunk_length = -1;
		ctx->current_config_len = 0;
		ctx->config_buffer_total_len = 0;
		ctx->config_status= APOLLO_CONFIG_READHEADER;
	} else {
		resp = calloc(1, ctx->len + len + 1);
		if (!resp) {
			return ENOMEM;
		}

		memcpy(resp, ctx->current_resp_string, ctx->len);
		memcpy(resp, ctx->current_resp_string+ctx->len, len);
		FREE(ctx->current_resp_string);
		ctx->current_resp_string = resp;
		ctx->len += len;
		ctx->current_resp_string[ctx->len] = '\0';
	}

	if (ctx->config_status == APOLLO_CONFIG_READHEADER) {
		ctx->config_status = __apollo_read_server_resp_header(ctx);
	} else {
		ctx->config_status = __apollo_read_server_resp_body(ctx);
	}

	return ctx->config_status;
}
