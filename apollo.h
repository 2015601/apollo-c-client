#ifndef __APOLLO_H
#define __APOLLO_H

// https://www.apolloconfig.com/#/zh/usage/other-language-client-user-guide

struct apollo_ctx;

typedef void (*Apollo_config_item_apply_cb)(const char *name, const char *value);
typedef int  (*Apollo_config_item_check_cb)(const char *name, const char *value);

// Configuration state in the current context
enum {
	APOLLO_CONFIG_BEGIN,
	APOLLO_CONFIG_READHEADER,
	APOLLO_CONFIG_READBODY,
	APOLLO_CONFIG_READED,
	APOLLO_CONFIG_BAD,
	APOLLO_CONFIG_LAUNCHED
};

struct apollo_config_item {
	const char *name;
	Apollo_config_item_apply_cb apply_cb;
	Apollo_config_item_check_cb check_cb;
};

struct apollo_ctx * Apollo_ctx_create(const char *namespace, const char *appId, const char *cluster);
void Apollo_ctx_free(struct apollo_ctx * ctx);


void Apollo_config_item_reigster(struct apollo_ctx * ctx, struct apollo_config_item *items,
	Apollo_config_item_apply_cb default_apply_cb, Apollo_config_item_check_cb default_check_cb);

char * Apollo_server_config_request(struct apollo_ctx *ctx);

int Apollo_server_response_read (struct apollo_ctx *ctx, char *buffer, int len, int reread);

int Apollo_server_config_launch(struct apollo_ctx * ctx);

#endif
