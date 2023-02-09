#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <malloc.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <apollo/apollo.h>


void default_cb(const char *name, const char *value)
{
	printf("%s:%s\n", name, value);
}

static int create_client_socket(const char *host, short port)
{
	int sock;
	struct sockaddr_in sin;

	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {
		fprintf(stderr, "socket error\n");
	}

	sin.sin_addr.s_addr = inet_addr(host);
	sin.sin_port = htons(port);
	sin.sin_family = AF_INET;

	if (connect(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		fprintf(stderr, "connect error\n");
		return -2;
	}

	return sock;
}

int main(void)
{
	struct apollo_ctx *ctx;
	char *req;
	int sock;

	ctx = Apollo_ctx_create ("application", "123", "default");
	Apollo_config_item_reigster(ctx, NULL, default_cb, NULL);

	sock = create_client_socket("10.2.9.57", 8080);

	Apollo_set_server_max_config_length(ctx, 0xffff);
	Apollo_set_server_req_cache(ctx, 1);

	req = Apollo_server_config_request(ctx);
	send(sock, req, strlen(req), 0);
	free(req);

	char buffer[1024];
	int len;
	int status = APOLLO_CONFIG_BEGIN;
	while((len=recv(sock, buffer, sizeof(buffer), 0)) > 0) {
		status = Apollo_server_response_read(ctx, buffer, len, 0);
		if (status == APOLLO_CONFIG_READED
		|| status < APOLLO_CONFIG_BEGIN) {
			break;
		}
	}
	status = Apollo_server_config_launch(ctx);

	printf("%s\n", Apollo_get_last_resp_string(ctx) ?: "null");
	printf("%s\n", Apollo_get_last_config_string(ctx) ?: "null");

	Apollo_ctx_free(ctx);

	close(sock);

	return status == APOLLO_CONFIG_LAUNCHED;
}
