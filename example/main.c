#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <malloc.h>

#include <apollo/apollo.h>


void default_cb(const char *name, const char *value)
{
	printf("%s:%s\n", name, value);
}

int main(void)
{
	struct apollo_ctx *ctx;
	char *req;
	struct sockaddr_in sin;
	int sock;

	ctx = Apollo_ctx_create ("application", "123", "default");
	Apollo_config_item_reigster(ctx, NULL, default_cb, NULL);

	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (sock < 0) {
		fprintf(stderr, "socket error\n");
		return -1;
	}

	sin.sin_addr.s_addr = inet_addr("10.2.9.57");
	sin.sin_port = htons(8080);
	sin.sin_family = AF_INET;

	if (connect(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		fprintf(stderr, "connect error\n");
		return -2;
	}

	req = Apollo_server_config_request(ctx);
	send(sock, req, strlen(req), 0);
	free(req);

	char buffer[1024];
	int len;
	int status = APOLLO_CONFIG_BEGIN;
	while((len=recv(sock, buffer, sizeof(buffer), 0)) > 0) {
		status = Apollo_server_response_read(ctx, buffer, len, 0);
		if (status == APOLLO_CONFIG_READED
		|| status == APOLLO_CONFIG_BAD) {
			break;
		}
	}
	Apollo_server_config_launch(ctx);
	Apollo_ctx_free(ctx);

	close(sock);

	return status == APOLLO_CONFIG_LAUNCHED;
}
