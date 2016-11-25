#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "mux_log.h"
#include "internal_ident.h"
#include "protocol_probe.h"

static int http_proto_identifier(const char *packet_data, int data_len,
				 char *proto_name, int name_len)
{
	if (!is_http_protocol(packet_data, data_len))
		return -1;

	if (name_len <= strlen("http"))
		return -1;

	strcpy(proto_name, "http");

	return 0;

}

void install_http_proto_identifier(void)
{
	register_intern_proto_ident("http", 0, http_proto_identifier);
}

/* sample code for echo protocol identification */

static int echo_proto_identifier(const char *packet_data, int data_len,
				 char *proto_name, int name_len)
{
	if (!is_echo_protocol(packet_data, data_len))
		return -1;

	if (name_len <= strlen("echo"))
		return -1;

	strcpy(proto_name, "echo");

	return 0;

}

void install_echo_proto_identifier(void)
{
	register_intern_proto_ident("echo", 0, echo_proto_identifier);
}

/*sample code for ssh protocol identification*/
static int ssh_proto_identifier(const char *packet_data, int data_len,
				char *proto_name, int name_len)
{
	if (!is_ssh_protocol(packet_data, data_len))
		return -1;

	if (name_len <= strlen("ssh"))
		return -1;

	strcpy(proto_name, "ssh");

	return 0;
}

void install_ssh_proto_identifier(void)
{
	register_intern_proto_ident("ssh", 0, ssh_proto_identifier);
}
