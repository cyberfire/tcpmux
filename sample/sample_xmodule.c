#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "internal_ident.h"
#include "mux_log.h"
#include "xmodule.h"
#include "protocol_probe.h"

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

int init_xmodule(void)
{
	register_intern_proto_ident("xecho", 0, echo_proto_identifier);
	register_intern_proto_ident("xssh", 0, ssh_proto_identifier);
	enable_intern_proto_identifier("xssh");
	enable_intern_proto_identifier("xecho");

	return 0;

}

int release_xmodule(void)
{
	unregsiter_intern_proto_ident("xssh");
	unregsiter_intern_proto_ident("xecho");
	return 0;
}
