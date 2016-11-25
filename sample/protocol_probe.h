#ifndef PROTOCOL_PROBE_H
#define PROTOCOL_PROBE_H

#include <string.h>

#define ECHO_TOKEN "echo"
#define SSH_TOKEN "SSH-2.0-"
#define GET_TOKEN "GET"
#define POST_TOKEN "POST"

static inline int is_ssh_protocol(const char *packet_data, int data_len)
{
	if (data_len < strlen(SSH_TOKEN) ||
	    strncmp(packet_data, SSH_TOKEN, strlen(SSH_TOKEN))) {
		return 0;
	}

	return 1;

}

static inline int is_echo_protocol(const char *packet_data, int data_len)
{
	if (data_len < strlen(ECHO_TOKEN) ||
	    strncmp(packet_data, ECHO_TOKEN, strlen(ECHO_TOKEN))) {
		return 0;
	}

	return 1;
}

static inline int is_http_protocol(const char *packet_data, int data_len)
{
	if (!strncmp(packet_data, GET_TOKEN, strlen(GET_TOKEN)) ||
	    !strncmp(packet_data, POST_TOKEN, strlen(POST_TOKEN))) {
		return 1;
	}

	return 0;
}

#endif
