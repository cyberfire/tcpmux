#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "protocol_probe.h"

/* 
 protocol between the external app and parent program are:
 stdin 0 ---- parent will write the packet_data , at most 1000
 stdout 1 ---- will return the protocol name string or "NOTFOUND" if cannot identify the packet
 stderr 2 ---   redirect to /dev/null

 exit code --- 0, means meaningful result returned
 */
 
int main(int argc, char *argv[])
{
	char buf[1024];
	int ret;

	ret = read(0, buf, 1024);

	if (ret <= 0)
		return -1;

	if (is_echo_protocol(buf, ret)) {
		write(1, "echo", strlen("echo"));
	} else if (is_ssh_protocol(buf, ret)) {
		write(1, "ssh", strlen("ssh"));
	} else {
		write(1, "NOTFOUND", strlen("NOTFOUND"));
	}

	return 0;
}
