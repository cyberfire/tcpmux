#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include "mux_log.h"



static int get_client_ip(int fd, unsigned int *cli_ip)
{
	int ret;
	struct sockaddr_in clnt_addr;
	socklen_t addr_len;

	addr_len = sizeof(clnt_addr);

	ret = getpeername(fd, (struct sockaddr *)&clnt_addr, &addr_len);

	if (ret < 0) {
		log_error("getpeername: %s\n", strerror(errno));
		return -1;
	}

	*cli_ip = clnt_addr.sin_addr.s_addr;

	return 0;
}

static int check_ip_proto_prog(unsigned int cli_ip, const char *proto,
			       const char *prog)
{
	struct in_addr in;

	in.s_addr = cli_ip;

	log_info("please add policy check for ip [%s] prog[%s] and proto[%s]\n",
		 inet_ntoa(in), prog, proto);

	return 1;
}

static void exec_real_server(char *prog, int count, char *para[])
{
	char **argv;
	int i;

	if (count == 0) {
		execl(prog, prog, NULL);
	} else {

		argv = malloc(sizeof(char *) * count + 2);

		if (argv == NULL)
			return;

		argv[0] = prog;

		for (i = 1; i < count + 1; i++)
			argv[i] = para[i - 1];

		argv[i] = NULL;

		execv(prog, argv);
	}

}

/*
* assume: stdin/stdout --- the tcp connection 
*          stderr   ---- /dev/null
*          argv[1]  ---- proto_name
*          argv[2]  ---- sever_program
*          argv[x]  ---- arguments  to server program
*/

int main(int argc, char *argv[])
{
	char *proto;
	char *server_prog;
	unsigned int client_ip;

	set_mux_log_daemon_mode("access_control");

	proto = argv[1];
	server_prog = argv[2];

	if (get_client_ip(0, &client_ip) < 0)
		exit(1);

	if (!check_ip_proto_prog(client_ip, proto, server_prog))
		exit(2);

	exec_real_server(server_prog, argc - 3, &argv[3]);

	return 4;

}
