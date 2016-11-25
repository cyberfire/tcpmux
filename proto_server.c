#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "list.h"
#include "mux_log.h"

#define TOKEN_PROXY "proxy"

struct proto_server {
	char *proto_name;
	char *prog;
	char *para;
	struct list link;
};

static LIST_HEAD(proto_server_list);

static void init_proto_server(struct proto_server *p_server)
{
	p_server->proto_name = NULL;
	p_server->prog = NULL;
	p_server->para = NULL;
	list_init(&p_server->link);
}

static void release_proto_server(struct proto_server *p_server)
{
	free(p_server->proto_name);
	free(p_server->prog);

	if (p_server->para)
		free(p_server->para);

	free(p_server);
}

static struct proto_server *find_proto_server_by_name(const char *proto_name)
{
	struct proto_server *p_server;

	list_for_each_entry(p_server, &proto_server_list, link) {
		if (!strcmp(p_server->proto_name, proto_name))
			return p_server;
	}
	return NULL;
}

int register_proto_server(const char *proto_name, const char *server_prog,
			  const char *para)
{
	struct proto_server *p_server;

	if (find_proto_server_by_name(proto_name))
		return -1;

	p_server = malloc(sizeof(struct proto_server));

	if (p_server == NULL)
		return -1;

	init_proto_server(p_server);

	p_server->proto_name = strdup(proto_name);
	p_server->prog = strdup(server_prog);

	if (para)
		p_server->para = strdup(para);

	list_prepend(&p_server->link, &proto_server_list);

	return 0;
}

int unregister_proto_server(const char *proto_name)
{
	struct proto_server *p_server;

	p_server = find_proto_server_by_name(proto_name);

	if (p_server == NULL)
		return -1;

	list_remove(&p_server->link);

	release_proto_server(p_server);

	return 0;

}

void unregister_all_proto_server(void)
{
	struct proto_server *p_server;
	struct proto_server *p_dummy;

	list_for_each_entry_safe(p_server, p_dummy, &proto_server_list, link) {
		unregister_proto_server(p_server->proto_name);
	}
}

static void dump_proto_server_entry(struct proto_server *p_server)
{
	log_info("proto server: proto [%s] program[%s] para[%s]\n",
		 p_server->proto_name, p_server->prog,
		 p_server->para ? p_server->para : "NONE");
}

void dump_all_proto_servers(void)
{
	int count = 0;
	struct proto_server *p_server;

	list_for_each_entry(p_server, &proto_server_list, link) {
		dump_proto_server_entry(p_server);
		count++;
	}

	log_info("total [%d] protocol server registerd\n", count);
}

static int count_para_num(const char *para)
{
	int count;
	const char *p;

	if (para == NULL)
		return 0;

	p = para;
	count = 1;

	while (*p) {
		if (*p++ != ',')
			continue;

		if (*p)
			count++;
	}

	return count;
}

static void launch_server_program(const char *prog, const char *para)
{
	int para_num;
	int i;
	char *p;

	para_num = count_para_num(para);

	log_debug("launch server [%s] para[%s] para_num[%d]\n",
		  prog, para, para_num);

	if (!para_num) {
		execl(prog, prog, NULL);

		log_error("execl prog [%s] failed, error [%s]\n", prog,
			  strerror(errno));

	} else {
		char **argv;

		argv =
		    malloc(sizeof(const char *) * (para_num + 2) +
			   strlen(para) + 1);

		if (argv == NULL)
			return;

		p = (char *)(argv + para_num + 2);

		strcpy(p, para);

		argv[0] = (char *)prog;

		for (i = 1; i < para_num + 1; i++) {
			argv[i] = p;
			while (*p && *p != ',')
				p++;

			*p = 0;
			p++;
			log_debug("argv[%d] [%s]\n", i, argv[i]);
		}

		argv[i] = NULL;	//The terminal sign

		execv(prog, argv);

		log_error("execl prog [%s] failed, error [%s]\n", prog,
			  strerror(errno));
	}

}

int exec_proto_server(int conn_fd, const char *proto_name)
{
	struct proto_server *p_server;
	int child_pid;
	int fd;

	p_server = find_proto_server_by_name(proto_name);

	if (p_server == NULL)
		return -1;

	log_debug("proto [%s] taken by server [%s]\n", proto_name,
		  p_server->prog);

	/* if conn_fd is 0, it is un-necessary to daemonzie first */

	if (conn_fd) {
		child_pid = fork();

		if (child_pid) {

			if (child_pid < 0)
				return -1;

			waitpid(child_pid, NULL, 0);

			return 0;
		}

		/* child process */
		dup2(conn_fd, 0);
		dup2(conn_fd, 1);

		fd = open("/dev/null", O_WRONLY);
		dup2(fd, 2);

		close(fd);
		close(conn_fd);

		child_pid = fork();

		if (child_pid)
			exit(0);

		setsid();
	}

	set_mux_log_daemon_mode(NULL);

	launch_server_program(p_server->prog, p_server->para);

	exit(1);

}
