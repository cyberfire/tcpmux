#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>

#include "tcpmux.h"
#include "mux_log.h"
#include "config_parser.h"
#include "proto_ident.h"
#include "internal_ident.h"
#include "proto_server.h"
#include "proxy_server.h"
#include "xmodule.h"

static const char *conf_file = NULL;

static int g_run_mode = FOREGROUND_MODE;
static int g_need_quit_loop = 0;
static int g_need_reinit = 0;
static int g_quit_program = 0;
static int g_dump_config = 0;
static char *prog_name;

static int setup_listen_socket(unsigned int bind_addr, int port)
{
	int fd;
	int on = 1;

	struct sockaddr_in srv_addr;

	fd = socket(AF_INET, SOCK_STREAM, 0);

	if (fd < 0)
		return -1;

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on))
	    < 0) {
		log_error("setsockopt error\n");
		goto error;
	}

	if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
		log_error("set FD_CLOEXEC failed. reason [%s]\n",
			  strerror(errno));
		goto error;
	}

	memset(&srv_addr, 0x0, sizeof(srv_addr));

	srv_addr.sin_family = AF_INET;
	srv_addr.sin_addr.s_addr = bind_addr;
	srv_addr.sin_port = htons(port);

	if (bind(fd, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) < 0) {
		log_error("bind failed at port [%d]\n", port);
		goto error;
	}

	if (listen(fd, 10) < 0) {
		log_error("listen\n");
		goto error;
	}

	return fd;

error:
	close(fd);
	return -1;
}

static void sig_usr2_handler(int sig)
{
	g_need_quit_loop = 1;
	g_need_reinit = 1;
}

static void sig_usr1_handler(int sig)
{
	g_need_quit_loop = 1;
	g_dump_config = 1;
}

static void sig_quit_program(int sig)
{
	g_need_quit_loop = 1;
	g_quit_program = 1;
}

static void setup_signal(void)
{
	struct sigaction act;
	sigset_t mask;

	sigemptyset(&mask);

	act.sa_handler = sig_usr2_handler;
	act.sa_mask = mask;
	act.sa_flags = 0;

	sigaction(SIGUSR2, &act, NULL);

	act.sa_handler = sig_usr1_handler;
	sigaction(SIGUSR1, &act, NULL);

	act.sa_handler = sig_quit_program;
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGHUP, &act, NULL);

	act.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &act, NULL);

}

static void setup_run_mode(int run_mode)
{
	init_mux_log(run_mode);

	if (run_mode == DAEMON_MODE) {
		daemon(1, 0);
	}

}

static int peek_first_packet_data(int conn_fd, char *buf, int buf_len,
				  int timeout)
{
	struct msghdr msg;
	struct iovec iovec;
	int len;

	iovec.iov_base = buf;
	iovec.iov_len = buf_len;
	msg.msg_name = NULL;
	msg.msg_iov = &iovec;
	msg.msg_iovlen = 1;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;

	len = recvmsg(conn_fd, &msg, MSG_PEEK);

	if (len <= 0) {
		log_debug("peek first packet data failed\n");
		return -1;
	}

	log_debug("get first packet:  [%d] bytes\n", len);

	return len;

}

static int handle_new_connection(int conn_fd)
{
	int ret;
	char buf[1024];
	int buf_len = 1023;
	char proto_name[64];
	int name_len = 64;
	int timeout = 20;
	struct timeval tv;

	if (g_run_mode == DEBUG_MODE)
		tv.tv_sec = 10;
	else
		tv.tv_sec = 0;

	tv.tv_usec = timeout * 1000;

	if (setsockopt(conn_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
		log_error("setsockopt error [%s]\n", strerror(errno));

	ret = peek_first_packet_data(conn_fd, buf, buf_len, timeout);
	if (ret < 0)
		return ret;

	/* restore to original to value */
	tv.tv_sec = 0;
	tv.tv_usec = 0;

	if (setsockopt(conn_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
		log_error("setsockopt error [%s]\n", strerror(errno));

	buf_len = ret;

	buf[ret] = 0x0;

	log_debug("packet data [%s]\n", buf);

	ret = identify_proto_name(buf, buf_len, proto_name, name_len);

	if (ret < 0)
		return ret;

	ret = deliver_proxy_connection(conn_fd, proto_name);

	if (ret < 0)
		return exec_proto_server(conn_fd, proto_name);
	else
		return 0;
}

static void dump_config(void)
{
	log_info("config file: %s\n", conf_file);

	log_info("log level:%d\n", get_log_level());

	dump_all_xmodules();
	dump_all_proto_idents();
	dump_all_proto_servers();
	dump_all_proxy_servers();
	dump_all_intern_idents();

}

static int inetd_mode_run(void)
{
	return handle_new_connection(0);
}

static void usage(const char *prog)
{
	printf("usage:  %s [-b ip] [-p port] [-c conf_file] [-d|i] "
	       "[-l log_level] [-h]\n\n", prog);

	printf("\t -b ip\t\t\tip address to bind\n");
	printf("\t -p port\t\tport to isten\n");
	printf("\t -c conf_file\t\tconfiguration file path\n");
	printf("\t -d|-i\t\t\tdeamon mode or inetd mode\n");
	printf("\t -l log_level\t\tset log level: 1-info,2-debug\n");
	printf("\t -h\t\t\tshow this information\n");
}

static char *search_default_conf_file(void)
{
	char *predefined[] = {
		"/etc/tcpmux.cfg",
		"./tcpmux.cfg",
		"/usr/local/etc/tcpmux.cfg",
		NULL
	};

	char *p;
	struct stat stat_buf;
	int i = 0;

	while (predefined[i]) {
		p = predefined[i++];

		if (stat(p, &stat_buf))
			continue;

		return p;
	}

	return NULL;
}

int main(int argc, char *argv[])
{
	int res;
	int check_bind_addr_config = 1;
	int check_listen_port_config = 1;
	int check_log_level_config = 1;
	int conf_file_set = 0;
	int listen_fd;
	int conn_fd;
	unsigned int bind_addr = INADDR_ANY;
	int listen_port = -1;
	int log_level = LOG_LEVEL_INFO;

	struct sockaddr_in clnt_addr;
	unsigned int clnt_addr_len = sizeof(clnt_addr);

	prog_name = strchr(argv[0], '/');
	if (prog_name)
		prog_name++;
	else
		prog_name = argv[0];

	while ((res = getopt(argc, argv, "b:p:c:dil:h")) != -1) {
		switch (res) {
		case 'b':
			check_bind_addr_config = 0;
			bind_addr = inet_addr(optarg);
			break;
		case 'p':
			check_listen_port_config = 0;
			listen_port = atoi(optarg);
			break;
		case 'c':
			conf_file = optarg;
			conf_file_set = 1;
			break;
		case 'd':
			g_run_mode = DAEMON_MODE;
			break;
		case 'i':
			g_run_mode = INETD_MODE;
			break;
		case 'l':
			log_level = strtoul(optarg, NULL, 10);
			check_log_level_config = 0;
			break;
		case 'h':
		default:
			usage(prog_name);
			exit(0);

		}

	}

	set_log_level(log_level);

	setup_run_mode(g_run_mode);

	if (!conf_file_set)
		conf_file = search_default_conf_file();

	if (conf_file == NULL) {
		log_error("no proper configure can be found!\n");
		exit(1);
	}

	install_intern_proto_identifiers();

	setup_signal();

reinit:

	if (parse_conf(conf_file) < 0) {
		log_error("failed to parse config file [%s]\n", conf_file);
		exit(1);
	}

	if (check_log_level_config && get_conf_log_level(&log_level) == 0) {
		set_log_level(log_level);
	}

	if (g_need_reinit) {
		g_need_reinit = 0;
		goto restart;
	}

	if (g_run_mode == INETD_MODE)
		return inetd_mode_run();

	if (check_bind_addr_config)
		get_conf_bind_addr(&bind_addr);

	if (check_listen_port_config)
		get_conf_listen_port(&listen_port);

	if (listen_port < 0) {
		log_error
		    ("please set listen port in command line or in config file [%s]\n",
		     conf_file);

		exit(2);
	}

	listen_fd = setup_listen_socket(bind_addr, listen_port);

	if (listen_fd < 0) {
		log_error("failed to listen at port [%d]\n", listen_port);
		exit(2);
	}

restart:

	while (1) {

		conn_fd = accept(listen_fd, (struct sockaddr *)&clnt_addr,
				 &clnt_addr_len);

		if (conn_fd < 0) {
			if (errno != EINTR) {
				log_error("accept failed! quit now ...\n");
				g_quit_program = 1;
				break;
			}

			if (g_need_quit_loop)
				break;

			continue;
		}

		handle_new_connection(conn_fd);
		close(conn_fd);
	}

	if (g_quit_program) {
		log_info("[%s] stopped running\n", prog_name);
		exit(0);
	}

	g_need_quit_loop = 0;

	if (g_need_reinit) {

		/* cleanup extension modules first */
		unregister_all_xmodule();
		unregister_all_proxy_server();
		unregister_all_proto_identifier();
		unregister_all_proto_server();

		check_log_level_config = 1;

		goto reinit;
	}

	if (g_dump_config) {
		g_dump_config = 0;
		dump_config();
	}

	goto restart;

}
