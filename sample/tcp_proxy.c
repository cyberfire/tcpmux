#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <malloc.h>
#include <fcntl.h>
#include <signal.h>
#include <syslog.h>

#include "list.h"

#define F_DATA_FD   0
#define F_LISTEN_FD 1
#define F_PASS_FD   2
#define F_CONN_FD  3
#define F_CLOSED_FD  4

#define MAX_CONTEXT_NUM  max_context_num
#define MAX_EPOLL_EVENTS 64

struct conn_context {
	int flag;
	int fd;
	struct conn_context *peer;
	struct list link;
};

static LIST_HEAD(conn_context_list);
static LIST_HEAD(cleanup_list);
static int context_count = 0;
static const char *service_path = "/tmp/unix.proxy.0";
static const char *tcp_ip = "127.0.0.1";
static int tcp_port = 80;
static int max_context_num = 1024;
static int quit_flag = 0;

static void insert_conn_context(struct conn_context *p_context)
{

	list_insert(&p_context->link, &conn_context_list);
	context_count++;
}

static void remove_conn_context(struct conn_context *p_context)
{
	list_remove(&p_context->link);
	context_count--;
}

static struct conn_context *new_conn_context(void)
{
	struct conn_context *p_context;

	if (context_count >= MAX_CONTEXT_NUM)
		return NULL;

	p_context = malloc(sizeof(struct conn_context));

	if (p_context == NULL)
		return NULL;

	p_context->flag = F_DATA_FD;
	p_context->fd = -1;
	p_context->peer = NULL;
	list_init(&p_context->link);

	return p_context;
}

static void reclaim_cleanup_list(void)
{
	struct conn_context *p_context;
	struct conn_context *p_dummy;

	list_for_each_entry_safe(p_context, p_dummy, &cleanup_list, link) {
		list_remove(&p_context->link);
		free(p_context);
	}

}

static void release_data_connection(struct conn_context *p_context,
				    int epoll_fd)
{
	struct conn_context *peer;

	peer = p_context->peer;

	epoll_ctl(epoll_fd, EPOLL_CTL_DEL, p_context->fd, NULL);
	epoll_ctl(epoll_fd, EPOLL_CTL_DEL, peer->fd, NULL);

	close(p_context->fd);
	close(peer->fd);

	remove_conn_context(p_context);
	remove_conn_context(peer);

	free(p_context);

	/* set flag to skip latter epoll event including the peer fd */
	peer->flag = F_CLOSED_FD;
	list_insert(&peer->link, &cleanup_list);
}

static int get_new_passing_fd(int unix_fd)
{
	int newfd;

	unsigned int magic;
	struct iovec iov;
	struct msghdr msg;
	struct cmsghdr *p_cmsg;
	char buf[128];
	int ret;

	iov.iov_base = (void *)&magic;
	iov.iov_len = sizeof(magic);

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_name = NULL;
	msg.msg_namelen = 0;

	p_cmsg = (void *)buf;

	msg.msg_control = p_cmsg;
	msg.msg_controllen = CMSG_LEN(sizeof(int));

	ret = recvmsg(unix_fd, &msg, 0);

	if (ret <= 0 || ret != iov.iov_len)
		return -1;

	newfd = *(int *)CMSG_DATA(p_cmsg);

	return newfd;
}

static int setup_unix_server(const char *channel)
{
	int fd;

	struct sockaddr_un un;

	if (strlen(channel) >= sizeof(un.sun_path))
		return -1;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);

	if (fd < 0)
		return -1;

	unlink(channel);

	memset(&un, 0, sizeof(un));

	un.sun_family = AF_UNIX;
	strcpy(un.sun_path, channel);

	if (bind(fd, (struct sockaddr *)&un, sizeof(un)) < 0) {
		close(fd);
		return -1;
	}

	if (listen(fd, 10) < 0) {
		close(fd);
		return -1;
	}

	return fd;
}

int handle_new_client(struct conn_context *p_context, int epoll_fd)
{
	int conn_fd;
	struct sockaddr_un un;
	socklen_t len = sizeof(un);
	struct conn_context *p_new;
	struct epoll_event ev;

	conn_fd = accept(p_context->fd, (struct sockaddr *)&un, &len);

	if (conn_fd < 0)
		return -1;

	p_new = new_conn_context();

	if (p_new == NULL)
		return 0;

	p_new->fd = conn_fd;
	p_new->flag = F_PASS_FD;

	ev.events = EPOLLIN;
	ev.data.ptr = p_new;

	insert_conn_context(p_new);

	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, conn_fd, &ev) < 0) {
		remove_conn_context(p_new);
	}

	return 0;

}

static void handle_pass_fd(struct conn_context *p_context, int epoll_fd)
{
	int new_fd;
	int peer_fd;
	struct conn_context *p_new;
	struct conn_context *p_peer;
	struct sockaddr_in srv_addr;
	socklen_t len;
	struct epoll_event ev;

	new_fd = get_new_passing_fd(p_context->fd);

	if (new_fd < 0) {
		epoll_ctl(epoll_fd, EPOLL_CTL_DEL, p_context->fd, NULL);
		close(p_context->fd);

		remove_conn_context(p_context);

		free(p_context);

		return;
	}

	p_new = new_conn_context();

	if (p_new == NULL) {
		goto error;
	}

	p_peer = new_conn_context();

	if (p_peer == NULL) {
		free(p_new);
		goto error;
	}

	peer_fd = socket(AF_INET, SOCK_STREAM, 0);

	if (peer_fd < 0)
		goto error0;

	if (fcntl(peer_fd, F_SETFL, O_NONBLOCK) < 0)
		goto error0;

	len = sizeof(srv_addr);

	memset(&srv_addr, 0, sizeof(srv_addr));

	srv_addr.sin_family = AF_INET;
	srv_addr.sin_addr.s_addr = inet_addr(tcp_ip);
	srv_addr.sin_port = htons(tcp_port);

	connect(peer_fd, (struct sockaddr *)&srv_addr, len);

	p_new->peer = p_peer;
	p_new->fd = new_fd;
	p_new->flag = F_DATA_FD;

	p_peer->fd = peer_fd;
	p_peer->peer = p_new;
	p_peer->flag = F_CONN_FD;

	ev.events = EPOLLOUT;
	ev.data.ptr = p_peer;

	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, peer_fd, &ev) < 0)
		goto error0;

	insert_conn_context(p_new);
	insert_conn_context(p_peer);

	return;

error0:
	free(p_new);
	free(p_peer);
	close(peer_fd);

error:
	close(new_fd);
	return;
}

static void handle_server_fd(struct conn_context *p_context, int epoll_fd)
{
	int fd = p_context->fd;
	int flag;
	int flag_len = sizeof(flag);
	struct conn_context *p_peer;
	struct epoll_event ev;

	p_peer = p_context->peer;

	if (getsockopt
	    (fd, SOL_SOCKET, SO_ERROR, &flag, (socklen_t *) & flag_len) < 0
	    || flag != 0) {
		epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);
		close(fd);

		remove_conn_context(p_context);
		remove_conn_context(p_peer);

		close(p_peer->fd);

		free(p_context);
		free(p_peer);
		return;
	}

	/* connection ok */
	p_context->flag = F_DATA_FD;
	ev.events = EPOLLIN;
	ev.data.ptr = p_context;
	epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev);

	ev.data.ptr = p_peer;
	epoll_ctl(epoll_fd, EPOLL_CTL_ADD, p_peer->fd, &ev);

}

static void handle_new_data(struct conn_context *p_context, int epoll_fd)
{
	char buf[1024];
	int ret;
	int fd, peer_fd;

	fd = p_context->fd;
	peer_fd = p_context->peer->fd;

	ret = recv(fd, buf, 1024, 0);

	if (ret <= 0) {
		release_data_connection(p_context, epoll_fd);
		return;
	}

	send(peer_fd, buf, ret, 0);

}

static void quit_program(int sig)
{
	quit_flag = 1;
}

static void setup_signal(void)
{
	struct sigaction act;
	sigset_t mask;

	sigemptyset(&mask);

	act.sa_mask = mask;
	act.sa_flags = 0;
	act.sa_handler = quit_program;

	sigaction(SIGINT, &act, NULL);
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGQUIT, &act, NULL);
	sigaction(SIGHUP, &act, NULL);

	act.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &act, NULL);

}

static void usage(char *prog)
{

	printf("usage:   %s [-a tcp_ip] [-p tcp_port] [-d] [-s serv_path] "
	       "[-n max_conn_num] [-h]\n\n", prog);
	printf("\t -a tcp_ip ip \t\taddress of tcp server\n");
	printf("\t -p tcp_port \t\tport of tcp server\n");
	printf("\t -d \t\t\tdaemon mode\n");
	printf("\t -s serv_path \t\tthe unix socket path\n");
	printf("\t -n max_conn_num \tmaximum connection number "
	       "to be proxied\n");
	printf("\t -h\t\t\tshow this information\n");
}

int main(int argc, char *argv[])
{

	int listen_fd;
	int epoll_fd;
	struct epoll_event ev, events[MAX_EPOLL_EVENTS];
	struct conn_context *p_context;
	char *prog_name;
	int res;
	int daemon_mode = 0;

	prog_name = strrchr(argv[0], '/');

	if (prog_name)
		prog_name++;
	else
		prog_name = argv[0];

	while ((res = getopt(argc, argv, "a:p:ds:n:h")) != -1) {
		switch (res) {
		case 'a':
			tcp_ip = optarg;
			break;
		case 'p':
			tcp_port = strtoul(optarg, NULL, 10);
			break;
		case 'd':
			daemon_mode = 1;
			break;
		case 's':
			service_path = optarg;
			break;
		case 'n':
			max_context_num = strtoul(optarg, NULL, 10) * 2;
			break;
		case 'h':
		default:
			usage(prog_name);
			return 0;
		}
	}

	if (daemon_mode) {
		daemon(0, 0);
		syslog(LOG_INFO,
		       "%s: service path [%s] max connection num [%d] "
		       "tcp at [%s:%d]\n", prog_name, service_path,
		       max_context_num / 2, tcp_ip, tcp_port);
	} else {
		printf("tcp proxy: service path [%s] max connection num [%d] "
		       "tcp at [%s:%d]\n",
		       service_path, max_context_num / 2, tcp_ip, tcp_port);
	}

	setup_signal();

	listen_fd = setup_unix_server(service_path);

	if (listen_fd < 0)
		exit(1);

	epoll_fd = epoll_create1(0);

	if (epoll_fd < 0)
		exit(2);

	p_context = new_conn_context();

	if (p_context == NULL)
		exit(3);

	p_context->flag = F_LISTEN_FD;
	p_context->fd = listen_fd;
	insert_conn_context(p_context);

	ev.events = EPOLLIN;
	ev.data.ptr = p_context;

	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &ev) < 0)
		exit(3);

	while (!quit_flag) {

		int nfds;

		nfds = epoll_wait(epoll_fd, events, MAX_EPOLL_EVENTS, -1);

		if (nfds <= 0)
			break;

		for (int i = 0; i < nfds; i++) {
			p_context = events[i].data.ptr;

			switch (p_context->flag) {
			case F_LISTEN_FD:
				if (handle_new_client(p_context, epoll_fd) < 0)
					quit_flag = 1;
				break;

			case F_PASS_FD:
				handle_pass_fd(p_context, epoll_fd);
				break;
			case F_CONN_FD:
				handle_server_fd(p_context, epoll_fd);
				break;

			case F_DATA_FD:
				handle_new_data(p_context, epoll_fd);
				break;

				break;
			case F_CLOSED_FD:
				break;

			}

		}

		reclaim_cleanup_list();

	}

	if (daemon_mode)
		syslog(LOG_INFO, "%s: down nicely\n", prog_name);
	else
		printf("%s: down nicely\n", prog_name);

	return 0;
}
