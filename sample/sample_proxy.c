#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <sys/select.h>

static int handle_passing_fd(int unix_fd)
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

int echo_conn_data(int conn_fd)
{
	char buf[128];
	int ret;

	ret = read(conn_fd, buf, 128);

	if (ret <= 0)
		return -1;

	write(conn_fd, buf, ret);

	return 0;

}

const char *proxy_path = "/tmp/unix.proxy.0";

int main(int argc, char *argv[])
{
	int listen_fd;
	int epoll_fd;
	int conn_fd;
	struct sockaddr_un un;
	socklen_t len = sizeof(un);
	struct epoll_event ev, events[8];

	listen_fd = setup_unix_server(proxy_path);

	if (listen_fd < 0)
		exit(1);

	epoll_fd = epoll_create1(0);

	if (epoll_fd < 0)
		exit(2);

	ev.events = EPOLLIN;
	ev.data.fd = listen_fd;

	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &ev) < 0)
		exit(3);

	while (1) {

		int nfds;
		int ev_fd;

		nfds = epoll_wait(epoll_fd, events, 8, -1);

		if (nfds <= 0)
			return -1;

		for (int i = 0; i < nfds; i++) {
			ev_fd = events[i].data.fd;
			if (ev_fd == listen_fd) {
				conn_fd =
				    accept(listen_fd, (struct sockaddr *)&un,
					   &len);

				if (conn_fd <= 0)
					exit(4);

				printf("new connection arrived [%d]\n",
				       conn_fd);
				ev.data.u64 = 0;
				ev.events = EPOLLIN;
				ev.data.fd = conn_fd;

				if (epoll_ctl
				    (epoll_fd, EPOLL_CTL_ADD, conn_fd, &ev) < 0)
					close(conn_fd);
			} else {
				int flag;
				int ret;

				flag = events[i].data.u64 >> 32;

				if (flag) {
					ret = echo_conn_data(ev_fd);

					if (ret < 0) {
						epoll_ctl(epoll_fd,
							  EPOLL_CTL_DEL, ev_fd,
							  NULL);
						close(ev_fd);
						printf
						    ("close passing fd [%d]\n",
						     ev_fd);
					}

				} else {
					ret = handle_passing_fd(ev_fd);

					if (ret < 0) {
						printf
						    ("close connection [%d]\n",
						     ev_fd);
						epoll_ctl(epoll_fd,
							  EPOLL_CTL_DEL, ev_fd,
							  NULL);
						close(ev_fd);
					} else {

						printf
						    ("add new passing fd [%d]\n",
						     ret);
						ev.events = EPOLLIN;
						ev.data.u64 = (1ULL << 32);
						ev.data.fd = ret;
						epoll_ctl(epoll_fd,
							  EPOLL_CTL_ADD, ret,
							  &ev);
					}
				}

			}
		}
	}

	return 0;

}
