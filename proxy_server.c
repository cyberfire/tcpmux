#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "list.h"
#include "mux_log.h"
#include "proxy_server.h"

struct proxy_server {
	char *proto;
	char *channel;
	int fd;
	int connected;
	struct list link;
};

static LIST_HEAD(proxy_server_list);

static void init_proxy_server(struct proxy_server *p_proxy)
{
	p_proxy->proto = NULL;
	p_proxy->channel = NULL;
	p_proxy->fd = -1;
	p_proxy->connected=0;
	list_init(&p_proxy->link);
}

static void release_proxy_server(struct proxy_server *p_proxy)
{
	free(p_proxy->proto);
	free(p_proxy->channel);
	free(p_proxy);
}

static struct proxy_server *find_proxy_server_by_proto(const char *proto)
{
	struct proxy_server *p_proxy;

	list_for_each_entry(p_proxy, &proxy_server_list, link) {
		if (!strcmp(p_proxy->proto, proto))
			return p_proxy;
	}
	return NULL;
}

int connect_proxy_server(struct proxy_server *p_proxy)
{
	int fd;
	struct sockaddr_un un;

	if (strlen(p_proxy->channel) >= sizeof(un.sun_path))
		return -1;

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
		return -1;

	memset(&un, 0, sizeof(un));

	un.sun_family = AF_UNIX;
	strcpy(un.sun_path, p_proxy->channel);

	if (connect(fd, (struct sockaddr *)&un, sizeof(un)) < 0) {
		close(fd);
		return -1;
	}

	p_proxy->fd = fd;

	return 0;
}

int register_proxy_server(const char *proto, const char *channel)
{
	struct proxy_server *p_proxy;

	if (find_proxy_server_by_proto(proto))
		return -1;

	p_proxy = malloc(sizeof(struct proxy_server));

	if (p_proxy == NULL)
		return -1;

	init_proxy_server(p_proxy);

	p_proxy->proto = strdup(proto);
	p_proxy->channel = strdup(channel);

	
	list_prepend(&p_proxy->link, &proxy_server_list);

	connect_proxy_server(p_proxy);
	
	return 0;

}

int unregister_proxy_server(const char *proto)
{
	struct proxy_server *p_proxy;

	p_proxy = find_proxy_server_by_proto(proto);

	if (p_proxy == NULL)
		return -1;

	if(p_proxy->fd>=0)
		close(p_proxy->fd);

	list_remove(&p_proxy->link);
	release_proxy_server(p_proxy);

	return 0;
}

void unregister_all_proxy_server(void)
{
	struct proxy_server *p_proxy;
	struct proxy_server *p_dummy;

	list_for_each_entry_safe(p_proxy, p_dummy, &proxy_server_list, link) {
		unregister_proxy_server(p_proxy->proto);
	}
}

static void dump_proxy_server_entry(struct proxy_server *p_proxy)
{
	log_info("proxy server: proto[%s] channel[%s] fd[%d]\n",
		 p_proxy->proto, p_proxy->channel, p_proxy->fd);
}

void dump_all_proxy_servers(void)
{
	int count = 0;
	struct proxy_server *p_proxy;

	list_for_each_entry(p_proxy, &proxy_server_list, link) {
		dump_proxy_server_entry(p_proxy);
		count++;
	}

	log_info("total [%d] proxy server registerd\n", count);
}

static int send_fd(int unix_fd, int conn_fd)
{
	struct iovec iov;
	struct msghdr msg;
	unsigned int magic;
	struct cmsghdr *p_cmsg;
	char buf[128];

	magic = 0xdeadbeaf;

	iov.iov_base = &magic;
	iov.iov_len = sizeof(magic);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_name = NULL;
	msg.msg_namelen = 0;

	p_cmsg = (void *)buf;

	p_cmsg->cmsg_level = SOL_SOCKET;
	p_cmsg->cmsg_type = SCM_RIGHTS;
	p_cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	*(int *)CMSG_DATA(p_cmsg) = conn_fd;

	msg.msg_control = p_cmsg;
	msg.msg_controllen = p_cmsg->cmsg_len;

	if (sendmsg(unix_fd, &msg, 0) != iov.iov_len)
		return -1;

	return 0;

}

static int real_deliver_proxy_connection(struct proxy_server *p_proxy, 
                                         int conn_fd)
{
	if (p_proxy->fd<0 || send_fd(p_proxy->fd, conn_fd) < 0) {

		if(p_proxy->fd>=0)
		{
			close(p_proxy->fd);
			p_proxy->fd=-1;
		}

		//try to connect again
		if(connect_proxy_server(p_proxy)<0)
			return -1;
			
		if(send_fd(p_proxy->fd,conn_fd)<0)
		{
		    close(p_proxy->fd);
		    p_proxy->fd=-1;
		   return -1;
		}

		return 0;
	}

	return 0;
}

int deliver_proxy_connection(int conn_fd, const char *proto)
{
	   int ret;

   	struct proxy_server *p_proxy;

	p_proxy = find_proxy_server_by_proto(proto);

	if (p_proxy == NULL)
		return -1;

	 ret=real_deliver_proxy_connection(p_proxy,conn_fd);

	 if(ret<0)
	 	log_debug("proto [%s] proxied to [%s] failed!\n", 
						proto, p_proxy->channel);
	 else
		log_debug("proto [%s] proxied to [%s] done\n", proto, p_proxy->channel);

	return ret;
}
