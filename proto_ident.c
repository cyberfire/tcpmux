#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "list.h"
#include "mux_log.h"
#include "proto_ident.h"
#include "internal_ident.h"

struct proto_ident {
	struct list link;
	char *name;
	char *app_name;
	int priority;
	int disabled;
};

static LIST_HEAD(proto_ident_list);

static void init_proto_ident(struct proto_ident *p_ident)
{
	list_init(&p_ident->link);
	p_ident->app_name = NULL;
	p_ident->name = NULL;
	p_ident->priority = 255;
	p_ident->disabled = 1;

}

static void release_proto_ident(struct proto_ident *p_ident)
{
	free(p_ident->name);
	free(p_ident->app_name);
	free(p_ident);
}

static int insert_new_ident(struct proto_ident *p_ident)
{
	struct proto_ident *pos;

	list_for_each_entry(pos, &proto_ident_list, link) {
		if (pos->priority > p_ident->priority)
			break;
	}

	list_prepend(&p_ident->link, &pos->link);

	return 0;
}

static struct proto_ident *find_proto_ident_by_name(const char *name)
{
	struct proto_ident *p_ident;

	list_for_each_entry(p_ident, &proto_ident_list, link) {
		if (!strcmp(p_ident->name, name))
			return p_ident;
	}

	return NULL;
}

int register_proto_identifier(const char *name, const char *app, int priority)
{
	struct proto_ident *p_ident;

	if (find_proto_ident_by_name(name))
		return -1;

	p_ident = malloc(sizeof(struct proto_ident));

	if (p_ident == NULL)
		return -1;

	init_proto_ident(p_ident);

	p_ident->name = strdup(name);
	p_ident->app_name = strdup(app);
	p_ident->priority = priority;

	insert_new_ident(p_ident);

	return 0;
}

int unregister_proto_identifier(const char *name)
{
	struct proto_ident *p_ident;

	p_ident = find_proto_ident_by_name(name);

	if (p_ident == NULL)
		return -1;

	list_remove(&p_ident->link);

	release_proto_ident(p_ident);

	return 0;
}

int set_proto_ident_disable(const char *name, int disable)
{
	struct proto_ident *p_ident;

	p_ident = find_proto_ident_by_name(name);

	if (p_ident == NULL)
		return -1;

	p_ident->disabled = disable;

	return 0;

}

static void dump_proto_ident_entry(struct proto_ident *p_ident)
{
	log_info
	    ("proto identifier: name [%s] app[%s] priority[%d] disabled[%d]\n",
	     p_ident->name, p_ident->app_name, p_ident->priority,
	     p_ident->disabled);
}

void dump_all_proto_idents(void)
{
	int count = 0;
	struct proto_ident *p_ident;

	list_for_each_entry(p_ident, &proto_ident_list, link) {
		dump_proto_ident_entry(p_ident);
		count++;
	}

	log_info("total [%d] protocol identifier registerd\n", count);
}

void unregister_all_proto_identifier(void)
{
	struct proto_ident *p_ident;
	struct proto_ident *p_dummy;

	list_for_each_entry_safe(p_ident, p_dummy, &proto_ident_list, link) {

		unregister_proto_identifier(p_ident->name);
	}
}

/* 
 protocol between the external app and parent program are:
 stdin 0 ---- parent will write the packet_data , at most 1000
 stdout 1 ---- will return the protocol name string or "NOTFOUND" if cannot identify the packet
 stderr 2 ---   redirect to /dev/null

 exit code --- 0, means meaningful result returned
 */

static int external_identity_protocol(const char *packet_data, int data_len,
				      char *proto_name, int name_len,
				      const char *app_name)
{
	int wpipe[2];
	int rpipe[2];
	int child_pid;
	int ret;
	int child_status;
	char buf[256];
	int buf_len = 256;

	pipe(wpipe);
	pipe(rpipe);

	child_pid = fork();

	if (child_pid == -1)
		return -1;

	if (child_pid == 0) {
		int fd = open("/dev/null", O_WRONLY);

		dup2(wpipe[0], 0);
		dup2(rpipe[1], 1);
		dup2(fd, 2);

		close(wpipe[0]);
		close(wpipe[1]);
		close(rpipe[0]);
		close(rpipe[1]);
		close(fd);

		set_mux_log_daemon_mode(NULL);

		log_debug("execl [%s] to identify packet [%d]\n", app_name,
			  data_len);

		execl(app_name, app_name, NULL);

		log_error("exec[%s] failed. reason [%s]\n", app_name,
			  strerror(errno));

		exit(1);
	}

	close(rpipe[1]);
	close(wpipe[0]);

	if (data_len > 1000)
		data_len = 1000;

	ret = write(wpipe[1], packet_data, data_len);

	if (ret != data_len)
		goto error;

	ret = read(rpipe[0], buf, buf_len - 1);

	if (ret <= 0)
		goto error;

	buf[ret] = 0;

	waitpid(child_pid, &child_status, 0);

	if (!WIFEXITED(child_status) || WEXITSTATUS(child_status)) {
		log_error("child failured: reason [%s]\n", buf);
		return -1;
	}

	log_debug("child returned: [%s]\n", buf);

	if (!strcmp(buf, TOKEN_NOTFOUND))
		return -1;

	if (name_len < ret + 1) {
		log_error
		    ("child returned proto [%s], while name buf size is too small [%d]\n",
		     buf, name_len);

		return -1;
	}

	strcpy(proto_name, buf);

	return 0;

error:
	waitpid(child_pid, &child_status, 0);
	return -1;
}

static int try_to_identify_protocol(const char *packet_data, int data_len,
				    char *proto_name, int name_len,
				    struct proto_ident *p_ident)
{
	int ret;

	log_debug
	    ("proto ident [%s] will call [%s] to analyze packet (len[%d])\n",
	     p_ident->name, p_ident->app_name, data_len);

	if (!strcmp(p_ident->name, INTERNAL_PROTO_IDENT_NAME)) {
		ret =
		    intern_identity_protocol(packet_data, data_len,
					       proto_name, name_len);
	} else {
		ret =
		    external_identity_protocol(packet_data, data_len,
					       proto_name, name_len,
					       p_ident->app_name);
	}

	if (ret)
		log_debug("ident [%s] probe result: NOT FOUND\n",
			  p_ident->name);
	else
		log_debug("ident [%s] probe result: protocol name [%s]\n",
			  p_ident->name, proto_name);

	return ret;
}

int identify_proto_name(const char *packet_data, int data_len, char *proto_name,
			int name_len)
{
	struct proto_ident *p_ident;

	list_for_each_entry(p_ident, &proto_ident_list, link) {
		if (!p_ident->disabled) {
			if (!try_to_identify_protocol
			    (packet_data, data_len, proto_name, name_len,
			     p_ident))
				return 0;

		}

	}

	return -1;
}
