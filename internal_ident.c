#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "list.h"
#include "mux_log.h"
#include "internal_ident.h"
#include "sample_intern_ident.h"

struct intern_ident {
	char *name;
	intern_ident_func_t probe;
	int priority;
	int disabled;
	struct list link;
};

static LIST_HEAD(intern_ident_list);

static void init_intern_ident(struct intern_ident *p_ident)
{
	p_ident->name = NULL;
	p_ident->priority = 255;
	p_ident->disabled = 1;
	p_ident->probe = NULL;
	list_init(&p_ident->link);
}

static void release_intern_ident(struct intern_ident *p_ident)
{
	free(p_ident->name);
	free(p_ident);
}

static struct intern_ident *find_intern_ident_by_name(const char *name)
{
	struct intern_ident *p_ident;

	list_for_each_entry(p_ident, &intern_ident_list, link) {
		if (!strcmp(p_ident->name, name))
			return p_ident;
	}
	return NULL;
}

static int insert_new_intern_ident(struct intern_ident *p_ident)
{
	struct intern_ident *pos;

	list_for_each_entry(pos, &intern_ident_list, link) {
		if (pos->priority > p_ident->priority)
			break;
	}

	list_prepend(&p_ident->link, &pos->link);

	return 0;
}

int set_intern_proto_identifier_priority(const char *name, int priority)
{
	struct intern_ident *p_ident;

	p_ident = find_intern_ident_by_name(name);

	if (p_ident == NULL)
		return -1;

	list_remove(&p_ident->link);

	p_ident->priority = priority;

	return insert_new_intern_ident(p_ident);
}

int set_intern_proto_ident_disable(const char *name, int disable)
{
	struct intern_ident *p_ident;

	p_ident = find_intern_ident_by_name(name);

	if (p_ident == NULL)
		return -1;

	p_ident->disabled = disable;

	return 0;
}

int register_intern_proto_ident(const char *name, int priority,
				  intern_ident_func_t func)
{
	struct intern_ident *p_ident;

	if (find_intern_ident_by_name(name))
		return -1;

	p_ident = malloc(sizeof(struct intern_ident));

	if (p_ident == NULL)
		return -1;

	init_intern_ident(p_ident);

	p_ident->name = strdup(name);
	p_ident->priority = priority;
	p_ident->probe = func;

	insert_new_intern_ident(p_ident);

	return 0;

}

int unregsiter_intern_proto_ident(const char *name)
{
	struct intern_ident *p_ident;

	p_ident = find_intern_ident_by_name(name);

	if (p_ident == NULL)
		return -1;

	list_remove(&p_ident->link);

	release_intern_ident(p_ident);

	return 0;

}

void disable_all_intern_proto_idents(void)
{
	struct intern_ident *p_ident;

	list_for_each_entry(p_ident, &intern_ident_list, link) {
		p_ident->disabled = 1;

	}
}

static void dump_intern_ident_entry(struct intern_ident *p_ident)
{
	log_info("internal identifier: name [%s] priority[%d] disabled[%d]\n",
		 p_ident->name, p_ident->priority, p_ident->disabled);
}

void dump_all_intern_idents(void)
{
	int count = 0;
	struct intern_ident *p_ident;

	list_for_each_entry(p_ident, &intern_ident_list, link) {
		dump_intern_ident_entry(p_ident);
		count++;
	}

	log_info("total [%d] internal identifier registerd\n", count);
}

static int try_to_identify_protocol(const char *packet_data, int data_len,
				    char *proto_name, int name_len,
				    struct intern_ident *p_ident)
{

	int ret;

	log_debug("internal ident [%s] will analyze packet (len[%d])\n",
		  p_ident->name, data_len);

	ret = p_ident->probe(packet_data, data_len, proto_name, name_len);

	log_debug("probe result: ret = [%d]\n", ret);

	return ret;
}

int intern_identity_protocol(const char *packet_data, int data_len,
			       char *proto_name, int name_len)
{
	struct intern_ident *p_ident;

	list_for_each_entry(p_ident, &intern_ident_list, link) {
		if (!p_ident->disabled) {
			if (!try_to_identify_protocol
			    (packet_data, data_len, proto_name, name_len,
			     p_ident))
				return 0;

		}

	}

	return -1;
}

void install_intern_proto_identifiers(void)
{
	install_echo_proto_identifier();
	install_ssh_proto_identifier();
	install_http_proto_identifier();
}
