#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libconfig.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include "config_parser.h"
#include "proto_ident.h"
#include "proto_server.h"
#include "internal_ident.h"
#include "proxy_server.h"
#include "xmodule.h"

#include "mux_log.h"

static config_t g_conf;
static const char *conf_version = NULL;
static int conf_addr_set = 0;
static int conf_port_set = 0;
static int conf_log_level_set = 0;
static int conf_log_level = 0;
static unsigned int conf_bind_addr;
static int conf_listen_port;

static int check_conf_version_compat(const char *conf_ver)
{
	/*will add version compatible checking here */
	return 1;
}

static int init_config(const char *conf_file, config_t * conf)
{

	const char *ver;
	config_init(conf);

	if (config_read_file(conf, conf_file) == CONFIG_FALSE) {
		if (config_error_line(conf) != 0) {
			log_error("%s:%d:%s\n", conf_file,
				  config_error_line(conf),
				  config_error_text(conf));
			goto error;

		}
		log_error("%s:%s\n", conf_file, config_error_text(conf));

		goto error;
	}

	if (config_lookup_string(conf, "version", &ver) == CONFIG_FALSE)
		goto error;

	if (check_conf_version_compat(ver) < 0)
		goto error;

	conf_version = strdup(ver);

	return 0;

error:
	config_destroy(conf);

	return -1;

}

static void set_conf_log_level(config_t * conf)
{

	if (config_lookup_int(conf, "log_level", &conf_log_level) ==
	    CONFIG_TRUE) {
		conf_log_level_set = 1;
	}
}

static void set_conf_addr_port(config_t * conf)
{
	const char *addr;

	if (config_lookup_string(conf, "bind_addr", &addr) == CONFIG_TRUE) {
		conf_bind_addr = inet_addr(addr);
		conf_addr_set = 1;
	}

	if (config_lookup_int(conf, "listen_port", &conf_listen_port) ==
	    CONFIG_TRUE) {
		conf_port_set = 1;
	}
}

static int set_conf_proto_identifier(config_t * conf)
{
	config_setting_t *set;
	config_setting_t *id_entry;
	int id_num;
	int i;
	int id_count = 0;

	set = config_lookup(conf, "proto_identifier");

	if (set == NULL)
		return 0;

	id_num = config_setting_length(set);

	for (i = 0; i < id_num; i++) {
		const char *id_name;
		const char *id_app;
		int priority;
		int disabled = 0;

		id_entry = config_setting_get_elem(set, i);

		if (config_setting_lookup_string(id_entry, "name", &id_name) &&
		    config_setting_lookup_string(id_entry, "identifier",
						 &id_app)
		    && config_setting_lookup_int(id_entry, "priority",
						 &priority)) {
			config_setting_lookup_int(id_entry, "disabled",
						  &disabled);
			if (register_proto_identifier(id_name, id_app, priority)
			    == 0)
				id_count++;

			if (disabled)
				disable_proto_identifier(id_name);
			else
				enable_proto_identifier(id_name);

		}
	}

	return id_count;
}

static int set_conf_proto_server(config_t * conf)
{

	config_setting_t *set;
	config_setting_t *server_entry;
	int server_num;
	int i;
	int server_count = 0;

	set = config_lookup(conf, "proto_server");

	if (set == NULL)
		return 0;

	server_num = config_setting_length(set);

	for (i = 0; i < server_num; i++) {

		const char *proto_name;
		const char *server_prog;
		const char *server_arg = NULL;

		server_entry = config_setting_get_elem(set, i);

		if (config_setting_lookup_string(server_entry, "proto",
						 &proto_name) &&
		    config_setting_lookup_string(server_entry, "server",
						 &server_prog)) {
			config_setting_lookup_string(server_entry, "para",
						     &server_arg);

			if (register_proto_server(proto_name, server_prog,
						  server_arg) == 0)
				server_count++;
		}
	}

	return server_count;

}

static int set_conf_proxy_server(config_t * conf)
{

	config_setting_t *set;
	config_setting_t *proxy_entry;
	int proxy_num;
	int i;
	int proxy_count = 0;

	set = config_lookup(conf, "proxy_server");

	if (set == NULL)
		return 0;

	proxy_num = config_setting_length(set);

	for (i = 0; i < proxy_num; i++) {

		const char *proto_name;
		const char *channel;

		proxy_entry = config_setting_get_elem(set, i);

		if (config_setting_lookup_string(proxy_entry, "proto",
						 &proto_name) &&
		    config_setting_lookup_string(proxy_entry, "channel",
						 &channel)) {

			if (register_proxy_server(proto_name, channel) == 0)
				proxy_count++;
		}
	}

	return proxy_count;

}

static int set_conf_internal_proto_identifer(config_t * conf)
{
	config_setting_t *set;
	config_setting_t *internal_entry;
	const char *proto_name;
	int disabled;
	int priority;
	int internal_count = 0;
	int i;
	int internal_num;

	set = config_lookup(conf, "internal_identifer");

	if (set == NULL)
		return 0;

	internal_num = config_setting_length(set);

	for (i = 0; i < internal_num; i++) {
		internal_entry = config_setting_get_elem(set, i);

		if (config_setting_lookup_string(internal_entry, "name",
						 &proto_name)) {
			disabled = 0;

			config_setting_lookup_int(internal_entry, "disabled",
						  &disabled);

			if (disabled)
				disable_intern_proto_identifier(proto_name);
			else {
				if (!enable_intern_proto_identifier(proto_name))
					internal_count++;
			}

			if (config_setting_lookup_int (internal_entry, "priority", 
				                                                     &priority))
				set_intern_proto_identifier_priority (proto_name, 
													priority);
		}

	}

	return internal_count;
}

static int set_conf_extension_module(config_t * conf)
{
	config_setting_t *set;
	config_setting_t *module_entry;
	const char *module_name;
	const char *module_file;
	int module_count = 0;
	int i;
	int module_num;

	set = config_lookup(conf, "extension_module");

	if (set == NULL)
		return 0;

	module_num = config_setting_length(set);

	for (i = 0; i < module_num; i++) {

		module_entry = config_setting_get_elem(set, i);

		if (config_setting_lookup_string
		    (module_entry, "name", &module_name)
		    && config_setting_lookup_string(module_entry, "file",
						    &module_file)) {

			if (register_xmodule(module_name, module_file)
			    == 0)
				module_count++;
		}

	}

	return module_count;
}

const char *get_conf_version(void)
{
	return conf_version;
}

int parse_conf(const char *conf_file)
{
	config_t *p_conf = &g_conf;
	int ret;

	if (conf_version)
		free((char *)conf_version);

	conf_version = NULL;
	conf_addr_set = 0;
	conf_port_set = 0;
	conf_log_level_set=0;

	if (init_config(conf_file, p_conf) < 0)
		return -1;

	set_conf_log_level(p_conf);

	set_conf_addr_port(p_conf);

	ret = set_conf_proto_identifier(p_conf);
	log_debug("config file: setting up [%d] protocol identifiers\n", ret);

	ret = set_conf_proxy_server(p_conf);
	log_debug("config file: setting up [%d] proxy servers\n", ret);

	ret = set_conf_proto_server(p_conf);
	log_debug("config file: setting up [%d] protocol servers\n", ret);

	ret = set_conf_extension_module(p_conf);
	log_debug("config file: find [%d] extension modules\n", ret);

	ret = set_conf_internal_proto_identifer(p_conf);
	log_debug("config file: enable [%d] "
		  "internal protocol identifiers\n", ret);

	config_destroy(p_conf);

	return 0;

}

int get_conf_log_level(int *p_level)
{
	if (!conf_log_level_set)
		return -1;

	*p_level = conf_log_level;
	return 0;
}

int get_conf_bind_addr(unsigned int *p_addr)
{
	if (!conf_addr_set)
		return -1;

	*p_addr = conf_bind_addr;

	return 0;

}

int get_conf_listen_port(int *p_port)
{
	if (!conf_port_set)
		return -1;

	*p_port = conf_listen_port;

	return 0;
}

