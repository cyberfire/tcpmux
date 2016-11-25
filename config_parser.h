#ifndef CONFIG_PARSER_H
#define CONFIG_PARSER_H

int parse_conf(const char *conf_file);

int get_conf_bind_addr(unsigned int *p_addr);

int get_conf_listen_port(int *p_port);

int get_conf_log_level(int *p_level);

const char *get_conf_version(void);

#endif
