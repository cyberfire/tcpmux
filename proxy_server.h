#ifndef PROXY_SERVER_H
#define PROXY_SERVER_H

int register_proxy_server(const char *proto, const char *channel);
int unregister_proxy_server(const char *proto);

void unregister_all_proxy_server(void);

void dump_all_proxy_servers(void);

int deliver_proxy_connection(int conn_fd, const char *proto);

#endif
