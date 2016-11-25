#ifndef PROTO_SERVER_H
#define PROTO_SERVER_H

int register_proto_server(const char *proto_name, const char *server_prog,
			  const char *para);

int unregister_proto_server(const char *proto_name);

void unregister_all_proto_server(void);

int exec_proto_server(int conn_fd, const char *proto_name);

void dump_all_proto_servers(void);

#endif
