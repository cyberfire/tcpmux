#ifndef PROTO_IDENT_H
#define PROTO_IDENT_H

#define TOKEN_NOTFOUND "NOTFOUND"

int register_proto_identifier(const char *name, const char *app, int priority);
int unregister_proto_identifier(const char *name);
void unregister_all_proto_identifier(void);

#define disable_proto_identifier(name)  set_proto_ident_disable(name,1)

#define enable_proto_identifier(name)    set_proto_ident_disable(name,0)

int set_proto_ident_disable(const char *name, int disable);

void dump_all_proto_idents(void);

int identify_proto_name(const char *packet_data, int data_len, char *proto_name,
			int name_len);

#endif
