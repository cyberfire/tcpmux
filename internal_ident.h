#ifndef INTERNAL_IDENT_H
#define INTERNAL_IDENT_H

#define INTERNAL_PROTO_IDENT_NAME "internal"

#define disable_intern_proto_identifier(name) set_intern_proto_ident_disable(name,1)
#define enable_intern_proto_identifier(name) set_intern_proto_ident_disable(name,0)

typedef int (*intern_ident_func_t) (const char *, int, char *, int);

int set_intern_proto_identifier_priority(const char *name, int priority);

int set_intern_proto_ident_disable(const char *name, int disable);

int register_intern_proto_ident(const char *name, int priority,
				  intern_ident_func_t func);
int unregsiter_intern_proto_ident(const char *name);

int intern_identity_protocol(const char *packet_data, int data_len,
			       char *proto_name, int name_len);

void dump_all_intern_idents(void);

void install_intern_proto_identifiers(void);

#endif
