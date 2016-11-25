#ifndef EXTENSION_MODULE_H
#define EXTENSION_MODULE_H

#define INIT_XMODULE_FUNC_NAME    "init_xmodule"
#define RELEASE_XMODULE_FUNC_NAME  "release_xmodule"

typedef int (*xmodule_init_t) (void);
typedef int (*xmodule_release_t) (void);

int register_xmodule(const char *mod_name, const char *mod_file);
int unregister_xmodule(const char *mod_name);

void unregister_all_xmodule(void);

void dump_all_xmodules(void);

#endif
