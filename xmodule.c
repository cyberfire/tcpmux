#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>

#include "list.h"
#include "mux_log.h"
#include "xmodule.h"

struct xmodule {
	char *name;
	char *file;
	void *handle;
	struct list link;
};

static LIST_HEAD(xmodule_list);

static void init_xmodule(struct xmodule *p_mod)
{
	p_mod->name = NULL;
	p_mod->file = NULL;
	p_mod->handle = NULL;

	list_init(&p_mod->link);
}

static void release_xmodule(struct xmodule *p_mod)
{
	free(p_mod->name);
	free(p_mod->file);
	free(p_mod);
}

static struct xmodule *find_xmodule_by_name(const char *name)
{
	struct xmodule *p_mod;

	list_for_each_entry(p_mod, &xmodule_list, link) {
		if (!strcmp(p_mod->name, name))
			return p_mod;
	}

	return NULL;
}

static int load_xmodule(struct xmodule *p_mod)
{
	void *h;
	xmodule_init_t init_func;

	h = dlopen(p_mod->file, RTLD_NOW);

	if (h == NULL) {
		log_error("load module [%s] failed. reason [%s]\n", p_mod->file,
			  dlerror());
		return -1;
	}

	init_func = dlsym(h, INIT_XMODULE_FUNC_NAME);

	if (init_func == NULL) {
		log_error("failed to locate function [%s]. reason [%s]\n",
			  INIT_XMODULE_FUNC_NAME, dlerror());

		dlclose(h);

		return -1;
	}

	if (init_func() < 0) {
		log_error("failed to execution init function for mdoule [%s]\n",
			  p_mod->file);
		dlclose(h);
		return -1;
	}

	p_mod->handle = h;

	return 0;
}

static int unload_xmodule(struct xmodule *p_mod)
{

	xmodule_release_t release_func;

	release_func = dlsym(p_mod->handle, RELEASE_XMODULE_FUNC_NAME);

	if (release_func == NULL)
		return -1;

	if (release_func() < 0)
		return -1;

	dlclose(p_mod->handle);

	return 0;

}

int register_xmodule(const char *mod_name, const char *mod_file)
{
	struct xmodule *p_mod;

	log_debug("register new module [%s] file [%s]\n", mod_name, mod_file);

	if (find_xmodule_by_name(mod_name))
		return -1;

	p_mod = malloc(sizeof(struct xmodule));

	if (p_mod == NULL)
		return -1;

	init_xmodule(p_mod);

	p_mod->name = strdup(mod_name);
	p_mod->file = strdup(mod_file);

	if (load_xmodule(p_mod) < 0) {
		release_xmodule(p_mod);
		return -1;
	}

	list_prepend(&p_mod->link, &xmodule_list);

	return 0;

}

int unregister_xmodule(const char *mod_name)
{
	struct xmodule *p_mod;

	p_mod = find_xmodule_by_name(mod_name);

	if (p_mod == NULL)
		return -1;

	if (unload_xmodule(p_mod) < 0)
		return -1;

	list_remove(&p_mod->link);

	release_xmodule(p_mod);

	return 0;

}

void unregister_all_xmodule(void)
{
	struct xmodule *p_mod;
	struct xmodule *p_dummy;

	list_for_each_entry_safe(p_mod, p_dummy, &xmodule_list, link) {
		unregister_xmodule(p_mod->name);
	}
}

static void dump_xmodule_entry(struct xmodule *p_mod)
{
	log_info("module: name [%s] file[%s]\n", p_mod->name, p_mod->file);
}

void dump_all_xmodules(void)
{
	int count = 0;
	struct xmodule *p_mod;

	list_for_each_entry(p_mod, &xmodule_list, link) {
		dump_xmodule_entry(p_mod);
		count++;
	}

	log_info("total [%d] extension module registerd\n", count);
}
