#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <stdarg.h>

#include "tcpmux.h"
#include "mux_log.h"

static int syslog_mode = 0;
static int cur_log_level = LOG_LEVEL_INFO;

void init_mux_log(int run_mode)
{
	if (run_mode == DAEMON_MODE || run_mode == INETD_MODE) {
		syslog_mode = 1;
		openlog("tcpmux", 0, LOG_USER);
	} else {
		syslog_mode = 0;
	}

}

void set_mux_log_daemon_mode(char *option)
{
	if (!syslog_mode) {
		syslog_mode = 1;

		if (option)
			openlog(option, 0, LOG_USER);
		else
			openlog("tcpmux", 0, LOG_USER);
	}
}

void log_error(const char *format, ...)
{
	va_list args;
	char buf[256];
	int buf_len = 256;

	va_start(args, format);
	vsnprintf(buf, buf_len, format, args);
	va_end(args);

	if (syslog_mode)
		syslog(LOG_ERR, "%s", buf);
	else
		fprintf(stderr, "%s", buf);
}

void log_msg(int level, char *format, ...)
{
	va_list args;
	char buf[256];
	int buf_len = 256;

	if (level > cur_log_level)
		return;

	va_start(args, format);
	vsnprintf(buf, buf_len, format, args);
	va_end(args);

	if (syslog_mode)
		syslog(LOG_INFO, "%s", buf);
	else
		fprintf(stdout, "%s", buf);

}

void set_log_level(int level)
{
	if (level >= LOG_LEVEL_INFO && level <= LOG_LEVEL_DBG)
		cur_log_level = level;
}

int get_log_level(void)
{
	return cur_log_level;
}
