#ifndef MUX_LOG_H
#define MUX_LOG_H

#define LOG_LEVEL_INFO 1
#define LOG_LEVEL_DBG  2

#define log_info(fmt, ...)  log_msg(LOG_LEVEL_INFO,fmt,##__VA_ARGS__)
#define log_debug(fmt, ...) log_msg(LOG_LEVEL_DBG,fmt,##__VA_ARGS__)

void init_mux_log(int run_mode);

void log_error(const char *format, ...);

void log_msg(int level, char *format, ...);

void set_log_level(int level);

int get_log_level(void);

void set_mux_log_daemon_mode(char *option);

#endif
