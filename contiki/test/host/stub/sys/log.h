/* host-test stand-in: firmware log lines go to stderr */
#pragma once
#include <stdio.h>
#define LOG_LEVEL_INFO 3
#define LOG_INFO(...) fprintf(stderr, __VA_ARGS__)
#define LOG_ERR(...)  fprintf(stderr, __VA_ARGS__)
