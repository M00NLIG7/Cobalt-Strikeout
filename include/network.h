#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>

void block_common_bad_ports();
int block_ip(const char *ip);
int block_port(int port);
