#include <stdio.h>
#include <regex.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <dirent.h>
#include <stdlib.h>

#define DT_DIR 4
#define DT_REG 8

#define MAX_PATH_LENGTH 4096
#define MAX_LINE_LENGTH 4096

typedef struct {
    char* directory_path;
    char* output_file_path;
} ThreadArgs;

void pii_discovery();
void database_discovery();
void webserver_discovery();
