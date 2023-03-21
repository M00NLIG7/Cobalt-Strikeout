#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <pwd.h>
#include <stdlib.h>
#include <grp.h>
#include <sys/types.h>
#include <errno.h>

#define MAX_LINE_LEN 1024

void audit_password_policy();
void audit_file_permssions();
void audit_user_and_groups();