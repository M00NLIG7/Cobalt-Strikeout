#include "system.h"

const char* get_package_manager() {
    if (access(APT, X_OK) != -1) {
        return "apt-get";
    }
    else if (access(YUM, X_OK) != -1) {
        return "yum";
    }
    else if (access(PACMAN, X_OK) != -1) {
        return "pacman";
    }
    else if (access(APK, X_OK) != -1) {
        return "apk";
    }
    else if (access(DNF, X_OK) != -1) {
        return "DNF";
    }
    else if (access(SLAPT, X_OK) != -1) {
        return "slapt-get";
    }
    else if (access(SLACK, X_OK) != -1) {
        return "slackpkg";
    }

    else {
        return NULL;
    }
}

void system_update() {
    const char* package_manager = get_package_manager();

    char* update_cmd = NULL;
    if (package_manager == NULL) {
        printf("Unable to determine the package manager.\n");
        return;
    }
    
    if (strcmp(package_manager, "apt") == 0) {
        update_cmd = "apt update -y && apt upgrade -y";
    }
    else if (strcmp(package_manager, "apt-get") == 0) {
        update_cmd = "apt-get update -y && apt-get upgrade -y";
    }
    else if (strcmp(package_manager, "dnf") == 0) {
        update_cmd = "dnf update -y && apk upgrade -y";
    }
    else if (strcmp(package_manager, "yum") == 0) {
        update_cmd = "yum update -y";
    }
    else if (strcmp(package_manager, "pacman") == 0) {
        update_cmd = "pacman -Syu --noconfirm";
    }
    else if (strcmp(package_manager, "apk") == 0) {
        update_cmd = "apk update && apk upgrade";
    }
    else if (strcmp(package_manager, "slapt") == 0) {
        update_cmd = "slapt-get update -y && slapt-get upgrade -y";

    }
    else if (strcmp(package_manager, "slackpkg") == 0) {
        update_cmd = "slackpkg update -y && slackpkg upgrade-all -y";

    }
    else {
        printf("Unable to determine the package manager.\n");
        return;
    }
    system(update_cmd);
}

void restart_service(char* service_name) {
    pid_t pid = find_pid_by_name(service_name);
    printf("%s PID is %d\n", service_name, pid);
    int ret = kill(pid, SIGHUP);
    if(ret == -1)
    {
        printf("kill failed!\n");
    }
}

pid_t find_pid_by_name(const char *pname) {
    DIR *dir;
    struct dirent *ent;
    char *endptr;
    char buf[512];
    FILE *fp;
    pid_t pid = -1;

    if (!(dir = opendir(PROC_PATH)))
        return -1;

    while ((ent = readdir(dir)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;

        endptr = NULL;
        long lpid = strtol(ent->d_name, &endptr, 10);
        if (*endptr != '\0')
            continue;

        snprintf(buf, sizeof(buf), PROC_PATH "%ld/cmdline", lpid);
        if (!(fp = fopen(buf, "r")))
            continue;

        if (fgets(buf, sizeof(buf), fp) == NULL) {
            fclose(fp);
            continue;
        }

        fclose(fp);

        char *cmd_start = buf;
        char *cmd_end = strstr(cmd_start, "\0");
        if (cmd_end == NULL)
            continue;

        cmd_end++;
        while (*cmd_end == '\0')
            cmd_end++;

        if (strstr(cmd_start, pname) != NULL) {
            pid = (pid_t) lpid;
            break;
        }
    }

    closedir(dir);
    return pid;
}
