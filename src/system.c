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

