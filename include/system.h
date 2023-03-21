#include <unistd.h>
#include <stdlib.h> 
#include <stdio.h>
#include <signal.h>
#include <sys/types.h>
#include <dirent.h>

// Package manager binaries
#define APT "/usr/bin/apt-get"
#define YUM "/usr/bin/yum"
#define PACMAN "/usr/bin/pacman"
#define APK "/usr/bin/apk"
#define DNF "/usr/bin/dnf"
#define SLAPT "/usr/bin/slapt-get"
#define SLACK "/usr/sbin/slackpkg"
#define PKG "/usr/bin/pkg"


void system_update();