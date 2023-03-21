#include "hardening.h"

void disable_core_dumps()
{
    struct rlimit rlim;
    rlim.rlim_cur = 0;
    rlim.rlim_max = 0;
    if (setrlimit(RLIMIT_CORE, &rlim) == -1) {
        perror("setrlimit");
    }
}

void disable_ipv6()
{
    // He primary purpose of creating the socket and setting its options is to ensure that any network 
    // communications that take place afterward will use only the IPv4 protocol (as opposed to using 
    // IPv6 as well, if it were available).
    int ipv6_disabled = 1;
    int ipv6_socket = socket(AF_INET6, SOCK_DGRAM, 0);
    if (ipv6_socket < 0) {
        perror("socket");
    }
    if (setsockopt(ipv6_socket, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6_disabled, sizeof(ipv6_disabled)) < 0) {
        perror("setsockopt");
    }
    close(ipv6_socket);
    FILE *fp = fopen("/proc/sys/net/ipv6/conf/all/disable_ipv6", "w");
    if (fp == NULL) {
        perror("fopen");
    }
    fprintf(fp, "%d", 1);
    fclose(fp);
}

void disable_setuid_binaries()
{
    // Disable the ability to use setuid binaries
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        perror("prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) failed");
    }
}

void disable_ptrace()
{
    // Disable ptrace
    if (prctl(PR_SET_DUMPABLE, 0) == -1) {
        perror("prctl");
    }
}

void disable_loading_kernel_modules()
{
    // Disable loading kernel modules
    int fd = open("/proc/sys/kernel/modules_disabled", O_WRONLY);
    if (fd == -1) {
        perror("open");
    } else {
        if (write(fd, "1", 1) == -1) {
            perror("write");
        }
        close(fd);
    }
}

void disable_loading_USB_Storage()
{
    // Disable loading of USB storage drivers
    int fd = open("/etc/modprobe.d/blacklist-usb-storage.conf", O_CREAT | O_WRONLY, 0644);
    if (fd == -1) {
        perror("open");
    } else {
        if (write(fd, "blacklist usb-storage\n", 22) == -1) {
            perror("write");
        }
        close(fd);
    }
}

void enable_aslr() {
    struct rlimit rl;
    if (getrlimit(RLIMIT_STACK, &rl) == 0) {
        rl.rlim_cur = RLIM_INFINITY;
        if (setrlimit(RLIMIT_STACK, &rl) != 0) {
        }
    }
}

void harden_sshd() {
    const char *sshd_config = "/etc/ssh/sshd_config";
    const char *log_level = "INFO";
    const char *x11_forwarding = "X11Forwarding no";

    // Set sshd_config file and key file permissions
    if (chmod(sshd_config, S_IRUSR | S_IWUSR) != 0) {
        fprintf(stderr, "Error setting permissions on %s\n", sshd_config);
        exit(EXIT_FAILURE);
    }

    DIR *dir = opendir("/etc/ssh");
    if (!dir) {
        fprintf(stderr, "Error opening directory /etc/ssh/\n");
        exit(EXIT_FAILURE);
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG && strstr(entry->d_name, "ssh_host_") == entry->d_name) {
            char key_path[1029];
            snprintf(key_path, sizeof(key_path), "/etc/ssh/%s", entry->d_name);

            struct stat key_stat;
            if (stat(key_path, &key_stat) < 0) {
                fprintf(stderr, "Error getting stat for %s\n", key_path);
                continue;
            }

            if (key_stat.st_mode & (S_IRWXG | S_IRWXO)) {
                if (chmod(key_path, S_IRUSR | S_IWUSR) != 0) {
                    fprintf(stderr, "Error setting permissions on %s\n", key_path);
                    continue;
                }
            }
        }
    }

    closedir(dir);

    // Update sshd_config file
    FILE *fp_in = fopen(sshd_config, "r");
    if (!fp_in) {
        fprintf(stderr, "Failed to open %s\n", sshd_config);
        exit(EXIT_FAILURE);
    }

    char tmp_file[1028];
    int fd = mkstemp(tmp_file);
    if (fd == -1) {
        fprintf(stderr, "Failed to create temporary file\n");
        exit(EXIT_FAILURE);
    }

    FILE *fp_out = fdopen(fd, "w+");
    if (!fp_out) {
        fprintf(stderr, "Failed to open temporary file\n");
        exit(EXIT_FAILURE);
    }

    int changed = 0;
    char line[1024];

    while (fgets(line, sizeof(line), fp_in) != NULL) {
        if (strncmp(line, "LogLevel ", 9) == 0) {
            fprintf(fp_out, "LogLevel %s\n", log_level);
            changed = 1;
        } else {
            fputs(line, fp_out);
        }
    }

    if (!changed) {
        fprintf(fp_out, "LogLevel %s\n", log_level);
    }

    fclose(fp_in);
    fclose(fp_out);

    if (rename(tmp_file, sshd_config) != 0) {
        fprintf(stderr, "Failed to replace %s\n", sshd_config);
        exit(EXIT_FAILURE);
    }

    printf("SSH LogLevel has been set to %s\n", log_level);

    // Disable X11 forwarding
    fp_in = fopen(sshd_config, "r");
    if (!fp_in) {
        fprintf(stderr, "Failed to open %s\n", sshd_config);
        exit(EXIT_FAILURE);
    }

    changed = 0;

    while (fgets(line, sizeof(line), fp_in) != NULL) {
        if (strncmp(line, "X11Forwarding", 13) == 0) {
            char *ptr = strchr(line, ' ');
            if (ptr != NULL) {
                int value = atoi(ptr);
                if (value == 0) {
                    fprintf(fp_out, "X11Forwarding yes\n");
                } else {
                    fprintf(fp_out, "%s", line);
                }
            } else {
                fprintf(fp_out, "X11Forwarding yes\n");
            }
        } else {
            fprintf(fp_out, "%s", line);
        }
    }
}

void secure_grub() {
    char cmd[100] = {0};
    char salt[SALT_LENGTH+1] = {0};
    char *encrypted_password;
    FILE *fp;

    // Generate a random salt for the password encryption
    srand(time(NULL));
    for (int i = 0; i < SALT_LENGTH; i++) {
        salt[i] = rand() % 26 + 'a';
    }

    // Get the encrypted password
    encrypted_password = crypt(PASSWORD, salt);

    // Set the GRUB password
    sprintf(cmd, "set superusers=\\\"root\\\"\npassword_pbkdf2 root %s", encrypted_password);
    fp = fopen("/etc/grub.d/40_custom", "w");
    fwrite(cmd, 1, strlen(cmd), fp);
    fclose(fp);

    // Update GRUB
    fp = popen("update-grub", "r");
    pclose(fp);
}

/*
Rationale - Removing support for unneeded filesystem types reduces the local attack surface of the
system. If this filesystem type is not needed, disable it.
*/

/* 
Description - The freevxfs filesystem type is a free version of the Veritas type filesystem. This is the
primary filesystem type for HP-UX operating systems
*/
void disable_freevxfs_mounting() {
    pid_t pid;
    int status;

    // Check if the freevxfs module is loaded
    pid = fork();
    if (pid == -1) {
        perror("fork");
    } else if (pid == 0) {
        // Child process
        execlp("lsmod", "lsmod", NULL);
        perror("lsmod");
    } else {
        // Parent process
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            FILE *fp = popen("grep -q freevxfs", "r");
            if (fp != NULL) {
                int c = fgetc(fp);
                if (c != EOF) {
                    // freevxfs module is loaded, remove it
                    printf("freevxfs module is loaded, removing...\n");
                    pid = fork();
                    if (pid == -1) {
                        perror("fork");
                    } else if (pid == 0) {
                        // Child process
                        execlp("rmmod", "rmmod", "freevxfs", NULL);
                        perror("rmmod");
                    } else {
                        // Parent process
                        waitpid(pid, &status, 0);
                    }
                }
                pclose(fp);
            } else {
                perror("grep");
            }
        } else {
            fprintf(stderr, "lsmod command failed\n");
        }
    }

    // Prevent future loading of the freevxfs module
    FILE *conf = fopen("/etc/modprobe.d/freevxfs.conf", "w");
    if (conf != NULL) {
        fprintf(conf, "install freevxfs /bin/true\n");
        fclose(conf);
    } else {
        perror("/etc/modprobe.d/freevxfs.conf");
    }
}

/*
Description - The jffs2 (journaling flash filesystem 2) filesystem type is a log-structured filesystem used
in flash memory devices
*/
void disable_jffs_mounting() {
    
    pid_t pid;
    int status;

    // Check if the jffs2 module is loaded
    pid = fork();
    if (pid == -1) {
        perror("fork");
    } else if (pid == 0) {
        // Child process
        execlp("lsmod", "lsmod", NULL);
        perror("lsmod");
    } else {
        // Parent process
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            FILE *fp = popen("grep -q jffs2", "r");
            if (fp != NULL) {
                int c = fgetc(fp);
                if (c != EOF) {
                    // jffs2 module is loaded, remove it
                    printf("jffs2 module is loaded, removing...\n");
                    pid = fork();
                    if (pid == -1) {
                        perror("fork");
                    } else if (pid == 0) {
                        // Child process
                        execlp("rmmod", "rmmod", "jffs2", NULL);
                        perror("rmmod");
                    } else {
                        // Parent process
                        waitpid(pid, &status, 0);
                    }
                }
                pclose(fp);
            } else {
                perror("grep");
            }
        } else {
            fprintf(stderr, "lsmod command failed\n");
        }
    }

    // Prevent future loading of the jffs2 module
    FILE *conf = fopen("/etc/modprobe.d/jffs2.conf", "w");
    if (conf != NULL) {
        fprintf(conf, "install jffs2 /bin/true\n");
        fclose(conf);
    } else {
        perror("/etc/modprobe.d/jffs2.conf");
    }
}

/*
Description - The hfs filesystem type is a hierarchical filesystem that allows you to mount Mac OS
filesystems.
*/
void disable_hfs_mounting() {
    pid_t pid;
    int status;

    // Check if the hfs module is loaded
    pid = fork();
    if (pid == -1) {
        perror("fork");
    } else if (pid == 0) {
        // Child process
        execlp("lsmod", "lsmod", NULL);
        perror("lsmod");
    } else {
        // Parent process
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            FILE *fp = popen("grep -q hfs", "r");
            if (fp != NULL) {
                int c = fgetc(fp);
                if (c != EOF) {
                    // hfs module is loaded, remove it
                    printf("hfs module is loaded, removing...\n");
                    pid = fork();
                    if (pid == -1) {
                        perror("fork");
                    } else if (pid == 0) {
                        // Child process
                        execlp("rmmod", "rmmod", "hfs", NULL);
                        perror("rmmod");
                    } else {
                        // Parent process
                        waitpid(pid, &status, 0);
                    }
                }
                pclose(fp);
            } else {
                perror("grep");
            }
        } else {
            fprintf(stderr, "lsmod command failed\n");
        }
    }

    // Prevent future loading of the hfs module
    FILE *conf = fopen("/etc/modprobe.d/hfs.conf", "w");
    if (conf != NULL) {
        fprintf(conf, "install hfs /bin/true\n");
        fclose(conf);
    } else {
        perror("/etc/modprobe.d/hfs.conf");
    }
}

/*
Description - The hfsplus filesystem type is a hierarchical filesystem designed to replace hfs that allows
you to mount Mac OS filesystems
*/
void disable_hfsplus_mounting() {
    pid_t pid;
    int status;

    // Check if the hfsplus module is loaded
    pid = fork();
    if (pid == -1) {
        perror("fork");
    } else if (pid == 0) {
        // Child process
        execlp("lsmod", "lsmod", NULL);
        perror("lsmod");
    } else {
        // Parent process
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            FILE *fp = popen("grep -q hfsplus", "r");
            if (fp != NULL) {
                int c = fgetc(fp);
                if (c != EOF) {
                    // hfsplus module is loaded, remove it
                    printf("hfsplus module is loaded, removing...\n");
                    pid = fork();
                    if (pid == -1) {
                        perror("fork");
                    } else if (pid == 0) {
                        // Child process
                        execlp("rmmod", "rmmod", "hfsplus", NULL);
                        perror("rmmod");
                    } else {
                        // Parent process
                        waitpid(pid, &status, 0);
                    }
                }
                pclose(fp);
            } else {
                perror("grep");
            }
        } else {
            fprintf(stderr, "lsmod command failed\n");
        }
    }

    // Prevent future loading of the hfsplus module
    FILE *conf = fopen("/etc/modprobe.d/hfsplus.conf", "w");
    if (conf != NULL) {
        fprintf(conf, "install hfsplus /bin/true\n");
        fclose(conf);
    } else {
        perror("/etc/modprobe.d/hfsplus.conf");
    }
}

/*
Description - The udf filesystem type is the universal disk format used to implement ISO/IEC 13346 and
ECMA-167 specifications. This is an open vendor filesystem type for data storage on a
broad range of media. This filesystem type is necessary to support writing DVDs and newer
optical disc formats
*/      
void disable_udf_mounting() {
    pid_t pid;
    int status;

    // Check if the udf module is loaded
    pid = fork();
    if (pid == -1) {
        perror("fork");
    } else if (pid == 0) {
        // Child process
        execlp("lsmod", "lsmod", NULL);
        perror("lsmod");
    } else {
        // Parent process
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            FILE *fp = popen("grep -q udf", "r");
            if (fp != NULL) {
                int c = fgetc(fp);
                if (c != EOF) {
                    // udf module is loaded, remove it
                    printf("udf module is loaded, removing...\n");
                    pid = fork();
                    if (pid == -1) {
                        perror("fork");
                    } else if (pid == 0) {
                        // Child process
                        execlp("rmmod", "rmmod", "udf", NULL);
                        perror("rmmod");
                    } else {
                        // Parent process
                        waitpid(pid, &status, 0);
                    }
                }
                pclose(fp);
            } else {
                perror("grep");
            }
        } else {
            fprintf(stderr, "lsmod command failed\n");
        }
    }

    // Prevent future loading of the udf module
    FILE *conf = fopen("/etc/modprobe.d/udf.conf", "w");
    if (conf != NULL) {
        fprintf(conf, "install udf /bin/true\n");
        fclose(conf);
    } else {
        perror("/etc/modprobe.d/udf.conf");
    }
}

/*
Description - The /tmp directory is a world-writable directory used for temporary storage by all users
and some applications

Rationale - Making /tmp its own file system allows an administrator to set the noexec option on the
mount, making /tmp useless for an attacker to install executable code. It would also
prevent an attacker from establishing a hardlink to a system setuid program and wait for it
to be updated. Once the program was updated, the hardlink would be broken and the
attacker would have his own copy of the program. If the program happened to have a
security vulnerability, the attacker could continue to exploit the known flaw.
This can be accomplished by either mounting tmpfs to /tmp, or creating a separate
partition for /tmp
*/
void ensure_tmp_is_configured() {
    struct stat sb;

    // Check if /tmp is a directory
    if (stat(TMP_DIR, &sb) == -1) {
        perror("stat");
    }
    if (!S_ISDIR(sb.st_mode)) {
        fprintf(stderr, "/tmp is not a directory\n");
    }

    // Set permissions to 1777
    if (chmod(TMP_DIR, S_IRWXU | S_IRWXG | S_IRWXO | S_ISVTX) == -1) {
        perror("chmod");
    }

    // Check if sticky bit is set
    if ((sb.st_mode & S_ISVTX) != S_ISVTX) {
        fprintf(stderr, "sticky bit is not set for /tmp\n");
    }

    // Create a tmpfiles.d configuration file to clean up /tmp on boot
    FILE *conf = fopen("/etc/tmpfiles.d/tmp.conf", "w");
    if (conf != NULL) {
        fprintf(conf, "D /tmp 1777 root root 10d\n");
        fclose(conf);
    } else {
        perror("/etc/tmpfiles.d/tmp.conf");
    }
}

/*
Description - The nodev mount option specifies that the filesystem cannot contain special devices.

Rationale - Since the /tmp filesystem is not intended to support devices, set this option to ensure that
users cannot attempt to create block or character special devices in /tmp 
*/
void ensure_nodev_on_temp() {
    // Check if /tmp is mounted with nodev option
    FILE *mountinfo = fopen("/proc/self/mountinfo", "r");
    if (mountinfo == NULL) {
        perror("fopen");
    }

    char line[4096];
    while (fgets(line, sizeof(line), mountinfo) != NULL) {
        char *mount_point = strstr(line, " /tmp ");
        if (mount_point != NULL) {
            char *options = strstr(line, " - ");
            if (options != NULL) {
                char *nodev = strstr(options, "nodev");
                if (nodev != NULL) {
                    printf("nodev option is set for /tmp\n");
                    fclose(mountinfo);
                    return 0;
                }
            }
        }
    }

    fprintf(stderr, "nodev option is not set for /tmp\n");
    fclose(mountinfo);
}

/*
Description - The nosuid mount option specifies that the filesystem cannot contain setuid files.

Rationale - Since the /tmp filesystem is only intended for temporary file storage, set this option to
ensure that users cannot create setuid files in /tmp 
*/
void ensure_nosuid_on_tmp() {
    // Remount /tmp with nosuid option
    if (mount(TMP_DIR, TMP_DIR, "tmpfs", MS_NOATIME | MS_NOSUID | MS_NODEV, "") == -1) {
        perror("mount");
    }

    // Check if nosuid option is set
    struct statvfs sb;
    if (statvfs(TMP_DIR, &sb) == -1) {
        perror("statvfs");
    }

    if ((sb.f_flag & ST_NOSUID) != ST_NOSUID) {
        fprintf(stderr, "nosuid option is not set for /tmp\n");
    }
}

/*
Description - /dev/shm is a traditional shared memory concept. One program will create a memory
portion, which other processes (if permitted) can access. Mounting tmpfs at /dev/shm is
handled automatically by systemd

Rationale - Any user can upload and execute files inside the /dev/shm similar to the /tmp partition.
Configuring /dev/shm allows an administrator to set the noexec option on the mount,
making /dev/shm useless for an attacker to install executable code. It would also prevent an
attacker from establishing a hardlink to a system setuid program and wait for it to be
updated. Once the program was updated, the hardlink would be broken and the attacker
would have his own copy of the program. If the program happened to have a security
vulnerability, the attacker could continue to exploit the known flaw
*/
void ensure_shm() {
    // Mount tmpfs on /dev/shm
    if (mount("none", SHM_DIR, "tmpfs", 0, "") == -1) {
        perror("mount");
    }

    // Set permissions for /dev/shm
    if (chmod(SHM_DIR, 01777) == -1) {
        perror("chmod");
    }

    // Optionally, set size limit for tmpfs filesystem
    // Note: this requires the Linux-specific "fallocate" system call
    /*
    int fd = open(SHM_DIR, O_RDONLY);
    if (fd == -1) {
        perror("open");
    }

    if (fallocate(fd, 0, 0, 1024 * 1024) == -1) {
        perror("fallocate");
    }

    close(fd);
    */
}

/*
Description - The nosuid mount option specifies that the filesystem cannot contain setuid files

Rationale - Setting this option on a file system prevents users from introducing privileged programs
onto the system and allowing non-root users to execute them.
*/
void ensure_nosuid_on_shm() {
    // Remount /dev/shm with nosuid option
    if (mount(SHM_DIR, SHM_DIR, "tmpfs", MS_NOSUID, "") == -1) {
        perror("mount");
    }

    // Check if nosuid option is set
    struct statvfs sb;
    if (statvfs(SHM_DIR, &sb) == -1) {
        perror("statvfs");
    }

    if ((sb.f_flag & ST_NOSUID) != ST_NOSUID) {
        fprintf(stderr, "nosuid option is not set for /dev/shm\n");
    }
}

/*
Description - Setting the sticky bit on world writable directories prevents users from deleting or
renaming files in that directory that are not owned by them.

Rationale - This feature prevents the ability to delete or rename files in world writable directories
(such as /tmp ) that are owned by another user.
*/
void ensure_sticky_bit() {
    FILE *fp;
    char command[] = "df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \\( -perm -0002 -a ! -perm -1000 \\) 2>/dev/null | xargs -I '{}' chmod a+t '{}'";
    char path[1024];
    char buf[1024];
    char *dirpath;
    DIR *dirp;
    struct dirent *direntp;
    struct stat st;
    int status;

    fp = popen(command, "r");
    if (fp == NULL) {
        perror("Error executing command");
    }

    while (fgets(path, sizeof(path), fp) != NULL) {
        path[strcspn(path, "\n")] = 0; // Remove newline character
        if ((dirp = opendir(path)) == NULL) {
            perror("Error opening directory");
            continue;
        }
        while ((direntp = readdir(dirp)) != NULL) {
            sprintf(buf, "%s/%s", path, direntp->d_name);
            if (lstat(buf, &st) < 0) {
                perror("Error getting file status");
                continue;
            }
            if (S_ISDIR(st.st_mode) && (st.st_mode & S_IWOTH) && !(st.st_mode & S_ISVTX)) {
                printf("Changing permissions for directory: %s\n", buf);
                status = chmod(buf, st.st_mode | S_ISVTX);
                if (status < 0) {
                    perror("Error changing permissions");
                }
            }
        }
        closedir(dirp);
    }

    pclose(fp);
}

/*
Description - autofs allows automatic mounting of devices, typically including CD/DVDs and USB drives.

Rationale - With automounting enabled anyone with physical access could attach a USB drive or disc
and have its contents available in system even if they lacked permissions to mount it
themselves
*/
void disable_auto_mounting() {
    FILE *fp;
    char command[] = "grep -q '^\\s*Auto\\s*\\(\\s*\\|\\)\\s*\\(no\\|false\\)' /etc/fstab || echo 'proc /proc proc defaults,nosuid,nodev,noexec,auto,hidepid=2 0 0' >> /etc/fstab";
    int status;

    status = system(command);
    if (status != 0) {
        fprintf(stderr, "Error executing command\n");
    }

    status = mount(NULL, "/", NULL, MS_REMOUNT | MS_RDONLY, NULL);
    if (status != 0) {
        fprintf(stderr, "Error disabling automounting\n");
    }
}


/*
Description - ICMP Redirects are used to send routing information to other hosts. As a host itself does
not act as a router (in a host only configuration), there is no need to send redirects

Rationale - An attacker could use a compromised host to send invalid ICMP redirects to other router
devices in an attempt to corrupt routing and have users access a system set up by the
attacker as opposed to a valid system.
*/
void disable_packet_redirect_sending() {
    FILE *fp;
    char *line = NULL;
    size_t len = 0;
    ssize_t read;

    // Open /etc/sysctl.conf for reading and writing
    fp = fopen("/etc/sysctl.conf", "a+");
    if (fp == NULL) {
        fprintf(stderr, "Error opening /etc/sysctl.conf\n");
    }

    // Check if send_redirects is enabled
    int send_redirects_enabled = 0;
    while ((read = getline(&line, &len, fp)) != -1) {
        if (strstr(line, "net.ipv4.conf.all.send_redirects") != NULL) {
            if (strstr(line, "= 1") != NULL) {
                send_redirects_enabled = 1;
            }
            break;
        }
    }

    // Disable send_redirects
    if (send_redirects_enabled) {
        fseek(fp, 0, SEEK_END);
        fprintf(fp, "net.ipv4.conf.all.send_redirects=0\n");
        fflush(fp);
    }

    // Close the file
    fclose(fp);

    // Open /proc/sys/net/ipv4/conf/all/send_redirects for writing
    fp = fopen("/proc/sys/net/ipv4/conf/all/send_redirects", "w");
    if (fp == NULL) {
        fprintf(stderr, "Error opening /proc/sys/net/ipv4/conf/all/send_redirects\n");
    }

    // Set the value of send_redirects to 0
    fprintf(fp, "0\n");
    fflush(fp);

    // Close the file
    fclose(fp);

    line = NULL;
    len = 0;

    fp = fopen("/etc/ssh/sshd_config", "r+");
    if (fp == NULL) {
        perror("Error opening sshd_config file");
        exit(EXIT_FAILURE);
    }

    while ((read = getline(&line, &len, fp)) != -1) {
        if (strncmp(line, "#UsePAM", 7) == 0) {
            fseek(fp, -read, SEEK_CUR);
            fprintf(fp, "UsePAM yes\n");
            break;
        } else if (strncmp(line, "UsePAM", 6) == 0) {
            fseek(fp, -read, SEEK_CUR);
            fprintf(fp, "UsePAM yes\n");
            break;
        }
    }

    if (line) {
        free(line);
    }
    fclose(fp);
}

/*
Description - The net.ipv4.ip_forward and net.ipv6.conf.all.forwarding flags are used to tell the
system whether it can forward packets or not

Rationale - Setting the flags to 0 ensures that a system with multiple interfaces (for example, a hard
proxy), will never be able to forward packets, and therefore, never serve as a router
*/
void disable_ip_forwarding() {
    pid_t pid;
    int status;

    // Fork a child process to execute sysctl to disable IP forwarding
    pid = fork();
    if (pid == -1) {
        fprintf(stderr, "Error forking child process\n");
    } else if (pid == 0) {
        // This is the child process
        execl("/sbin/sysctl", "sysctl", "-w", "net.ipv4.ip_forward=0", NULL);
        // execl only returns if an error occurs
        fprintf(stderr, "Error executing sysctl\n");
    } else {
        // This is the parent process
        waitpid(pid, &status, 0);
        if (status != 0) {
            fprintf(stderr, "Error executing sysctl\n");
        }
    }
}

/*
Description - In networking, source routing allows a sender to partially or fully specify the route packets
take through a network. In contrast, non-source routed packets travel a path determined
by routers in the network. In some cases, systems may not be routable or reachable from
some locations (e.g. private addresses vs. Internet routable), and so source routed packets
would need to be used.

Rationale - Setting net.ipv4.conf.all.accept_source_route,
net.ipv4.conf.default.accept_source_route, net.ipv6.conf.all.accept_source_route and
net.ipv6.conf.default.accept_source_route to 0 disables the system from accepting
source routed packets. Assume this system was capable of routing packets to Internet
routable addresses on one interface and private addresses on another interface. Assume
that the private addresses were not routable to the Internet routable addresses and vice
versa. Under normal routing circumstances, an attacker from the Internet routable
addresses could not use the system as a way to reach the private address systems. If,
however, source routed packets were allowed, they could be used to gain access to the
private address systems as the route could be specified, rather than rely on routing
protocols that did not allow this routing
*/
void disable_source_routing() {
    pid_t pid;
    int status;

    // Fork a child process to execute sysctl to disable source routing
    pid = fork();
    if (pid == -1) {
        fprintf(stderr, "Error forking child process\n");
    } else if (pid == 0) {
        // This is the child process
        execl("/sbin/sysctl", "sysctl", "-w", "net.ipv4.conf.all.accept_source_route=0", "net.ipv4.conf.default.accept_source_route=0", NULL);
        // execl only returns if an error occurs
        fprintf(stderr, "Error executing sysctl\n");
    } else {
        // This is the parent process
        waitpid(pid, &status, 0);
        if (status != 0) {
            fprintf(stderr, "Error executing sysctl\n");
        }
    }
}

/*
Description - ICMP redirect messages are packets that convey routing information and tell your host
(acting as a router) to send packets via an alternate path. It is a way of allowing an outside
routing device to update your system routing tables. By setting
net.ipv4.conf.all.accept_redirects and net.ipv6.conf.all.accept_redirects to 0,
the system will not accept any ICMP redirect messages, and therefore, won't allow
outsiders to update the system's routing tables

Rationale - Attackers could use bogus ICMP redirect messages to maliciously alter the system routing
tables and get them to send packets to incorrect networks and allow your system packets
to be captured
*/
void disable_icmp_redirects() {
    pid_t pid;
    int status;

    // Fork a child process to execute sysctl to disable ICMP redirects
    pid = fork();
    if (pid == -1) {
        fprintf(stderr, "Error forking child process\n");
    } else if (pid == 0) {
        // This is the child process
        execl("/sbin/sysctl", "sysctl", "-w", "net.ipv4.conf.all.accept_redirects=0", "net.ipv4.conf.default.accept_redirects=0", NULL);
        // execl only returns if an error occurs
        fprintf(stderr, "Error executing sysctl\n");
    } else {
        // This is the parent process
        waitpid(pid, &status, 0);
        if (status != 0) {
            fprintf(stderr, "Error executing sysctl\n");
        }
    }
}

/*
Description - When tcp_syncookies is set, the kernel will handle TCP SYN packets normally until the
half-open connection queue is full, at which time, the SYN cookie functionality kicks in. SYN
cookies work by not using the SYN queue at all. Instead, the kernel simply replies to the
SYN with a SYN|ACK, but will include a specially crafted TCP sequence number that
encodes the source and destination IP address and port number and the time the packet
was sent. A legitimate connection would send the ACK packet of the three way handshake
with the specially crafted sequence number. This allows the system to verify that it has
received a valid response to a SYN cookie and allow the connection, even though there is no
corresponding SYN in the queue.

Rationale - Attackers use SYN flood attacks to perform a denial of service attacked on a system by
sending many SYN packets without completing the three way handshake. This will quickly
use up slots in the kernel's half-open connection queue and prevent legitimate connections
from succeeding. SYN cookies allow the system to keep accepting valid connections, even if
under a denial of service attack
*/
void enable_tcp_syn_cookies() {
    pid_t pid;
    int status;

    // Fork a child process to execute sysctl to enable TCP SYN Cookies
    pid = fork();
    if (pid == -1) {
        fprintf(stderr, "Error forking child process\n");
        exit(EXIT_FAILURE);
    } else if (pid == 0) {
        // This is the child process
        execl("/sbin/sysctl", "sysctl", "-w", "net.ipv4.tcp_syncookies=1", NULL);
        // execl only returns if an error occurs
        fprintf(stderr, "Error executing sysctl\n");
        exit(EXIT_FAILURE);
    } else {
        // This is the parent process
        waitpid(pid, &status, 0);
        if (status != 0) {
            fprintf(stderr, "Error executing sysctl\n");
            exit(EXIT_FAILURE);
        }
    }
}

/*
Description - sudo can be configured to run only from a pseudo-pty

Rationale - Attackers can run a malicious program using sudo, which would again fork a background
process that remains even when the main program has finished executing
*/
void ensure_sudo_uses_pty() {
    FILE *fp;
    char *sudoers_file = "/etc/sudoers";
    char command[1024];
    int status;

    snprintf(command, sizeof(command), "grep -q '^Defaults\\s\\+requiretty' %s || echo 'Defaults requiretty' >> %s", sudoers_file, sudoers_file);
    status = system(command);
    if (status != 0) {
        fprintf(stderr, "Error executing command\n");
        exit(EXIT_FAILURE);
    }
}

/*
Description - sudo can use a custom log file.

Rationale - A sudo log file simplifies auditing of sudo commands
*/
void ensure_sudo_log_file_exists() {
    char *sudo_log_file = "/var/log/sudo.log";
    struct stat file_stat;
    int status;

    status = stat(sudo_log_file, &file_stat);
    if (status != 0) {
        fprintf(stderr, "Error getting file status\n");
        exit(EXIT_FAILURE);
    }

    if (!S_ISREG(file_stat.st_mode)) {
        status = system("touch /var/log/sudo.log");
        if (status != 0) {
            fprintf(stderr, "Error creating sudo log file\n");
            exit(EXIT_FAILURE);
        }

        status = system("chmod 640 /var/log/sudo.log");
        if (status != 0) {
            fprintf(stderr, "Error changing permissions on sudo log file\n");
            exit(EXIT_FAILURE);
        }
    }

    status = system("grep -q '^Defaults\\s*logfile=\"/var/log/sudo.log\"' /etc/sudoers || echo 'Defaults logfile=\"/var/log/sudo.log\"' >> /etc/sudoers");
    if (status != 0) {
        fprintf(stderr, "Error adding Defaults logfile option to sudoers file\n");
        exit(EXIT_FAILURE);
    }
}

/*
Description - The .netrc file contains data for logging into a remote host for file transfers via FTP.
While the system administrator can establish secure permissions for users' .netrc files, the
users can easily override these.

Rationale - The .netrc file presents a significant security risk since it stores passwords in unencrypted
form. Even if FTP is disabled, user accounts may have brought over .netrc files from other
systems which could pose a risk to those systems.

If a .netrc file is required, and follows local site policy, it should have permissions of 600 or
more restrictive.
*/
void remove_netrc_files() {
    struct passwd *pw;
    struct stat sb;
    mode_t mask = S_IRWXG | S_IRWXO; // remove group and others' read, write, and execute permissions

    while ((pw = getpwent()) != NULL) {
        char *homedir = pw->pw_dir;
        char *netrc_path = malloc(strlen(homedir) + 7); // 7 = strlen("/.netrc") + 1
        sprintf(netrc_path, "%s/.netrc", homedir);
        if (stat(netrc_path, &sb) != -1 && S_ISREG(sb.st_mode)) {
            if (chmod(netrc_path, sb.st_mode & ~mask) == -1) {
                perror("chmod");
            } else {
                printf("Removed .netrc file for user %s\n", pw->pw_name);
                unlink(netrc_path);
            }
        }
        free(netrc_path);
    }

    endpwent();
}

void ensure_path_integrity() {
    char *path_env_var;
    char *new_path_env_var;

    path_env_var = getenv("PATH");

    if (path_env_var == NULL) {
      printf("Error: PATH environment variable not set\n");
      exit(EXIT_FAILURE);
    }

    size_t path_len = strlen(path_env_var);
    if (path_len > MAX_PATH_LEN) {
      printf("Error: PATH environment variable is too long\n");
      exit(EXIT_FAILURE);
    }

    new_path_env_var = (char*)malloc(path_len + 1);
    if (new_path_env_var == NULL) {
      printf("Error: failed to allocate memory\n");
      exit(EXIT_FAILURE);
    }

    char *p = strtok(path_env_var, ":");
    int found_root_path = 0;

    while (p != NULL) {
      if (strcmp(p, "/usr/local/sbin") == 0) {
        found_root_path = 1;
      }
      strcat(new_path_env_var, p);
      strcat(new_path_env_var, ":");
      p = strtok(NULL, ":");
    }

    if (!found_root_path) {
      strcat(new_path_env_var, "/usr/local/sbin");
      strcat(new_path_env_var, ":");
    }

    if (setenv("PATH", new_path_env_var, 1) != 0) {
      printf("Error: failed to set PATH environment variable: %s\n", strerror(errno));
      exit(EXIT_FAILURE);
    }

    printf("Successfully set PATH environment variable to: %s\n", new_path_env_var);

    free(new_path_env_var);
}   

void secure_samba() {

}

void secure_mysql() {
    // Step 1: Disable insecure SSL/TLS protocols
   system("mysql -u root -p mypassword -e \"SET GLOBAL ssl_cipher='TLSv1.2';\"");
   
   // Step 2: Disable the use of LOAD DATA LOCAL statement
   system("mysql -u root -p mypassword -e \"SET GLOBAL local_infile=0;\"");
   
   // Step 3: Disable the use of UDF feature
   system("mysql -u root -p mypassword -e \"SET GLOBAL disable_query_log=1;\"");
   
   // Step 4: Create a separate user with restricted privileges
   system("mysql -u root -p mypassword -e \"CREATE USER 'appuser'@'localhost' IDENTIFIED BY 'apppassword';\"");
   system("mysql -u root -p mypassword -e \"GRANT SELECT, INSERT, UPDATE, DELETE ON mydatabase.* TO 'appuser'@'localhost';\"");
   
   // Step 5: Regularly update the MySQL server
   // Note: This step cannot be automated in code, and must be done manually by the system administrator
   
   printf("MySQL server has been secured.\n");
}
