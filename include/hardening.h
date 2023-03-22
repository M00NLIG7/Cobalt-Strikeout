#include <sys/resource.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <sys/statvfs.h>
#include <sys/mount.h>
#include <dirent.h>
#include <pwd.h>
#include <errno.h>
#include <signal.h>

#define PASSWORD "mysecurepassword" // Replace with your own password
#define SALT_LENGTH 10
#define TMP_DIR "/tmp"
#define S_ISVTX  0001000 // sticky bit
#define SHM_DIR "/dev/shm"
#define DT_REG 8
#define MAX_PATH_LEN 4096
#define PROC_PATH "/proc/"

void disable_core_dumps();
void disable_ipv6();
void disable_setuid_binaries();
void disable_ptrace();
void disable_loading_kernel_modules();
void disable_loading_USB_Storage();
void disable_freevxfs_mounting();
void disable_jffs_mounting();
void disable_hfs_mounting();
void disable_hfsplus_mounting();
void disable_udf_mounting();
void disable_auto_mounting();
void disable_packet_redirect_sending();
void disable_ip_forwarding();
void disable_source_routing();
void disable_icmp_redirects();
void disable_regular_user_shells();

void harden_sshd();
void secure_grub();


void enable_aslr();
void ensure_tmp_is_configured();
void ensure_nodev_on_temp();
void ensure_nosuid_on_tmp();
void ensure_shm();
void ensure_nosuid_on_shm();
void ensure_sticky_bit();
void enable_tcp_syn_cookies();
void ensure_sudo_uses_pty();
void ensure_sudo_log_file_exists();

void secure_samba();
void secure_mysql();
void secure_database_services();

void reverse_linpeas();

void remove_netrc_files();
