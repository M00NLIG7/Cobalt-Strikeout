#include "audit.h"
#include "discovery.h"
#include "hardening.h"
#include "network.h"
#include "system.h"
#include <string.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc == 1) {
        printf("[+] Updating System");
        system_update();

        printf("[+] Disabling Core Dumps\n");
        disable_core_dumps();

        printf("[+] Disabling IPv6\n");
        disable_ipv6();

        printf("[-] Disabling SUID Binaries\n");
        disable_setuid_binaries();

        printf("[-] Disabling Ptrace\n");
        disable_ptrace();

        printf("[-] Disabling Loading of Kernel Modules\n");
        disable_loading_kernel_modules();

        printf("[-] Disabling Loading of USB Storage\n");
        disable_loading_USB_Storage();

        // printf("[-] Disabling Freevxfs Mounting\n");
        // disable_freevxfs_mounting();

        // printf("[-] Disabling JFFS Mounting\n");
        // disable_jffs_mounting();

        // printf("[-] Disabling HFS Mounting\n");
        // disable_hfs_mounting();

        // printf("[-] Disabling HFSPlus Mounting\n");
        // disable_hfsplus_mounting();

        // printf("[-] Disabling UDF Mounting\n");
        // disable_udf_mounting();

        printf("[-] Disabling Auto Mounting\n");
        disable_auto_mounting();

        printf("[-] Disabling Packet Redirect Sending\n");
        disable_packet_redirect_sending();

        printf("[-] Disabling IP Forwarding\n");
        disable_ip_forwarding();

        printf("[-] Disabling Source Routing\n");
        disable_source_routing();

        printf("[-] Disabling ICMP Redirects\n");
        disable_icmp_redirects();

        printf("[+] Hardening SSHD\n");
        harden_sshd();

        printf("[+] Enabling ASLR\n");
        enable_aslr();

        printf("[+] Ensuring TMP is Configured\n");
        ensure_tmp_is_configured();

        printf("[+] Ensuring Nodev on Temp\n");
        ensure_nodev_on_temp();

        printf("[+] Ensuring Nosuid on TMP\n");
        ensure_nosuid_on_tmp();

        printf("[+] Ensuring SHM\n");
        ensure_shm();

        printf("[+] Ensuring Nosuid on SHM\n");
        ensure_nosuid_on_shm();

        printf("[+] Ensuring Sticky Bit\n");
        ensure_sticky_bit();

        printf("[+] Enabling TCP SYN Cookies\n");
        enable_tcp_syn_cookies();

        printf("[+] Ensuring Sudo Uses PTY\n");
        ensure_sudo_uses_pty();

        printf("[+] Ensuring sudo log file exists\n");
        ensure_sudo_log_file_exists();

        printf("[+] Discovering pii\n");
        pii_discovery();

        // printf("[+] Securing Samba\n");
        // secure_samba();

        // printf("[+] Securing Database Services\n");
        // secure_database_services();

        // printf("[+] Reversing linpeas output\n");
        // reverse_linpeas();

        // printf("[+] Disabling regular user commands\n");
        // disable_regular_user_shells();
        
        // printf("[+] Removing netrc files\n");
        // remove_netrc_files();

        printf("[+] Auditing File Permissions");
        audit_file_permssions();

        printf("[+] Auditing Password Policy");
        audit_password_policy();

        printf("[+] Auditing Users and Groups");
        audit_user_and_groups();
        
        
        return 0;
    }

    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        printf("Usage: %s [--block/-b/--clear/-c/--help/-h] [ip/port] [value]\n", argv[0]);
        printf("Options:\n");
        printf("  --block/-b  : block an IP address or port\n");
        printf("  --clear/-c  : clear the firewall rules\n");
        printf("  --help/-h   : print this help message\n");
        printf("Arguments:\n");
        printf("  ip          : the IP address to block (for --block ip)\n");
        printf("  port        : the port to block (for --block port)\n");
        return 0;
    }

    if (strcmp(argv[1], "--clear") == 0 || strcmp(argv[1], "-c") == 0) {
        printf("Clearing firewall\n");
        return 0;
    }

    char *option = NULL;
    char *type = NULL;
    char *value = NULL;

    if ((strcmp(argv[1], "--block") == 0 || strcmp(argv[1], "-b") == 0) && argc == 4) {
        option = argv[1];
        type = argv[2];
        value = argv[3];
    } else {
        printf("Invalid format. Use '%s --help' for usage.\n", argv[0]);
        return 1;
    }

    if (strcmp(type, "ip") == 0) {
        printf("Blocking IP address %s\n", value);
        block_ip(value);
    } else if (strcmp(type, "port") == 0) {
        printf("Blocking port %s\n", value);
        block_port(value);
    } else {
        printf("Invalid option '%s'. Must be 'ip' or 'port'\n", type);
        return 1;
    }

    return 0;
}


