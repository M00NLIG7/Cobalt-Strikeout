#include "audit.h"
#include "discovery.h"
#include "hardening.h"
#include "network.h"
#include "system.h"


int main () {
    printf("[+] Disabling Core Dumpes\n");
    disable_core_dumps();

    printf("[+] Disabling IPv6\n");
    disable_ipv6();

    printf("[+] Disable SUID Binaries\n");
    disable_setuid_binaries();

    printf("[+] Disable Ptrace\n");
    disable_ptrace();

    printf("[+] Disable Loading of Kernel Modules\n");
    disable_loading_kernel_modules();

    printf("[+] Disable Loading of USB Storage\n");
    disable_loading_USB_Storage();

    // printf("[+] Disable Freevxfs Mounting\n");
    // disable_freevxfs_mounting();

    // printf("[+] Disable JFFS Mounting\n");
    // disable_jffs_mounting();

    // printf("[+] Disable HFS Mounting\n");
    // disable_hfs_mounting();

    // printf("[+] Disable HFSPlus Mounting\n");
    // disable_hfsplus_mounting();

    // printf("[+] Disable UDF Mounting\n");
    // disable_udf_mounting();

    printf("[+] Disable Auto Mounting\n");
    disable_auto_mounting();

    printf("[+] Disable Packet Redirect Sending\n");
    disable_packet_redirect_sending();

    printf("[+] Disable IP Forwarding\n");
    disable_ip_forwarding();

    printf("[+] Disable Source Routing\n");
    disable_source_routing();

    printf("[+] Disable ICMP Redirects\n");
    disable_icmp_redirects();

    printf("[+] Harden SSHD\n");
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

    printf("[+] Ensuring PATH integrity\n");
    ensure_path_integrity();

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

}