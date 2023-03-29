#include "audit.h"

#define MAX_LINE_LEN 256

void audit_password_policy() {
    // check if the password policy configuration file exists
    FILE *fp = fopen("/etc/pam.d/common-password", "r+");
    if (fp == NULL) {
        // file doesn't exist, create it
        fp = fopen("/etc/pam.d/common-password", "w");
        if (fp == NULL) {
            printf("Error creating file\n");
            return;
        }
    }

    // check if the password policy configuration line already exists in the file
    char line[MAX_LINE_LEN];
    while (fgets(line, MAX_LINE_LEN, fp) != NULL) {
        if (strstr(line, "pam_pwquality.so") != NULL) {
            printf("Password policy configuration already exists in file\n");
            fclose(fp);
            return;
        }
    }

    // write the password policy configuration line to the file
    fprintf(fp, "password    required    pam_pwquality.so try_first_pass retry=3\n");

    fclose(fp);

    // write the password policy options to the configuration file
    fp = fopen("/etc/security/pwquality.conf", "w");
    if (fp == NULL) {
        printf("Error opening file\n");
        return;
    }

    fprintf(fp, "minlen = 12\n"); // minimum password length
    fprintf(fp, "dcredit = -1\n"); // at least one digit required
    fprintf(fp, "ucredit = -1\n"); // at least one uppercase letter required
    fprintf(fp, "ocredit = -1\n"); // at least one special character required

    fclose(fp);
}

void audit_file_permssions() {
    // chown root:root /etc/passwd
    if (chown("/etc/passwd", 0, 0) == -1) {
        perror("Error changing ownership of /etc/passwd");
    }

    // chmod u-x,go-wx /etc/passwd
    if (chmod("/etc/passwd", S_IRUSR | S_IWUSR) == -1) {
        perror("Error changing permissions of /etc/passwd");
    }

    if (chown("/etc/passwd-", 0, 0) == -1) {
        perror("Error changing owner of /etc/passwd-");
    }

    if (chmod("/etc/passwd-", S_IWGRP|S_IWOTH|S_IXUSR) == -1) {
        perror("Error changing permission of /etc/passwd-");
    }

    // Set ownership of /etc/group to root:root
    if (chown("/etc/group", 0, 0) != 0) {
        // handle error
        perror("Error changing owner of /etc/group");
    }
    
    // Set permissions on /etc/group to u-x,go-wx
    if (chmod("/etc/group", S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) != 0) {
        // handle error
        perror("Error changing permission of /etc/group");

    }

    // chown root:root /etc/group-
    if (chown("/etc/group-", 0, 0) == -1) {
        perror("chown");
    }

    // chmod u-x,go-wx /etc/group-
    if (chmod("/etc/group-", S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) == -1) {
        perror("chmod");
    }

     if (chown("/etc/shadow", 0, 2) == -1) {
        perror("chown");
    }

    if (chown("/etc/shadow-", 0, 2) == -1) {
        perror("chown");
    }

    if (chmod("/etc/shadow", S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP) == -1) {
        perror("chmod");
    }

    if (chmod("/etc/shadow-", S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP) == -1) {
        perror("chmod");
    }

    struct passwd *pwd = getpwnam("root");
    struct group *grp = getgrnam("shadow");

    if (chown("/etc/gshadow", pwd->pw_uid, grp->gr_gid) == -1) {
        perror("chown");
    }

    if (chmod("/etc/gshadow", S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP) == -1) {
        perror("chown");
    }

    if (chown("/etc/gshadow-", pwd->pw_uid, grp->gr_gid) == -1) {
        perror("chown");
    }

    if (chmod("/etc/gshadow-", S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP) == -1) {
        perror("chown");
    }    
}


void audit_user_and_groups() {
    // Remove sudo privileges from all users
    struct passwd *pwd;
    while ((pwd = getpwent()) != NULL) {  // Iterate over all users
        // Skip the root user
        if (pwd->pw_uid == 0) {
            continue;
        }
        // Remove the user from the sudo group
        struct group *sudo_group = getgrnam("sudo");
        if (sudo_group == NULL) {
            fprintf(stderr, "Error: Could not find the sudo group.\n");
            continue;
        }
        gid_t sudo_gid = sudo_group->gr_gid;
        gid_t *groups;
        int num_groups = getgrouplist(pwd->pw_name, pwd->pw_gid, NULL, &num_groups);
        if (num_groups == -1) {
            groups = malloc(sizeof(gid_t));
            if (groups == NULL) {
                fprintf(stderr, "Error: Failed to allocate memory.\n");
                continue;
            }
        } else {
            groups = malloc(num_groups * sizeof(gid_t));
            if (groups == NULL) {
                fprintf(stderr, "Error: Failed to allocate memory.\n");
                continue;
            }
            if (getgrouplist(pwd->pw_name, pwd->pw_gid, groups, &num_groups) == -1) {
                fprintf(stderr, "Error: Failed to get group list for user %s.\n", pwd->pw_name);
                free(groups);
                continue;
            }
        }
        int i;
        int changed = 0;
        for (i = 0; i < num_groups; i++) {
            if (groups[i] == sudo_gid) {
                groups[i] = pwd->pw_gid;
                changed = 1;
            }
        }
        if (changed) {
            if (setgroups(num_groups, groups) == -1) {
                fprintf(stderr, "Error: Failed to set group list for user %s.\n", pwd->pw_name);
            }
        }
        free(groups);
    }

    endpwent();  // Close the password database
}


void ensure_shadowed_passwords() {
    // Check if the system uses shadowed passwords
    struct stat sb;
    if (stat("/etc/shadow", &sb) != 0 || !(sb.st_mode & S_IRUSR)) {
        fprintf(stderr, "Error: Shadowed passwords are not enabled on this system.\n");
        return 1;
    }

    // Open the /etc/passwd file for reading and /etc/shadow file for writing
    FILE *passwd_file = fopen("/etc/passwd", "r");
    if (passwd_file == NULL) {
        perror("Error opening /etc/passwd");
        return 1;
    }

    FILE *shadow_file = fopen("/etc/shadow", "w");
    if (shadow_file == NULL) {
        perror("Error opening /etc/shadow");
        fclose(passwd_file);
        return 1;
    }

    // Parse each line of the /etc/passwd file
    char line[1024];
    while (fgets(line, sizeof(line), passwd_file) != NULL) {
        // Extract the username and password
        char *username = strtok(line, ":");
        char *password = strtok(NULL, ":");
        char *uid = strtok(NULL, ":");
        char *gid = strtok(NULL, ":");
        char *gecos = strtok(NULL, ":");
        char *home = strtok(NULL, ":");
        char *shell = strtok(NULL, ":");

        // If a password is found, remove it and write the modified line to the /etc/shadow file
        if (password != NULL && strlen(password) > 0) {
            // Create a blank entry in the shadow file for this user
            fprintf(shadow_file, "%s::", username);

            // Copy the remaining fields from the passwd file to the shadow file
            if (uid != NULL) fprintf(shadow_file, "%s:", uid);
            if (gid != NULL) fprintf(shadow_file, "%s:", gid);
            if (gecos != NULL) fprintf(shadow_file, "%s:", gecos);
            if (home != NULL) fprintf(shadow_file, "%s:", home);
            if (shell != NULL) fprintf(shadow_file, "%s", shell);

            fprintf(shadow_file, "\n");
        } else {
            // If the line does not contain a password, copy it to the shadow file as-is
            fprintf(shadow_file, "%s", line);
        }
    }

    // Close both files
    fclose(passwd_file);
    fclose(shadow_file);
}

/*
Description - While the system administrator can establish secure permissions for users' home
directories, the users can easily override these.

Rationale - Group or world-writable user home directories may enable malicious users to steal or
modify other users' data or to gain another user's system privileges
*/
void audit_home_directories() {
    struct passwd *pw;
    struct stat sb;
    int min_perm = 0750;

    while ((pw = getpwent()) != NULL) {
        char *homedir = pw->pw_dir;
        if (stat(homedir, &sb) == -1) {
            perror("stat");
            continue;
        }
        mode_t perm = sb.st_mode & 0777;
        if (perm < min_perm) {
            if (chmod(homedir, min_perm) == -1) {
                perror("chmod");
            } else {
                printf("Updated permissions for %s's home directory: %s\n", pw->pw_name, homedir);
            }
        }
    }

    endpwent();
}

void audit_uids() {
    struct passwd *pwd;
    int root_uid = 0;
    int uid_changes = 0;


    // Iterate over all entries in the passwd file
    while ((pwd = getpwent()) != NULL) {
        // If an account other than root has UID 0, change its UID to a value other than 0
        if (pwd->pw_uid == root_uid && strcmp(pwd->pw_name, "root") != 0) {
        printf("Changing UID of account %s\n", pwd->pw_name);
        uid_t new_uid = getuid() + uid_changes + 1;
        if (setuid(new_uid) != 0) {
            fprintf(stderr, "Failed to set UID for account %s: %s\n", pwd->pw_name, strerror(errno));
            exit(EXIT_FAILURE);
        }
        uid_changes++;
        }
    }

    endpwent(); // Close the passwd file

    // Check if any changes were made
    if (uid_changes > 0) {
     printf("Successfully changed UID for %d account(s)\n", uid_changes);
    } else {
      printf("Root is the only UID 0 account\n");
    }
}

void audit_shadow_group() {
    struct group *shadow_group;
    int n_members = 0;
    char **members;
    struct passwd *pwd;
    int rc;

    shadow_group = getgrnam("shadow");
    if (shadow_group == NULL) {
        printf("Error: shadow group does not exist\n");
        exit(EXIT_FAILURE);
    }

    members = shadow_group->gr_mem;

    // Count the number of members in the group
    while (members[n_members] != NULL) {
        n_members++;
    }

    if (n_members == 0) {
        printf("Shadow group is empty\n");
        exit(EXIT_SUCCESS);
    }

    printf("Removing %d member(s) from shadow group\n", n_members);

    for (int i = 0; i < n_members; i++) {
        pwd = getpwnam(members[i]);
        if (pwd == NULL) {
        printf("Error: failed to get passwd entry for user %s\n", members[i]);
        exit(EXIT_FAILURE);
        }
        rc = setgroups(1, &pwd->pw_gid);
        if (rc != 0) {
        printf("Error: failed to set group for user %s: %s\n", members[i], strerror(errno));
        exit(EXIT_FAILURE);
        }
    }

    printf("Successfully removed all members from shadow group\n");

}
