#include <stdlib.h>

#include "audit.h"
#include "discovery.h"
#include "hardening.h"
#include "network.h"
#include "system.h"


void secure_database_services();
// Sanitization shit
// void configure_selinux();
// void configure_apparmor();
// Configure logging
void reverse_linpeas();
// DNS Sec
void secure_dns();


#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>

#include <string.h>


int main() {
    char **installed_databases = detect_databases();
    int i;

    printf("Installed databases:\n");
    for (i = 0; installed_databases[i] != NULL; i++) {
        printf("%s\n", installed_databases[i]);
        free(installed_databases[i]); // Free the memory allocated for each installed database name
    }

    free(installed_databases); // Free the memory allocated for the array of installed database names
    return 0;
}