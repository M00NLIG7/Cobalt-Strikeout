#include "discovery.h"

int file_contains_pii(const char* file_path) {
    // Ignore binary files
    FILE* fp = fopen(file_path, "rb");
    if (fp != NULL) {
        char buf[1024];
        size_t read_size = fread(buf, 1, sizeof(buf), fp);
        fclose(fp);
        if (read_size > 0 && buf[0] == '\0') {
            return 0;
        }
    }

    // Search for PII using regular expressions
    regex_t ssn_regex, credit_card_regex, email_regex;
    int reti;
    char line[MAX_LINE_LENGTH];

    // SSN regex pattern
    char *ssn_pattern = "[0-9]{3}-[0-9]{2}-[0-9]{4}";

    // Credit card regex pattern
    char *credit_card_pattern = "[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}";

    // Email regex pattern
    char *email_pattern = "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,4}";

    // Compile regular expressions
    reti = regcomp(&ssn_regex, ssn_pattern, REG_EXTENDED);
    if (reti) {
        perror("Error compiling SSN regex");
        return 0;
    }
    reti = regcomp(&credit_card_regex, credit_card_pattern, REG_EXTENDED);
    if (reti) {
        perror("Error compiling credit card regex");
        regfree(&ssn_regex);
        return 0;
    }
    reti = regcomp(&email_regex, email_pattern, REG_EXTENDED);
    if (reti) {
        perror("Error compiling email regex");
        regfree(&ssn_regex);
        regfree(&credit_card_regex);
        return 0;
    }

    // Check each line of the file for matches to PII regex patterns
    fp = fopen(file_path, "r");
    if (fp == NULL) {
        perror("fopen");
        regfree(&ssn_regex);
        regfree(&credit_card_regex);
        regfree(&email_regex);
        return 0;
    }
    int found_pii = 0;
    while (fgets(line, MAX_LINE_LENGTH, fp) != NULL) {
        reti = regexec(&ssn_regex, line, 0, NULL, 0);
        if (!reti) {
            found_pii = 1;
            break;
        }
        reti = regexec(&credit_card_regex, line, 0, NULL, 0);
        if (!reti) {
            found_pii = 1;
            break;
        }
        reti = regexec(&email_regex, line, 0, NULL, 0);
        if (!reti) {
            found_pii = 1;
            break;
        }
    }
    fclose(fp);
    regfree(&ssn_regex);
    regfree(&credit_card_regex);
    regfree(&email_regex);
    return found_pii;
}

// Define the thread function
void search_directory(char* directory_path, FILE* output_file) {
    DIR* dir = opendir(directory_path);
    if (dir == NULL) {
        perror("opendir");
        return;
    }
    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') {
            continue; // skip hidden files and directories
        }
        char file_path[MAX_PATH_LENGTH];
        sprintf(file_path, "%s/%s", directory_path, entry->d_name);
        if (entry->d_type == DT_DIR) {
            // Recursively search subdirectories
            search_directory(file_path, output_file);
        } else if (entry->d_type == DT_REG) {
            // Check if file contains PII and write path to output file if it does
            if (file_contains_pii(file_path)) {
                fprintf(output_file, "%s\n", file_path);
            }
        }
    }
    closedir(dir);
}

int file_contains_pattern(const char* file_path, const regex_t* regex) {
    int fd = open(file_path, O_RDONLY);
    if (fd == -1) {
        perror("open");
        return 0;
    }
    struct stat file_stat;
    if (fstat(fd, &file_stat) == -1) {
        perror("fstat");
        close(fd);
        return 0;
    }
    void* file_data = mmap(NULL, file_stat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (file_data == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 0;
    }
    int found_pattern = 0;
    if (regexec(regex, (char*)file_data, 0, NULL, 0) == 0) {
        found_pattern = 1;
    }
    munmap(file_data, file_stat.st_size);
    close(fd);
    return found_pattern;
}

void pii_discovery() {
    char* directory_path = "/home/";
    char* output_file_path = "output";
    FILE* output_file = fopen(output_file_path, "w");
    if (output_file == NULL) {
        perror("fopen");
        return;
    }

    search_directory(directory_path, output_file);

    fclose(output_file);
}

char** detect_databases() {
    DIR *dir;
    struct dirent *entry;
    char *database_names[] = {"mysql", "psql", "redis-server", "mongod", "sqlite3"}; // Add other database names as necessary
    int num_databases = sizeof(database_names) / sizeof(database_names[0]);
    int i, num_installed = 0;
    char **installed_databases = (char**) malloc(num_databases * sizeof(char*)); // Allocate memory for the installed database names

    dir = opendir("/usr/bin"); // Look for databases in the /usr/bin directory
    if (dir == NULL) {
        perror("opendir");
    }

    while ((entry = readdir(dir)) != NULL) {
        for (i = 0; i < num_databases; i++) {
            if (strcmp(entry->d_name, database_names[i]) == 0) {
                installed_databases[num_installed] = strdup(database_names[i]); // Add the installed database name to the list
                num_installed++;
                installed_databases = (char**) realloc(installed_databases, (num_installed+1) * sizeof(char*)); // Reallocate memory for the next installed database name
            }
        }
    }

    closedir(dir);

    installed_databases[num_installed] = NULL; // Set the last element of the array to NULL to mark the end of the list
    installed_databases = (char**) realloc(installed_databases, (num_installed+1) * sizeof(char*)); // Reallocate memory to fit the NULL terminator
    return installed_databases;
}
