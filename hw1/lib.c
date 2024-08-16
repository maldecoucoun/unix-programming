// lib.c
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <limits.h>
#include <stdarg.h>
#include <fnmatch.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/stat.h>
#include <sys/types.h>


static FILE *(*original_fopen)(const char *, const char *) = NULL;
static size_t (*original_fread)(void *ptr, size_t size, size_t nmemb, FILE *stream) = NULL;
static size_t (*original_fwrite)(const void *, size_t, size_t, FILE *) = NULL;
static int (*original_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;
static int (*original_getaddrinfo)(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) = NULL;
static int (*original_system)(const char *command) = NULL;

static int (*original_printf)(const char *format, ...) = NULL;

void init() __attribute__((constructor));
void finalize() __attribute__((destructor));

typedef struct Blacklist {
    char *pattern;
    // FILE *ptr;
    struct Blacklist *next;
    FILE *logFile;
} Blacklist;

typedef struct FileMapEntry {
    FILE* file;
    char* path;
    struct FileMapEntry* next;
} FileMapEntry;

FileMapEntry* fileMapHead = NULL;  // Head of the linked list


char real_path[PATH_MAX];
Blacklist *open_blacklist = NULL;
Blacklist *read_blacklist = NULL;
Blacklist *write_blacklist = NULL;
Blacklist *connect_blacklist = NULL;
Blacklist *getaddrinfo_blacklist = NULL;
static char *current_filename = NULL;

typedef struct LogFileMapping {
    char *filename;
    char *log_filename;
    struct LogFileMapping *next;
} LogFileMapping;

LogFileMapping *log_file_head = NULL;

void add_file_mapping(FILE* file, const char* path) {
    FileMapEntry* entry = (FileMapEntry*) malloc(sizeof(FileMapEntry));
    if (entry == NULL) return; // Handle allocation failure

    entry->file = file;
    entry->path = strdup(path);  // Duplicate the path for storage
    entry->next = fileMapHead;
    fileMapHead = entry;
}


const char *get_log_filename(const char *operation, const char *filename) {
    static pid_t pid = 0;
    if (pid == 0) {
        pid = getpid(); // Capture PID once
    }

    char expected_suffix[20];
    snprintf(expected_suffix, sizeof(expected_suffix), "-%s.log", operation); // Constructs "-read.log" or "-write.log"

    // printf("Operation: %s, Checking for log filename with suffix: %s\n", operation, expected_suffix);

    // LogFileMapping *current = log_file_head;
    // while (current) {
    //     if (strcmp(current->filename, filename) == 0) {
    //         return current->log_filename; // Return existing log filename if found
    //     }
    //     current = current->next;
    // }
    
    LogFileMapping *new_mapping = malloc(sizeof(LogFileMapping));
    if (new_mapping) {
        new_mapping->filename = strdup(filename);
        new_mapping->log_filename = malloc(1024);
        snprintf(new_mapping->log_filename, 256, "%d-%s%s", pid, filename, expected_suffix);
        // printf("Creating new log mapping: %s\n", new_mapping->log_filename);
        new_mapping->next = log_file_head;
        log_file_head = new_mapping;
        return new_mapping->log_filename;
    }
    return NULL;
}

char *strdup_clean(const char *src) {
    if (!src) return NULL;
    while(isspace((unsigned char)*src)) src++;  // Skip leading whitespace
    if (*src == '\0') return strdup("");  // Return an empty string if only whitespace

    const char *end = src + strlen(src) - 1;
    while(end > src && isspace((unsigned char)*end)) end--;
    int len = end - src + 1;

    char *dest = malloc(len + 1);
    if (dest) {
        strncpy(dest, src, len);
        dest[len] = '\0';
    }
    return dest;
}

static void add_to_blacklist(Blacklist **list, const char *pattern) {
    Blacklist *new_node = malloc(sizeof(Blacklist));
    if (!new_node) {
        perror("Failed to allocate memory for blacklist node");
        return;
    }
    new_node->pattern = strdup_clean(pattern);
    new_node->next = *list;
    *list = new_node;
    // printf("Added to blacklist: %s\n", new_node->pattern); // Debugging output
}

static void free_blacklist(Blacklist *list) {
    Blacklist *current;
    while (list) {
        current = list;
        list = list->next;
        free(current->pattern);
        free(current);
    }
}

int count_chars(const char *str, char ch) {
    int count = 0;
    while (*str) {
        if (*str == ch) count++;
        str++;
    }
    return count;
}

const char *extract_match_part(const char *pattern) {
    const char *star = strchr(pattern, '*');
    if (star) {
        static char buffer[256];
        int length = star - pattern;
        strncpy(buffer, pattern, length);
        buffer[length] = '\0';
        return buffer;
    }
    return pattern;
}

const char *resolve_relative_path(const char *pattern) {
    static char resolved_path[PATH_MAX];
    if (pattern[0] == '.') { 
        char cwd[PATH_MAX];
        if (getcwd(cwd, sizeof(cwd)) == NULL) {
            perror("getcwd failed");
            return NULL;
        }
        snprintf(resolved_path, sizeof(resolved_path), "%s%s", cwd, pattern + 1);
        return resolved_path;
    }
    return pattern; 
}

int is_file_blacklisted(const char *filename, Blacklist *list) {
    while (list) {
        if (list->pattern) {
            const char *pattern_prefix = extract_match_part(list->pattern);
            const char *absolute_pattern_prefix = resolve_relative_path(pattern_prefix);

            // printf("    Pattern: %s\n", list->pattern);
            // printf("    Pattern prefix for matching: '%s'\n", absolute_pattern_prefix);
            // printf("    Original filename: '%s'\n", filename);
            // printf("\n");

            if (strstr(filename, absolute_pattern_prefix) != NULL) {
                printf("    Match found. Blacklisting '%s'\n\n\n", filename);
                return 1;
            } else {
                // printf("No match found for this pattern.\n\n");
            }

            list = list->next;
        } 
    }
    return 0;
}

int is_word_blacklisted(const char *data, Blacklist *list) {
    while (list) {
        // printf("Pattern: %s\n", list->pattern);
        // printf("Data: %s\n", data);
        // printf("Pattern length: %zu\n", strlen(list->pattern));
        // printf("Data length: %zu\n", strlen(data));
        if (strstr(data, list->pattern) != NULL) {
            return 1;
        }
        list = list->next;
    }
    return 0;
}

void print_blacklists() {
    const char *categories[] = {"open", "read", "write", "connect", "getaddrinfo"};
    Blacklist *lists[] = {open_blacklist, read_blacklist, write_blacklist, connect_blacklist, getaddrinfo_blacklist};
    size_t num_categories = sizeof(categories) / sizeof(categories[0]);

    for (size_t i = 0; i < num_categories; i++) {
        printf("Blacklist for %s:\n", categories[i]);
        Blacklist *current = lists[i];
        if (current == NULL) {
            printf("  [Empty]\n");
        }
        while (current != NULL) {
            printf("  %s\n", current->pattern);
            current = current->next;
        }
    }
}

void read_config(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open config file");
        return;
    }

    char line[256];
    Blacklist **current_list = NULL;

    while (fgets(line, sizeof(line), file)) {
        // Remove any newline character
        line[strcspn(line, "\r\n")] = 0;  // Handle both Unix and Windows line endings
        if (strstr(line, "BEGIN open-blacklist")) {
            current_list = &open_blacklist;
        } else if (strstr(line, "BEGIN read-blacklist")) {
            current_list = &read_blacklist;
        } else if (strstr(line, "BEGIN write-blacklist")) {
            current_list = &write_blacklist;
        } else if (strstr(line, "BEGIN connect-blacklist")) {
            current_list = &connect_blacklist;
        } else if (strstr(line, "BEGIN getaddrinfo-blacklist")) {
            current_list = &getaddrinfo_blacklist;
        } else if (strstr(line, "END")) {
            current_list = NULL;
        } else if (current_list && line[0] != '\n' && line[0] != '#') {
            add_to_blacklist(current_list, line);
        }
    }

    // print_blacklists();
    fclose(file);
}

char* process_filename(const char *input_path) {
    // Duplicate input to a new modifiable string
    char *result = strdup(input_path);
    if (!result) {
        perror("Failed to allocate memory");
        return NULL;
    }

    // Find the last '/' to isolate the filename
    char *last_slash = strrchr(result, '/');
    if (last_slash) {
        // Shift the filename to the start of the string
        memmove(result, last_slash + 1, strlen(last_slash));
    }

    // Find the last '.' to remove file extension
    char *dot = strrchr(result, '.');
    if (dot) {
        *dot = '\0';  // Terminate string at the dot to remove extension
    }

    return result;  // Caller must free this memory
}

FILE *fopen(const char *path, const char *mode) {

    if (strcmp(path, "config.txt") == 0) {
        return original_fopen(path, mode);
    }

    current_filename = process_filename(path);

    if (realpath(path, real_path) == NULL) {
        perror("realpath failed");
        return NULL;
    }
    
    if (is_file_blacklisted(real_path, open_blacklist)) {
        errno = EACCES;
        fprintf(stderr, "[logger] fopen(\"%s\", \"%s\") = 0x0\n", path, mode);
        return NULL;
    }

    // printf("Processed filename: %s\n", current_filename);

    FILE *result = original_fopen(path, mode);

    fprintf(stderr, "[logger] fopen(\"%s\", \"%s\") = %p\n", path, mode, result);
    
    return result;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    size_t result = original_fread(ptr, size, nmemb, stream);
    size_t actual_size = size * nmemb;
    char *read_data = malloc(actual_size + 1);
    // bool flag = false;
    
    if (read_data) {
        memcpy(read_data, ptr, actual_size);
        read_data[actual_size] = '\0';
        
        if (is_word_blacklisted(read_data, read_blacklist)) {
            errno = EACCES;
            fprintf(stderr, "[logger] fread(\"%p\", %zu, %zu, %p) = 0\n", ptr, size, nmemb, stream);
            memset(ptr, 0, sizeof(read_data));
            return 0;  
        }
        free(read_data);
    }

    const char *log_filename = get_log_filename("read", current_filename);
    if (log_filename) {
        FILE *logFile = original_fopen(log_filename, "a");
        if (logFile) {
            fprintf(logFile, "%s", (const char*)ptr);
            fclose(logFile);
        }
    }
    fprintf(stderr, "[logger] fread(\"%p\", %zu, %zu, %p) = %zu\n", ptr, size, nmemb, stream, result);
    return result;   
}

char* escape_string(const char* input) {
    if (input == NULL) return NULL;

    size_t input_len = strlen(input);
    size_t output_len = 0;

    // Calculate the length of the output string
    for (size_t i = 0; i < input_len; ++i) {
        switch (input[i]) {
            case '\n': output_len += 2; break; // "\n" -> "\\n"
            case '\t': output_len += 2; break; // "\t" -> "\\t"
            case '\\': output_len += 2; break; // "\\" -> "\\\\"
            default: output_len += 1; break;
        }
    }

    // Allocate memory for the output string
    char* output = (char*)malloc(output_len + 1); // +1 for null terminator
    if (output == NULL) return NULL;

    size_t pos = 0;
    for (size_t i = 0; i < input_len; ++i) {
        switch (input[i]) {
            case '\n':
                output[pos++] = '\\';
                output[pos++] = 'n';
                break;
            case '\t':
                output[pos++] = '\\';
                output[pos++] = 't';
                break;
            case '\\':
                output[pos++] = '\\';
                output[pos++] = '\\';
                break;
            default:
                output[pos++] = input[i];
                break;
        }
    }
    output[pos] = '\0'; // Null-terminate the string

    return output;
}

const char* get_blacklist_pattern(Blacklist* head, const char* key) {
    while (head != NULL) {
        if (strcmp(head->pattern, key) == 0) {
            return head->pattern;  
        }
        head = head->next; 
    }
    return NULL; 
}

const char* get_path_from_file_ptr(FILE* file) {
    FileMapEntry* entry = fileMapHead;
    while (entry != NULL) {
        if (entry->file == file) {
            return entry->path;  
        }
        entry = entry->next;
    }
    return NULL;  // Not found
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    size_t total_bytes = size * nmemb;
    char *data = (char *)malloc(total_bytes + 1);
    if (!data) {
        perror("Memory allocation failed for fwrite buffer");
        return 0;
    }

    memcpy(data, ptr, total_bytes);
    data[total_bytes] = '\0';
    
    size_t written = original_fwrite(ptr, size, nmemb, stream);
    
    // const char *path = get_path_from_file_ptr(stream);
    // if (realpath(path, real_path) == NULL) {
    //     perror("realpath failed");
    //     return 0;
    // }
    char proclnk[1024];
    char filename[1024];
    ssize_t r;
    int fno = fileno(stream);
    snprintf(proclnk, sizeof(proclnk), "/proc/self/fd/%d", fno);
    r = readlink(proclnk, filename, sizeof(filename) - 1);
    if (r < 0) {
        perror("Failed to readlink");
        free(data);
        return 0;
    }
    filename[r] = '\0';

    // printf("    fp -> fno -> filename: %p -> %d -> %s\n", stream, fno, filename);

    char* escaped_str = escape_string((const char*)ptr);    

    if (is_file_blacklisted(filename, write_blacklist)) {
        errno = EACCES;
        if (escaped_str) {            
            fprintf(stderr, "[logger] fwrite(\"%s\", %zu, %zu, %p) = 0\n", escaped_str, size, nmemb, stream);
            free(escaped_str); 
        } else {            
            fprintf(stderr, "[logger] fwrite(\"%s\", %zu, %zu, %p) = 0\n", (char*)ptr, size, nmemb, stream);
        }
        return 0;
    }
    
    else  {const char *log_filename = get_log_filename("write", filename);
        if (log_filename) {
            FILE *logFile = original_fopen(log_filename, "a");
            if (logFile) {
                fprintf(logFile, "%s", data);
                free(data);
                fclose(logFile);
            }
        }
    

        if (escaped_str) {
            fprintf(stderr, "[logger] fwrite(\"%s\", %zu, %zu, %p) = %zu\n", escaped_str, size, nmemb, stream, written);
            free(escaped_str); 
        } else {
            fprintf(stderr, "[logger] fwrite(\"%s\", %zu, %zu, %p) = %zu\n", (char*)ptr, size, nmemb, stream, written);
        }  
        
        return written;
    }
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    char ip_str[INET6_ADDRSTRLEN];  // Buffer to hold the IP address string
    int result;
   
    if (addr->sa_family == AF_INET) {  // IPv4
        const struct sockaddr_in *in_addr = (const struct sockaddr_in *)addr;
        if (inet_ntop(AF_INET, &(in_addr->sin_addr), ip_str, sizeof(ip_str)) == NULL) {
            perror("inet_ntop failed for IPv4");
            return -1;
        }

    } else if (addr->sa_family == AF_INET6) {  // IPv6
        const struct sockaddr_in6 *in6_addr = (const struct sockaddr_in6 *)addr;
        if (inet_ntop(AF_INET6, &(in6_addr->sin6_addr), ip_str, sizeof(ip_str)) == NULL) {
            perror("inet_ntop failed for IPv6");
            return -1;
        }
    } else {
        fprintf(stderr, "Unsupported address family.\n");
        return -1;
    }

    if (is_word_blacklisted(ip_str, connect_blacklist)) {
        errno = ECONNREFUSED;
        fprintf(stderr, "[logger] connect(%d, \"%s\", %u) = -1\n", sockfd, ip_str, addrlen);
        // fprintf(stderr, "Error with client connecting to server");
        return -1;  // Block the connection attempt
    }

    else {
        result = original_connect(sockfd, addr, addrlen);
        fprintf(stderr, "[logger] connect(%d, \"%s\", %u) = %d\n", sockfd, ip_str, addrlen, result);
        return result;
    }
}

int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
    int result = -1;

    if (is_word_blacklisted(node, getaddrinfo_blacklist)) {
        int error_code = EAI_NONAME;
        fprintf(stderr, "[logger] getaddrinfo(\"%s\", %s, %p, %p) = %d\n",
            node, service ? service : "(nil)", (void *)hints, (void *)res, error_code);
        return error_code; 
    }
    else {
        result = original_getaddrinfo(node, service, hints, res);
        fprintf(stderr, "[logger] getaddrinfo(\"%s\", %s, %p, %p) = %d\n",
                node, service ? service : "(nil)", (void *)hints, (void *)res, result);

        if (result == 0) {
            struct addrinfo *rp;
            char addrstr[100];
            void *ptr;
            for (rp = *res; rp != NULL; rp = rp->ai_next) {
                switch (rp->ai_family) {
                    case AF_INET:
                        ptr = &((struct sockaddr_in *) rp->ai_addr)->sin_addr;
                        break;
                    case AF_INET6:
                        ptr = &((struct sockaddr_in6 *) rp->ai_addr)->sin6_addr;
                        break;
                }
                inet_ntop(rp->ai_family, ptr, addrstr, 100);
                // fprintf(stderr, "IP address: %s\n", addrstr);
            }
        }
        return result;
    }
}

int system(const char *command) {

    int result = original_system(command);

    fprintf(stderr, "[logger] system(\"%s\") = %d\n", command, result);

    return result;
}


int printf(const char *format, ...) {
    va_list args;
    va_start(args, format);
    int result = vfprintf(stdout, format, args);
    va_end(args);
    return result;
}


void init_hook(void) __attribute__((constructor));
void finish_hook(void) __attribute__((destructor));

void init() {
    original_printf = dlsym(RTLD_NEXT, "printf");
    const char* output_file = getenv("LOGGER_OUTPUT");
    if (output_file) {
        freopen(output_file, "a", stderr); 
    }
}

void finalize() {
    fclose(stdout);
}

void init_hook() {
    original_fopen = dlsym(RTLD_NEXT, "fopen");
    original_fread = dlsym(RTLD_NEXT, "fread");
    original_fwrite = dlsym(RTLD_NEXT, "fwrite");
    original_connect = dlsym(RTLD_NEXT, "connect");
    original_getaddrinfo = dlsym(RTLD_NEXT, "getaddrinfo");
    original_system = dlsym(RTLD_NEXT, "system");
    read_config("config.txt"); // adjust the path as necessary
}

void finish_hook() {
    free_blacklist(open_blacklist);
    free_blacklist(read_blacklist);
    free_blacklist(write_blacklist);
    free_blacklist(connect_blacklist);
    free_blacklist(getaddrinfo_blacklist);
}

