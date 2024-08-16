// logger.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    char *so_path = "./logger.so";  // Default shared object path
    char *output_file = NULL;       // Default output file is NULL (stderr)
    int opt;

    // Parse command line options for -p and -o
    while ((opt = getopt(argc, argv, "p:o:")) != -1) {
        switch (opt) {
            case 'p':  // Set the path to the shared object
                so_path = optarg;
                break;
            case 'o':  // Set the output file path
                output_file = optarg;
                break;
            default:
                fprintf(stdout, "Usage: %s [-o file] [-p sopath] config.txt command [args...]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (optind >= argc) {
        fprintf(stdout, "Expected configuration file and command after options\n");
        exit(EXIT_FAILURE);
    }

    // char *config_file = argv[optind];
    optind++; // Increment optind to point to the command

    if (optind >= argc) {
        fprintf(stdout, "Expected command after configuration file\n");
        exit(EXIT_FAILURE);
    }

    setenv("LD_PRELOAD", so_path, 1);
    if (output_file) {
        setenv("LOGGER_OUTPUT", output_file, 1);
    }

    // Execute the command with remaining arguments
    execvp(argv[optind], &argv[optind]);
    perror("execvp");
    return EXIT_FAILURE;
}
