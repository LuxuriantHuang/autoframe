//===-- demo2_input.c - Demo: Input Variables (Should Be Filtered) ------===//
///
/// This demo shows variables that come from user input.
/// These should be FILTERED OUT by taint analysis.
///
//===----------------------------------------------------------------------===//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Flag constants (these should still be identified)
#define MODE_SECURE  0x01
#define MODE_VERBOSE 0x02
#define MODE_DEBUG   0x04

// A real flag variable
static int global_mode = 0;

void set_mode(int mode) {
    global_mode = mode;  // Only accept flag constants

    if (global_mode & MODE_SECURE) {
        printf("Secure mode\n");
    }
}

// Variables that should be filtered (tainted by input)
char buffer[256];
int user_input = 0;

void read_user_input() {
    // These variables are tainted by input - should be filtered
    int n = read(STDIN_FILENO, buffer, sizeof(buffer) - 1);
    if (n > 0) {
        buffer[n] = '\0';
        user_input = atoi(buffer);  // Tainted value
    }

    // Even though we compare user_input, it should be filtered
    if (user_input == 42) {
        printf("Got 42\n");
    }
}

// A function that might look like a flag but receives input
void process_tainted(int tainted_value) {
    // tainted_value comes from input, should be filtered
    if (tainted_value == 1) {
        printf("Tainted branch\n");
    }
}

// Another flag variable (NOT tainted)
static int config_flags = 0;

void configure() {
    // This is a real flag variable
    config_flags = MODE_SECURE | MODE_VERBOSE;

    if (config_flags & MODE_SECURE) {
        printf("Configured securely\n");
    }
}

// Variable from stdin that's used in comparisons
int stdin_value = 0;

int main() {
    // Real flag variable
    global_mode = MODE_SECURE;
    if (global_mode & MODE_SECURE) {
        printf("Secure\n");
    }

    // Tainted input
    printf("Enter a number: ");
    fflush(stdout);

    char line[32];
    if (fgets(line, sizeof(line), stdin)) {
        stdin_value = atoi(line);  // Tainted!

        // Even though we compare it, stdin_value should be filtered
        if (stdin_value == 100) {
            printf("Got 100\n");
        }
    }

    // More tainted input
    read_user_input();
    process_tainted(user_input);

    // Another flag variable
    config_flags = MODE_DEBUG;
    if (config_flags == MODE_DEBUG) {
        printf("Debug mode\n");
    }

    return 0;
}
