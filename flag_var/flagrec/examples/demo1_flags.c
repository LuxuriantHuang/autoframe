//===-- demo1_flags.c - Demo: Enum/Macro Flag Variables -----------------===//
///
/// This demo shows typical flag variable usage with enums and macros.
/// Expected to identify: mode, state, options as flag variables.
///
//===----------------------------------------------------------------------===//

#include <stdio.h>

// Enum constants (should be grouped)
typedef enum {
    MODE_READ = 0,
    MODE_WRITE = 1,
    MODE_EXECUTE = 2,
    MODE_APPEND = 3
} FileMode;

// Macro constants (should be grouped)
#define FLAG_READ   0x01
#define FLAG_WRITE  0x02
#define FLAG_EXEC   0x04
#define FLAG_ASYNC  0x08

// Another enum group
typedef enum {
    STATE_IDLE = 0,
    STATE_RUNNING = 1,
    STATE_PAUSED = 2,
    STATE_ERROR = 3
} DeviceState;

// Another macro group
#define LEVEL_DEBUG 0
#define LEVEL_INFO  1
#define LEVEL_WARN  2
#define LEVEL_ERROR 3

// Global flag variable (should be identified)
static FileMode current_mode = MODE_READ;
static DeviceState device_state = STATE_IDLE;

void process_file(FileMode mode) {
    // Assignment of constant
    current_mode = mode;

    // Flag check
    if (current_mode == MODE_WRITE) {
        printf("Write mode\n");
    } else if (current_mode == MODE_READ) {
        printf("Read mode\n");
    }

    // Bitwise check
    int options = FLAG_READ | FLAG_WRITE;
    if (options & FLAG_WRITE) {
        printf("Write enabled\n");
    }
}

void set_device_state(DeviceState state) {
    device_state = state;

    // Switch case check (should be detected)
    switch (device_state) {
        case STATE_IDLE:
            printf("Idle\n");
            break;
        case STATE_RUNNING:
            printf("Running\n");
            break;
        case STATE_PAUSED:
            printf("Paused\n");
            break;
        case STATE_ERROR:
            printf("Error\n");
            break;
    }
}

// Local flag variable in function
void configure_device(int config) {
    int options = FLAG_READ | FLAG_ASYNC;

    if (config & FLAG_READ) {
        printf("Read option set\n");
    }

    if (options & FLAG_ASYNC) {
        printf("Async mode\n");
    }
}

// NOT a flag variable - should be filtered
int counter = 0;
void increment_counter() {
    counter = counter + 1;  // Arithmetic operation
}

int main() {
    // Test assignments
    current_mode = MODE_WRITE;
    device_state = STATE_RUNNING;

    // Test checks
    if (current_mode == MODE_WRITE) {
        printf("In write mode\n");
    }

    process_file(MODE_READ);
    set_device_state(STATE_PAUSED);

    // Bitwise operations
    int flags = FLAG_READ | FLAG_WRITE;
    if (flags & FLAG_WRITE) {
        printf("Write flag set\n");
    }

    for (int i = 0; i < 10; i++) {
        counter++;  // Pure arithmetic, should be filtered
    }

    return 0;
}
