//===-- demo3_arithmetic.c - Demo: Arithmetic Variables (Should Be Filtered) ---===//
///
/// This demo shows variables involved in arithmetic operations.
/// These should be FILTERED OUT as they're not flag variables.
///
//===----------------------------------------------------------------------===//

#include <stdio.h>

// Flag constants (should be identified)
#define COLOR_RED   0xFF0000
#define COLOR_GREEN 0x00FF00
#define COLOR_BLUE  0x0000FF

// Real flag variables
static int current_color = COLOR_RED;
static int display_mode = 0;

// These are NOT flag variables - arithmetic counters/accumulators
int loop_counter = 0;
int byte_count = 0;
int running_sum = 0;
float average = 0.0f;

// Arithmetic variables in computation
void compute_statistics(int data[], int n) {
    int sum = 0;      // Accumulator - should be filtered
    int min = data[0];
    int max = data[0];

    for (loop_counter = 0; loop_counter < n; loop_counter++) {
        sum += data[loop_counter];           // Arithmetic!
        if (data[loop_counter] < min) {
            min = data[loop_counter];
        }
        if (data[loop_counter] > max) {
            max = data[loop_counter];
        }
    }

    running_sum = sum;
    average = (float)sum / n;  // Division!

    byte_count = n * sizeof(int);
}

// Index variable (arithmetic)
void process_array(int arr[], int size) {
    int i = 0;  // Loop index - arithmetic

    for (i = 0; i < size; i++) {
        arr[i] = arr[i] * 2;  // Arithmetic operation
    }

    // Total bytes
    int total = size * 4;  // Arithmetic!
}

// Real flag variable usage
void set_display_color(int color) {
    current_color = color;  // Assignment of flag constant

    if (current_color == COLOR_RED) {
        printf("Red color\n");
    } else if (current_color == COLOR_GREEN) {
        printf("Green color\n");
    } else if (current_color == COLOR_BLUE) {
        printf("Blue color\n");
    }
}

// Mixed: some flags, some arithmetic
void mixed_function(int count) {
    int local_flag = COLOR_RED;      // Flag variable
    int accumulator = 0;             // Arithmetic variable

    // Flag operations
    if (local_flag == COLOR_RED) {
        printf("Red\n");
    }

    // Arithmetic operations
    for (int i = 0; i < count; i++) {
        accumulator += i;  // Arithmetic!
    }

    // Result used but still arithmetic
    if (accumulator > 100) {
        printf("Large sum\n");
    }
}

// File processing with arithmetic
int process_data(const char* filename) {
    int bytes_read = 0;    // Arithmetic counter
    int chunks = 0;        // Arithmetic counter

    // Simulated processing
    bytes_read = 1024;
    chunks = bytes_read / 256;  // Division!

    if (chunks > 4) {
        printf("Many chunks\n");
    }

    return bytes_read;
}

// Position tracking (arithmetic)
struct Position {
    int x, y;
};

struct Position cursor_pos = {0, 0};

void move_cursor(int dx, int dy) {
    cursor_pos.x += dx;  // Arithmetic!
    cursor_pos.y += dy;  // Arithmetic!
}

// Real flag: file open mode
#define MODE_RDONLY 0
#define MODE_WRONLY 1
#define MODE_RDWR   2

static int file_mode = MODE_RDONLY;

void open_file(int mode) {
    file_mode = mode;  // Flag assignment

    if (file_mode == MODE_RDONLY) {
        printf("Read-only\n");
    } else if (file_mode == MODE_WRONLY) {
        printf("Write-only\n");
    } else if (file_mode == MODE_RDWR) {
        printf("Read-write\n");
    }
}

int main() {
    // Real flag variables
    current_color = COLOR_GREEN;
    display_mode = 1;

    if (current_color == COLOR_GREEN) {
        printf("Current is green\n");
    }

    set_display_color(COLOR_BLUE);
    open_file(MODE_RDWR);

    // Arithmetic operations (these variables should be filtered)
    int data[] = {1, 2, 3, 4, 5};
    compute_statistics(data, 5);

    printf("Sum: %d, Average: %.2f\n", running_sum, average);
    printf("Loop counter: %d, Byte count: %d\n", loop_counter, byte_count);

    process_array(data, 5);

    move_cursor(10, 20);
    printf("Position: %d, %d\n", cursor_pos.x, cursor_pos.y);

    process_data("data.bin");

    return 0;
}
