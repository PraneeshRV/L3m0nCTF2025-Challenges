#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void setup() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void win() {
    puts("Congratulations! Here is your shell.");
    system("/bin/sh");
}

void vuln() {
    char buffer[256];
    while(1) {
        printf("> ");
        if (fgets(buffer, sizeof(buffer), stdin) == NULL) break;
        
        
        printf(buffer);
        
        
        if (strncmp(buffer, "exit", 4) == 0) {
            break;
        }
    }
}

int main() {
    setup();
    puts("Welcome to the Format Pie Shop!");
    puts("We serve pies with a side of addresses.");
    vuln();
    return 0;
}
