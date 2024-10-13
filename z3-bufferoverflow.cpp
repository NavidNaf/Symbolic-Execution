#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[10];
    strcpy(buffer, input);  // Vulnerable: No bounds checking!
    printf("Input: %s\n", buffer);
}

int main() {
    char user_input[100];
    printf("Enter your input: ");
    gets(user_input);  // Vulnerable: gets doesn't check bounds!
    vulnerable_function(user_input);
    return 0;
}