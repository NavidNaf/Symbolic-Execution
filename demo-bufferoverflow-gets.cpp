#include <stdio.h>
#include <string.h>

int main() {
    char buffer[10];
    printf("Enter some input: ");
    gets(buffer);  // Vulnerable: No bounds checking!
    printf("You entered: %s\n", buffer);
    return 0;
}
