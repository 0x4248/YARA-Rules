/*
 * Add
 * This is for testing YARA rules
 * Compile with GCC or Windows C Compiler
*/

#include <stdio.h>


/**
 * add - Adds two numbers
 * @param a: First number
 * @param b: Second number
 * @returns: Sum of a and b
*/
int add(int a, int b)
{
    return a + b;
}


/**
 * main - Prints the sum of two numbers that are passed as arguments
 * @param argc: Number of arguments
 * @param argv: Array of arguments
 * @returns: 0
*/
int main(int argc, char *argv[])
{
    int a, b, sum;

    if (argc != 3)
    {
        printf("Usage: %s <num1> <num2>\n", argv[0]);
        return 1;
    } else {
        a = atoi(argv[1]);
        b = atoi(argv[2]);
        sum = add(a, b);
        printf("%d + %d = %d\n", a, b, sum);
        return 0;
    }
}