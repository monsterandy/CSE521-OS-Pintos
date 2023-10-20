#ifndef FIXED_POINT_H
#define FIXED_POINT_H

/* Define the number of fractional bits. */
#define FRACT_BITS 15

/* Useful constants. */
#define FP_ONE (1 << FRACT_BITS)
#define FP_HALF (FP_ONE >> 1)

/* Convert an integer to fixed-point format. */
#define INT_TO_FP(n) ((n) << FRACT_BITS)

/* Convert a fixed-point number to integer (rounds toward zero). */
#define FP_TO_INT_ZERO(x) ((x) >> FRACT_BITS)

/* Convert a fixed-point number to integer (rounds to nearest). */
#define FP_TO_INT_NEAREST(x) (((x) >= 0) ? ((x) + FP_HALF) / FP_ONE : ((x) - FP_HALF) / FP_ONE)

/* Add two fixed-point numbers. */
#define FP_ADD(x, y) ((x) + (y))

/* Subtract two fixed-point numbers. */
#define FP_SUB(x, y) ((x) - (y))

/* Add a fixed-point number and an integer. */
#define FP_ADD_MIX(x, n) ((x) + INT_TO_FP(n))

/* Subtract an integer from a fixed-point number. */
#define FP_SUB_MIX(x, n) ((x) - INT_TO_FP(n))

/* Multiply two fixed-point numbers. */
#define FP_MULT(x, y) (((int64_t) (x)) * (y) / FP_ONE)

/* Multiply a fixed-point number by an integer. */
#define FP_MULT_MIX(x, n) ((x) * (n))

/* Divide two fixed-point numbers. */
#define FP_DIV(x, y) (((int64_t) (x)) * FP_ONE / (y))

/* Divide a fixed-point number by an integer. */
#define FP_DIV_MIX(x, n) ((x) / (n))

#endif /* FIXED_POINT_H */