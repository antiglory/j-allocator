#ifndef HEADER_H
#define HEADER_H

// system libs including

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>


// macros
#define TRUE 1
#define FALSE 0

#define CHUNK_ALIGNMENT 8

#define NUM_BINS 8
#define BIN_SIZE_INCREMENT 128

#define PROT_READ_BIT   0x1
#define PROT_WRITE_BIT  0x2
#define PROT_EXEC_BIT   0x4

// typedefs
typedef unsigned char byte_t;

typedef struct chunk_t {
    size_t size;
    byte_t priv;

    byte_t CHUNK_INUSE;
    byte_t PREV_INUSE;
    byte_t NON_MAIN_ARENA;
    byte_t IS_MMAPED;

    struct chunk_t* fd;
    struct chunk_t* bk;
} chunk_t;

#endif
