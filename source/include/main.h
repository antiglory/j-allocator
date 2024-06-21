#ifndef HEADER_H
#define HEADER_H

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <inttypes.h>

// macros
#define TRUE  1
#define FALSE 0

#define CHUNK_ALIGNMENT_BYTES 8

#define JCACHE_CHUNK_AMOUNT   16
#define JCACHE_SIZE_INCREMENT 128

#define PROT_READ_BIT   0x1
#define PROT_WRITE_BIT  0x2
#define PROT_EXEC_BIT   0x4

#define INUSE_BIT       0x1
#define PREV_INUSE_BIT  0x2
#define IS_MMAPED_BIT   0x4

// typedefs
typedef unsigned char byte_t;

typedef struct chunk_t {
    size_t size;        // chunk size
    size_t hsize;       // headers size
    byte_t flags;       // PREV_INUSE, INUSE and MMAPED
    struct chunk_t* fd; // forward chunk pointer
    struct chunk_t* bk; // backward chunk pointer
} chunk_t;

#endif
