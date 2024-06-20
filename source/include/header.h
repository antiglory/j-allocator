#ifndef HEADER_H
#define HEADER_H

// system libs including

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <inttypes.h>

// macros
#define TRUE 1
#define FALSE 0

#define CHUNK_ALIGNMENT_BYTES 8

#define JCACHE_BINS_NUM 8
#define JCACHE_BIN_SIZE_INCREMENT 128

#define PROT_READ_BIT   0x1
#define PROT_WRITE_BIT  0x2
#define PROT_EXEC_BIT   0x4

#define CHUNK_INUSE_BIT     0x1
#define PREV_INUSE_BIT      0x2
#define NON_MAIN_ARENA_BIT  0x4
#define IS_MMAPED_BIT       0x8

// typedefs
typedef unsigned char byte_t;

typedef struct chunk_t {
    size_t size;
    byte_t flags;
    struct chunk_t* fd;
    struct chunk_t* bk;
} chunk_t;

#endif
