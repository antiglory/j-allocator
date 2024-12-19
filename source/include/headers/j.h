#ifndef J_H
#define J_H

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

// macros
#define TRUE  1
#define FALSE 0

#define JC_ERROR_INVALID_POINTER  0x22

#define JF_ERROR_DOUBLE_FREE      0x69
#define JF_ERROR_INVALID_POINTER  0x70

#define JI_ERROR_ALREADY_INITIALIZED        0x11
#define JI_ERROR_SECTION_ALLOCATION_FAILED  0x12

#define JA_ERROR_VALIDATE_PRIV  0x51
#define JA_ERROR_PERMISSION_SET 0x52
#define JA_ERROR_HEAP_ADJUST    0x55

#define JI_ERROR_SHM_OPEN     0x15
#define JI_ERROR_FTRUNCATE    0x16
#define JI_ERROR_MMAP         0x17

#define JCACHE_CHUNK_AMOUNT   16
#define JCACHE_SIZE_INCREMENT 128

#define PROT_READ_BIT   0x1
#define PROT_WRITE_BIT  0x2
#define PROT_EXEC_BIT   0x4

#define INUSE_BIT       0x1
#define PREV_INUSE_BIT  0x2
#define IS_MMAPED_BIT   0x4

#define CHUNK_ALIGNMENT_BYTES 8

// typedefs
typedef unsigned char byte_t;

typedef struct chunk_t {
    size_t          size;   // chunk size
    size_t          hsize;  // headers size
    byte_t          flags;  // PREV_INUSE, INUSE and MMAPED
    struct chunk_t* fd;     // forward chunk pointer
    struct chunk_t* bk;     // backward chunk pointer
    // chunk_t is approximately 40 bytes long (this may trigger overhead)
} chunk_t;

typedef struct {
    chunk_t* jcachebin[JCACHE_CHUNK_AMOUNT];
    int32_t  jerrorcode;
    byte_t   initialized;
} jinfo_t;

// settings
__attribute__((visibility("default"))) void* jalloc(size_t size, byte_t priv);
__attribute__((visibility("default"))) void  jfree(void* ptr);

#endif
