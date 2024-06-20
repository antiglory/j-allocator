#include "include/main.h"

// global vars

// initializing jalloc main bin
chunk_t* jcachebin[JCACHE_BINS_NUM] = {NULL};

// just-align-size
static size_t jalignsize(const size_t size) {
    return (size + CHUNK_ALIGNMENT_BYTES - 1) & ~(CHUNK_ALIGNMENT_BYTES - 1);
}

// just-get-bin-index
int jgetbinindex(const size_t size) {
    return (size / JCACHE_BIN_SIZE_INCREMENT) < JCACHE_BINS_NUM ? (size / JCACHE_BIN_SIZE_INCREMENT) : (JCACHE_BINS_NUM - 1);
}

// helper to coalesce adjacent free chunks
void jcoalescechunk(chunk_t* chunk) {
    const chunk_t* next_chunk = (chunk_t*)((char*)chunk + chunk->size);

    if (!(next_chunk->flags & CHUNK_INUSE_BIT)) {
        chunk->size += next_chunk->size;
        chunk->fd = next_chunk->fd;

        if (next_chunk->fd)
            next_chunk->fd->bk = chunk;
    }
}

void* jalloc(const size_t size, const byte_t priv) {
    int protection_flags;
    void* page_start;
    const size_t aligned_size = jalignsize(size + sizeof(chunk_t));

    // validate the priv bits
    if ((priv & 0x7) != priv) {
        return NULL;
    }

    // set the memory protection flags
    if (priv & PROT_EXEC_BIT)
        protection_flags = PROT_READ | PROT_WRITE | PROT_EXEC;
    else
        protection_flags = PROT_READ | PROT_WRITE;

    // find the appropriate bin
    const int bin_index = jgetbinindex(aligned_size);

    chunk_t* current_chunk = jcachebin[bin_index];
    chunk_t* previous_chunk = NULL;

    // search for a reusable chunk in the current bin
    while (current_chunk != NULL) {
        if (current_chunk->size >= aligned_size && !(current_chunk->flags & CHUNK_INUSE_BIT)) {
            current_chunk->flags |= CHUNK_INUSE_BIT;
            current_chunk->flags = (current_chunk->flags & 0xF0) | (priv & 0x0F); // store priv in lower 4 bits

            void* payload_area = (void*)((char*)current_chunk + sizeof(chunk_t));

            mprotect(payload_area, aligned_size - sizeof(chunk_t), protection_flags);
            return payload_area;
        }

        previous_chunk = current_chunk;
        current_chunk = current_chunk->fd;
    }

    // no reusable chunk found, allocate a new one
    if (previous_chunk != NULL)
        page_start = (void*)((char*)previous_chunk + previous_chunk->size + CHUNK_ALIGNMENT_BYTES);
    else {
        page_start = sbrk(0);

        if (sbrk(aligned_size) == (void*)-1)
            return NULL;
    }

    memset(page_start, 0, aligned_size);

    // initializing a new chunk's headers
    chunk_t* new_chunk = (chunk_t*)page_start;
    new_chunk->size = aligned_size;
    new_chunk->flags = CHUNK_INUSE_BIT | (priv & 0x0F);
    new_chunk->fd = NULL;
    new_chunk->bk = NULL;

    if (previous_chunk != NULL)
        previous_chunk->fd = new_chunk;
    else
        jcachebin[bin_index] = new_chunk;

    void* payload_area = (void*)((char*)new_chunk + sizeof(chunk_t));
    mprotect(payload_area, aligned_size - sizeof(chunk_t), protection_flags);

    return payload_area;
}

// just-free
void jfree(void* ptr) {
    if (!ptr) return;

    chunk_t* chunk = (chunk_t*)((char*)ptr - sizeof(chunk_t));

    if (!(chunk->flags & CHUNK_INUSE_BIT)) return; // sanity check

    chunk->flags &= ~CHUNK_INUSE_BIT;

    jcoalescechunk(chunk);

    return;
}

int main(void) {
    int* heap = jalloc(4, 0x1 | 0x2);
    // jalloc(sizeof(int), PROT_READ_BIT | PROT_WRITE_BIT);

    if (!heap) return 1;

    *heap = 10;

    jfree(heap);
    return 0;
}
