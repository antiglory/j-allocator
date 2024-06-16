#include "include/header.h"

chunk_t* cachebin[NUM_BINS] = {NULL};

// just-align-size
static size_t jalignsize(size_t size) {
    if (size % CHUNK_ALIGNMENT != 0) {
        size += CHUNK_ALIGNMENT - (size % CHUNK_ALIGNMENT);
    }
    return size;
}

// just-get-bin-index
int jgetbinindex(const size_t size) {
    return (size / BIN_SIZE_INCREMENT) < NUM_BINS ? (size / BIN_SIZE_INCREMENT) : (NUM_BINS - 1);
}

// just-allocate
void* jalloc(const size_t _Size, const byte_t _Priv) {
    int prot, flags;
    void* page_start;

    if ((_Priv & 0x7)!= _Priv) {
        return NULL;
    }

    if (_Priv & PROT_EXEC_BIT) {
        prot = PROT_READ | PROT_WRITE | PROT_EXEC;
    } else {
        prot = PROT_READ | PROT_WRITE;
    }

    flags = MAP_PRIVATE | MAP_ANONYMOUS;

    const size_t f_Size = jalignsize(_Size + sizeof(chunk_t));

    // find the appropriate bin
    const int binindex = jgetbinindex(f_Size);
    chunk_t* current = cachebin[binindex];
    chunk_t* prev = NULL;

    // search for a reusable chunk in the current bin
    while (current!= NULL) {
        if (current->size >= f_Size && current->CHUNK_INUSE == FALSE) {
            current->CHUNK_INUSE = TRUE;
            current->priv = _Priv;
            void* payload_area = (void*)((char*)current + sizeof(chunk_t));
            mprotect(payload_area, f_Size - sizeof(chunk_t), prot);
            return payload_area;
        }
        prev = current;
        current = current->fd;
    }

    // no reusable chunk found then allocate one
    chunk_t* lastchunk = NULL;
    if (prev!= NULL) {
        lastchunk = prev;
        page_start = (void*)((char*)lastchunk + lastchunk->size + CHUNK_ALIGNMENT);
    } else {
        page_start = sbrk(0);
        if (sbrk(f_Size) == (void*)-1) {
            return NULL;
        }
    }

    memset(page_start, 0, f_Size);

    chunk_t new_chunk;
    new_chunk.size = f_Size;
    new_chunk.priv = _Priv;
    new_chunk.fd = NULL;
    new_chunk.CHUNK_INUSE = TRUE;
    new_chunk.IS_MMAPED = FALSE;
    new_chunk.PREV_INUSE = FALSE;
    new_chunk.NON_MAIN_ARENA = FALSE;

    memcpy(page_start, &new_chunk, sizeof(chunk_t));

    if (prev!= NULL) {
        prev->fd = page_start;
    } else {
        cachebin[binindex] = page_start;
    }

    void* payload_area = (void*)((char*)page_start + sizeof(chunk_t));
    mprotect(payload_area, f_Size - sizeof(chunk_t), prot);

    return payload_area;
}

// just-free
void jfree(void* ptr) {
    if (ptr == NULL) return;

    chunk_t* chunk = (chunk_t*)((char*)ptr - sizeof(chunk_t));
    chunk->CHUNK_INUSE = FALSE;
}

int main(void) {
    int* heap = jalloc(4, 0x1 | 0x2);
    *heap = 10;

    printf("[%p]  : %d\n", heap, *heap);

    jfree(heap);
    return 0;
}

// meu codigo nao foi feito pra ser legivel/compreendivel
