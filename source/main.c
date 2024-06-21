#include "include/main.h"
// TODO: quando uma chunk for encontrada e for utilizada, atualizar o tamanho dela (talvez o tamanho dos headers também) com o novo tamanho dela a partir do que foi pedido nos argumentos (_Size)

/*
example of the (double) linked algorithm between chunks:

pwndbg> p jcachebin
$1 = {0x555555559000, 0x0 <repeats 15 times>}
pwndbg> p *jcachebin[0]
$2 = {
  size = 40,
  flags = 3 '\003',
  fd = 0x555555559028,
  bk = 0x0
}
pwndbg> p *((*jcachebin[0])->fd)
$3 = {
  size = 40,
  flags = 3 '\003',
  fd = 0x555555559050,
  bk = 0x555555559000
}
pwndbg> p *(*jcachebin[0]->fd)->fd
$4 = {
  size = 40,
  flags = 3 '\003',
  fd = 0x0,
  bk = 0x555555559028
}
*/

// initializing jalloc main bin
chunk_t* jcachebin[JCACHE_CHUNK_AMOUNT] = {NULL};

// just-align-size
static size_t jalignsize(const size_t size) {
    return (size + CHUNK_ALIGNMENT_BYTES - 1) & ~(CHUNK_ALIGNMENT_BYTES - 1);
}

// just-get-bin-index
static int jgetbinindex(const size_t size) {
    return (size / JCACHE_SIZE_INCREMENT) < JCACHE_CHUNK_AMOUNT ? (size / JCACHE_SIZE_INCREMENT) : (JCACHE_CHUNK_AMOUNT - 1);
}

// helper to coalesce adjacent free chunks
static void jcoalescechunk(chunk_t* chunk) {
    const chunk_t* next_chunk = (chunk_t*)((char*)chunk + chunk->size);

    if (!(next_chunk->flags & INUSE_BIT)) {
        chunk->size += next_chunk->size;
        chunk->fd = next_chunk->fd;

        if (next_chunk->fd)
            next_chunk->fd->bk = chunk;
    }
}

void* jalloc(const size_t size, const byte_t priv) {
    int protection_flags;
    const size_t aligned_size = jalignsize(size + sizeof(chunk_t));

    void* chunk; // page start

    // validate the priv bits
    if ((priv & 0x7) != priv)
        return NULL;

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
        if (current_chunk->size >= aligned_size && !(current_chunk->flags & INUSE_BIT)) {
            current_chunk->flags |= INUSE_BIT;
            current_chunk->flags = (current_chunk->flags & 0xF0) | (priv & 0x0F); // store priv in lower 4 bits of current_chunk->flags byte

            void* payload_area = (void*)((char*)current_chunk + sizeof(chunk_t));

            mprotect(payload_area, aligned_size - sizeof(chunk_t), protection_flags);

            return payload_area;
        }

        previous_chunk = current_chunk;
        current_chunk = current_chunk->fd;
    }

    // no reusable chunk found, allocate a new one
    chunk = sbrk(0);

    if (sbrk(aligned_size) == (void*)-1)
        return NULL;

    memset(chunk, 0, aligned_size);

    // initializing a new chunk's headers
    chunk_t* new_chunk = (chunk_t*)chunk;
    new_chunk->size = aligned_size;
    new_chunk->hsize = sizeof(chunk_t);
    new_chunk->flags = INUSE_BIT | (priv & 0x0F);
    new_chunk->fd = NULL;
    new_chunk->bk = previous_chunk;

    if (previous_chunk != NULL)
        previous_chunk->fd = new_chunk;
    else
        jcachebin[bin_index] = new_chunk;

    void* payload_area = (void*)((char*)new_chunk + sizeof(chunk_t));

    mprotect(payload_area, aligned_size - sizeof(chunk_t), protection_flags);

    jcoalescechunk(new_chunk);

    return payload_area;
    // the payload area is the area ready for use by the user
}

// just-free
void jfree(void* ptr) {
    if (!ptr) return;

    chunk_t* chunk = (chunk_t*)((char*)ptr - sizeof(chunk_t));

    if (!(chunk->flags & INUSE_BIT)) return; // sanity check

    chunk->flags &= ~INUSE_BIT;

    if (chunk->fd)
        chunk->fd->bk = chunk->bk;

    if (chunk->bk)
        chunk->bk->fd = chunk->fd;
    else {
        const int bin_index = jgetbinindex(chunk->size);
        jcachebin[bin_index] = chunk->fd;
    }

    jcoalescechunk(chunk);

    return;
}

int main(void) {
    const char string[] = "goodbye world\0";

    char* heap = jalloc(sizeof(string), PROT_READ_BIT | PROT_WRITE_BIT);
    if (!heap) return 1;

    strcpy(heap, string);

    printf("%s\n", heap);

    jfree(heap);
    return 0;
}
