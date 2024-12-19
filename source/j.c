#include "include/headers/j.h"

/* some abbreviations of object's name (to clarify understanding) 

    - priv: privillege/s
    - fd: file descriptor or forward
    - bk: backward

    - _n: name
    - h/_h: header/s
    - j: just (pun on the name of the allocator)

    - JC: jcoalescechunk
    - JF: jfree
    - JI: jinit
    - JA: jalloc
*/

/*
example of the (double) linked algorithm between chunks:

(compiled with: `gcc -g -o main main.c`)

(code)
int main(void) {
    char* chunk1 = jalloc(sizeof(int), PROT_READ_BIT | PROT_WRITE_BIT);
    char* chunk2 = jalloc(sizeof(int), PROT_READ_BIT | PROT_WRITE_BIT);
    char* chunk3 = jalloc(sizeof(int), PROT_READ_BIT | PROT_WRITE_BIT);

    if (!chunk1 || !chunk2 || !chunk3) return 1;

    *chunk1 = 10;
    *chunk2 = 20;
    *chunk3 = 30;

    jfree(chunk1);
    jfree(chunk2);
    jfree(chunk3);
    return 0;
}

(context)
────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────
 ► 0x5555555555c4 <main+125>    call   jfree                       <jfree>
        rdi: 0x555555559028 ◂— 0xa
────────[ SOURCE (CODE) ]─────────────────────────────────────────────────
In file: /.../.../.../.../.../source/main.c:164
   159
   160   *chunk1 = 10;
   161   *chunk2 = 20;
   162   *chunk3 = 30;
   163
 ► 164   jfree(chunk1);
──────────────────────────────────────────────────────────────────────────
pwndbg> p jinfo->jcachebin
$1 = {0x555555559060, 0x0 <repeats 15 times>}
pwndbg> p *(jinfo->jcachebin[0])
$2 = {
  size = 48,
  hsize = 40,
  flags = 3 '\003',
  fd = 0x0,
  bk = 0x555555559030
}
pwndbg> p *(*(jinfo->jcachebin[0]))->bk
$3 = {
  size = 48,
  hsize = 40,
  flags = 3 '\003',
  fd = 0x555555559060,
  bk = 0x555555559000
}
pwndbg> p *((*(*(jinfo->jcachebin[0]))->bk)->bk)
$4 = {
  size = 48,
  hsize = 40,
  flags = 3 '\003',
  fd = 0x555555559030,
  bk = 0x0
}
*/

jinfo_t* jinfo = NULL;

// helper to align chunk size
static size_t jalignsize(const size_t size)
{
    return (size + CHUNK_ALIGNMENT_BYTES - 1) & ~(CHUNK_ALIGNMENT_BYTES - 1);
}

// helper to get jcache index
static int32_t jgetbinindex(const size_t size)
{
    return (size / JCACHE_SIZE_INCREMENT) < JCACHE_CHUNK_AMOUNT ? (size / JCACHE_SIZE_INCREMENT) : (JCACHE_CHUNK_AMOUNT - 1);
}

// helper to coalesce a chunk
static void jcoalescechunk(chunk_t* chunk)
{
    if (!chunk)
    {
        jinfo->jerrorcode = JC_ERROR_INVALID_POINTER;
        return;
    }

    chunk_t* next_chunk = (chunk_t*)((char*)chunk + chunk->size);
    chunk_t* prev_chunk = chunk->bk;

    // coalesce with the next chunk if its free
    if (next_chunk && !(next_chunk->flags & INUSE_BIT))
    {
        chunk->size += next_chunk->size;
        chunk->fd    = next_chunk->fd;

        if (next_chunk->fd)
            next_chunk->fd->bk = chunk;
    }

    // coalesce with the previous chunk if its free
    if (prev_chunk && !(prev_chunk->flags & INUSE_BIT))
    {
        prev_chunk->size += chunk->size;
        prev_chunk->fd = chunk->fd;

        if (chunk->fd)
            chunk->fd->bk = prev_chunk;

        chunk = prev_chunk;
    }

    // update bin ptrs
    const int32_t bin_index = jgetbinindex(chunk->size);

    if (jinfo->jcachebin[bin_index] == chunk->bk)
        jinfo->jcachebin[bin_index] = chunk;

    return;
}

// function to initialize jallocator info structure
static int32_t jinit(void) {
    int32_t temp_ret_code = 0x0;

    const char*  shm_n = "/j";
    const size_t size  = sizeof(jinfo_t);

    // jsection descriptor
    const int32_t sd = shm_open(shm_n, O_CREAT | O_RDWR, 0666);

    if (sd == -1)
    {
        temp_ret_code = JI_ERROR_SHM_OPEN;
        return temp_ret_code;
    }

    if (ftruncate(sd, size) == -1)
    {
        temp_ret_code = JI_ERROR_FTRUNCATE;

        close(sd);
        shm_unlink(shm_n);

        return temp_ret_code;
    }

    jinfo = (jinfo_t*)mmap(
        NULL,
        size,
        PROT_READ | PROT_WRITE,
        MAP_SHARED,
        sd,
        0
    );

    if (jinfo == MAP_FAILED)
    {
        temp_ret_code = JI_ERROR_MMAP;

        close(sd);
        shm_unlink(shm_n);

        return temp_ret_code;
    }

    close(sd);

    jinfo->jerrorcode  = 0;
    jinfo->initialized = 1;

    for (int i = 0; i < JCACHE_CHUNK_AMOUNT; ++i)
    {
        jinfo->jcachebin[i] = NULL;
    }

    return temp_ret_code;
}

// jalloc main implementation
void* jalloc(const size_t size, const byte_t priv)
{
    // jinfo sanity check
    if (!jinfo)
        if (jinit() != 0x0)
        {
            puts("abort: jinit");
            return NULL;
        }

    int32_t protection_flags;

    const size_t aligned_size = jalignsize(size + sizeof(chunk_t));
    const size_t page_size    = sysconf(_SC_PAGESIZE);

    void* chunk; // page start?

    // validate the priv bits
    if ((priv & 0x7) != priv)
    {
        jinfo->jerrorcode = JA_ERROR_VALIDATE_PRIV;
        return NULL;
    }

    // set the memory protection flags
    if (priv & PROT_EXEC_BIT)
        protection_flags = PROT_READ | PROT_WRITE | PROT_EXEC;
    else
        protection_flags = PROT_READ | PROT_WRITE;

    // find the appropriate bin
    const int32_t bin_index = jgetbinindex(aligned_size);

    chunk_t* current_chunk  = jinfo->jcachebin[bin_index];
    chunk_t* previous_chunk = NULL;

    // search for a reusable chunk in the current bin
    while (current_chunk != NULL)
    {
        if (current_chunk->size >= aligned_size && !(current_chunk->flags & INUSE_BIT))
        {
            const size_t remaining_size = current_chunk->size - aligned_size;

            // found chunk can be used only if the new chunk size be smaller than the current size (if exists a chunk in the fd)
            if (remaining_size >= sizeof(chunk_t) + CHUNK_ALIGNMENT_BYTES)
            {
                // split the chunk if there's enough space for a new chunk
                chunk_t* new_chunk = (chunk_t*)((char*)current_chunk + aligned_size);
                new_chunk->size  = remaining_size; // changing chunk size with the new size
                new_chunk->flags = current_chunk->flags & ~INUSE_BIT; // clear INUSE_BIT for a new chunk
                new_chunk->fd    = current_chunk->fd;
                new_chunk->bk    = current_chunk;

                if (current_chunk->fd)
                    current_chunk->fd->bk = new_chunk;

                // if no forward chunk
                current_chunk->size = aligned_size;
                current_chunk->fd   = new_chunk;
            }

            current_chunk->flags |= INUSE_BIT;
            current_chunk->flags  = (current_chunk->flags & 0xF0) | (priv & 0x0F); // store priv in lower 4 bits of current_chunk->flags byte

            void* payload_area = (void*)((char*)current_chunk + sizeof(chunk_t));

            // setting permissions with basis on the requested privilleges
            if (
                mprotect(
                    (void*)((uintptr_t)payload_area & ~(page_size - 1)),
                    aligned_size,
                    protection_flags
            ) == -1)
            {
                jinfo->jerrorcode = JA_ERROR_PERMISSION_SET;
                return NULL;
            }

            return payload_area;
            // the payload area is the area which is read for use by the user
        }

        previous_chunk = current_chunk;
        current_chunk = current_chunk->fd;
    }

    // no reusable chunk found, then allocate a new one
    chunk = sbrk(0);

    if (sbrk(aligned_size) == (void*)-1)
    {
        jinfo->jerrorcode = JA_ERROR_HEAP_ADJUST;
        return NULL;
    }

    // only fill chunk space with zeros if its size is smaller than page size (4096 normally)
    if (aligned_size < page_size)
        memset(chunk, 0, aligned_size);

    // initializing a new chunk's headers
    chunk_t* new_chunk = (chunk_t*)chunk;
    new_chunk->size    = aligned_size;
    new_chunk->hsize   = sizeof(chunk_t);
    new_chunk->flags   = INUSE_BIT | (priv & 0x0F);
    new_chunk->fd      = NULL;
    new_chunk->bk      = previous_chunk;

    if (previous_chunk != NULL)
        previous_chunk->fd = new_chunk;
    else
        jinfo->jcachebin[bin_index] = new_chunk;

    void* payload_area = (void*)((char*)new_chunk + sizeof(chunk_t));

    // setting permissions with basis on the requested privilleges
    if (
        mprotect(
            (void*)((uintptr_t)payload_area & ~(page_size - 1)),
            aligned_size,
            protection_flags
        ) == -1)
    {
        jinfo->jerrorcode = JA_ERROR_PERMISSION_SET;
        return NULL;
    }

    jcoalescechunk(new_chunk);

    return payload_area;
    // the payload area is the area which is read for use by the user
}

// a part of jalloc implementation, is a function to free the allocated chunk
void jfree(void* _Ptr)
{
    // _Ptr is the pointer to the allocated chunk which will be free

    // jinfo structure sanity checks
    if (!jinfo)
        if (jinit() != 0x0)
        {
            puts("abort: jinit");
            return;
        }

    if (!_Ptr)
    {
        jinfo->jerrorcode = JF_ERROR_INVALID_POINTER;
        return;
    }

    chunk_t* chunk = (chunk_t*)((char*)_Ptr - sizeof(chunk_t));

    if (!(chunk->flags & INUSE_BIT))
    {
        // chunk is not in use
        for (int i = 0; i < JCACHE_CHUNK_AMOUNT; i++)
        {
            if ((chunk_t*)jinfo->jcachebin[i] == chunk)
            {
                // chunk already is in jcache
                jinfo->jerrorcode = JF_ERROR_DOUBLE_FREE;
                return;
            }
        }
    }

    chunk->flags &= ~INUSE_BIT; // clears INUSE bit

    jcoalescechunk(chunk); // coalesce with forward, backward and existing chunks

    if (jinfo->jerrorcode == JC_ERROR_INVALID_POINTER) return;

    // after coalescing, updates the jcache
    const int32_t bin_index = jgetbinindex(chunk->size);

    if (!chunk->bk || jinfo->jcachebin[bin_index] == chunk->bk)
        jinfo->jcachebin[bin_index] = chunk;

    return;
}
