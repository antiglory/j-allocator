# j-allocator
__just-allocate(or)__
a very simple and basic linux heap allocator written in C

# features and aspects
- first fit and segregated free list allocator (has aspects of both);
- performs linear searches to allocate new chunks or to find existing chunks;
- chunks have robust identification from the headers;
- uses bins as the basis of the algorithm;
- has a reasonable flexibility in terms of the privileges of the allocated chunks, each chunk has its own privileges, which can be useful in contexts where several chunks with different purposes are allocated in the same region;
- the linear search through bins could be slow for large bins;
- not a thread-safe allocator, in other words, it is theoretically incompatible to use the allocator in more than one thread of the process, as data may be overwritten, the same chunk can be allocated to more than one thread, etc;
- not as efficient in sanity checks and bin traversal due to using a big computational effort in very large allocations;
- memory overhead can occur in very small allocations (around 1 to 64 bytes) due to the size of the chunk headers, which is a bit exaggerated (around 40 bytes in 64 bits);

# note
- same as (g)libc allocator, the responsibility of not exceeding the bounds of the allocated chunk belongs to the programmer/you;
- the stability and integrity of a allocated chunk or the heap in general is not guaranteed;
- the allocator isn't compatible with the (g)libc allocator (__ptmalloc__), and it is not recommended to use both at the same time or to use a (g)libc function that forces it use. But why? jalloc uses sbrk(), we are manipulating specifically the heap and not an second-mapped or isolated section, so it happens that the (g)libc chunks can conflict with the jalloc chunks because each one does not have information about the allocations made by. (for example, you call `printf("%d\n", value)` and it write the formatted string at the same offset/region as a chunk in the heap allocated by the jalloc)
