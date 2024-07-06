# j-allocator
__(just-allocate)__
a very simple and basic linux heap allocator written in C

# features and aspects
- first fit and segregated free list heap allocator (has aspects of both);
- performs linear searches to allocate new chunks or to find existing chunks;
- chunks have robust identification from the headers;
- uses bins as the basis of the algorithm;
- the linear search through bins could be slow for large bins;
- not a thread-safe allocator, in other words, it is theoretically incompatible to use the allocator in more than one thread of the process, as data may be overwritten, the same chunk allocated to more than one thread, etc;
- not as efficient in sanity checks and bin traversal due to using a big computational effort in very large allocations;
- memory overhead can occur in very small allocations (around 1 to 64 bytes) due to the size of the chunk headers, which is a bit exaggerated (around 40 bytes at 64 bits arch);

# note
- same as g/libc allocator, the responsibility of not exceeding the bounds of the allocated chunk belongs to the programmer/you;
- the stability and integrity of a allocated chunk or the heap in general is not guaranteed;
- the allocator isn't compatible with the glibc allocator (__ptmalloc__), and it is not recommended to use both at the same time or to use a libc function that forces it use. But why? jalloc uses sbrk(), we are manipulating specifically the heap and not an isolated section, so it happens that the glibc chunks can conflict with the jalloc chunks (for example, you call `printf("%p", addr)` and it write the formatted string at the same offset as a chunk in the heap allocated by the jalloc).
