# j-allocator
a very simple and basic heap allocator written in C

# features
- first fit and segregated free list heap allocator (has aspects of both);
- performs linear searches to allocate new chunks or to find existing chunks which have been freed and are ready for use;
- uses bins as the basis of the algorithm;
- chunks have robust identification from the headers.

# note
- same as libc allocator, the responsibility of not exceeding the bounds of the allocated chunk belongs to the programmer/you;
- the stability and integrity of a allocated chunk or the heap in general is not guaranteed;
- the allocator isn't compatible with the libc allocator (__ptmalloc__), and it is not recommended to use both at the same time or to use a libc function that forces it use. But why? jalloc uses sbrk(), we are manipulating specifically the heap and not an isolated section, so it happens that the libc chunks can conflict with the jalloc's chunks. So, for example, you call `printf("%p", addr)` and it write the formatted string at the same offset as a chunk in the heap allocated by jalloc().
