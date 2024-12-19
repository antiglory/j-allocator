// example of j-allocator usage
#include "source/j.c"

int main(void) {
    // (code)
    const char c[] = {
        0x90, 0x90,                    // nop^2
        0xb8, 0x69, 0x00, 0x00, 0x00,  // mov $0x69, %eax
        0xc3                           // ret
    };

    int* chunk = jalloc(sizeof(c), PROT_READ_BIT | PROT_WRITE_BIT | PROT_EXEC_BIT);
    if (!chunk)
    {
        if (!jinfo)
        {
            puts("abort: jalloc");
            return 1;
        } 
        else
        {
            printf("%d\n", jinfo->jerrorcode);
            return 1;
        }
    }

    memcpy(chunk, c, sizeof(c));

    int v = ((int(*)())chunk)();
    if (!v) return 1;

    printf("returned '0x%x'\n", v);

    jfree(chunk);
    return 0;
}
