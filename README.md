# Process Injection in Linux using PTRACE

This repo contains a PoC of process injection in Linux using PTRACE (ptrace.h). The shellcode is from [this repo](https://github.com/Yyax13/shellcode) and it's a simple execve shellcode that spawns a /bin/sh shell.

## Usage

To compile the code, run:

```bash
make build
```

We also provide a dummy target binary to test the injection. You can compile it with:

```bash
make dummy
```

To run the injection, use:

```bash
sudo ./proc_inj <pid>
```

## Paper

You can read the full paper about this project in [paper.md](paper.md).