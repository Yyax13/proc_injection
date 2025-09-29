# Proccess Injection in Linux using PTRACE

This repo contains a PoC of proccess injection in Linux using PTRACE (ptrace.h). The shellcode is from [this repo](https://github.com/Yyax13/shellcode) and it's a simple execve shellcode that spawns a /bin/sh shell.

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

A detailed explanation of the code and the techniques used can be found in our paper (not in github yet, stay tuned).