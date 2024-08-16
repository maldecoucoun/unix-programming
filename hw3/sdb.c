#include <elf.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <capstone/capstone.h>
#include <stdlib.h>
#include <stdbool.h>

#define INT3 0xcc
#define MAX_BREAKPOINTS 100

typedef struct {
    uint64_t address;
    long original_data;
    int active;
} breakpoint_t;

breakpoint_t breakpoints[MAX_BREAKPOINTS];
int breakpoint_count = 0;
int breakpoint_index = 0;

static Elf64_Shdr get_section_hdr64(FILE *file_ptr, Elf64_Ehdr elf_hdr, Elf64_Off n) {
    Elf64_Shdr section_hdr;
    fseeko(file_ptr, elf_hdr.e_shoff + n * elf_hdr.e_shentsize, SEEK_SET);
    fread(&section_hdr, sizeof(section_hdr), 1, file_ptr);
    return section_hdr;
}

static void get_text_section(const char *path, uint8_t **textptr, uint64_t *n, uint64_t *sh_addr) {
    FILE *file_ptr = fopen(path, "rb");

    unsigned char e_ident[EI_NIDENT];
    fread(e_ident, 1, EI_NIDENT, file_ptr);
    if (strncmp((char *) e_ident, "\x7f""ELF", 4) != 0) {
        printf("ELFMAGIC mismatch!\n");
        fclose(file_ptr);
        return;
    }

    if (e_ident[EI_CLASS] == ELFCLASS64) {
        Elf64_Ehdr elf_hdr;
        memcpy(elf_hdr.e_ident, e_ident, EI_NIDENT);
        fread((void *) &elf_hdr + EI_NIDENT, sizeof(elf_hdr) - EI_NIDENT, 1, file_ptr);

        Elf64_Off shstrndx;
        if (elf_hdr.e_shstrndx == SHN_XINDEX) {
            shstrndx = get_section_hdr64(file_ptr, elf_hdr, 0).sh_link;
        } else {
            shstrndx = elf_hdr.e_shstrndx;
        }

        Elf64_Shdr section_hdr_string_tbl_hdr = get_section_hdr64(file_ptr, elf_hdr, shstrndx);
        char *const section_hdr_string_tbl = malloc(section_hdr_string_tbl_hdr.sh_size);
        fseeko(file_ptr, section_hdr_string_tbl_hdr.sh_offset, SEEK_SET);
        fread(section_hdr_string_tbl, 1, section_hdr_string_tbl_hdr.sh_size, file_ptr);

        Elf64_Off shnum;
        if (elf_hdr.e_shnum == SHN_UNDEF) {
            shnum = get_section_hdr64(file_ptr, elf_hdr, 0).sh_size;
        } else {
            shnum = elf_hdr.e_shnum;
        }

        for (Elf64_Off i = 0; i < shnum; i++) {
            Elf64_Shdr section_hdr = get_section_hdr64(file_ptr, elf_hdr, i);
            // we are only interested in .text section
            if (strcmp(".text", section_hdr_string_tbl + section_hdr.sh_name) == 0) {
                *textptr = malloc(section_hdr.sh_size);
                fseeko(file_ptr, section_hdr.sh_offset, SEEK_SET);
                fread(*textptr, 1, section_hdr.sh_size, file_ptr);
                *n = section_hdr.sh_size;
                *sh_addr = section_hdr.sh_addr;
                break;
            }
        }
        free(section_hdr_string_tbl);
    }
    fclose(file_ptr);
}

static void disassemble(csh handle, const uint8_t *code, size_t code_size, uint64_t address) {
    cs_insn *insn;
    size_t count = cs_disasm(handle, code, code_size, address, 0, &insn);
    for (size_t i = 0; i < count && i < 5; i++) {
        char bytes[128] = "";
        for (int j = 0; j < insn[i].size; j++) {
            snprintf(&bytes[j * 3], 4, "%2.2x ", insn[i].bytes[j]);
        }
        printf("\t%"PRIx64": %-32s%s\t%s\n", insn[i].address, bytes, insn[i].mnemonic, insn[i].op_str);
    }
    cs_free(insn, count);
    if (count == 0) {
        printf("** the address is out of the range of the text section.\n");
    }
}

static bool isCmd(char *line) {
    if (strcmp(line, "si\n") == 0) {
        return true;
    }
    if (strcmp(line, "cont\n") == 0) {
        return true;
    }
    if (strcmp(line, "info reg\n") == 0) {
        return true;
    }
    if (strcmp(line, "info break\n") == 0) {
        return true;
    }
    if (strstr(line, "delete ") == line) {
        return true;
    }
    if (strstr(line, "patch ") == line) {
        return true;
    }
    if (strcmp(line, "syscall\n") == 0) {
        return true;
    }
    return false;
}

static void print_registers(struct user_regs_struct regs) {
    printf("$rax 0x%016llx    $rbx 0x%016llx    $rcx 0x%016llx\n", regs.rax, regs.rbx, regs.rcx);
    printf("$rdx 0x%016llx    $rsi 0x%016llx    $rdi 0x%016llx\n", regs.rdx, regs.rsi, regs.rdi);
    printf("$rbp 0x%016llx    $rsp 0x%016llx    $r8  0x%016llx\n", regs.rbp, regs.rsp, regs.r8);
    printf("$r9  0x%016llx    $r10 0x%016llx    $r11 0x%016llx\n", regs.r9, regs.r10, regs.r11);
    printf("$r12 0x%016llx    $r13 0x%016llx    $r14 0x%016llx\n", regs.r12, regs.r13, regs.r14);
    printf("$r15 0x%016llx    $rip 0x%016llx    $eflags 0x%016llx\n", regs.r15, regs.rip, regs.eflags);
}

static void add_breakpoint(pid_t child, uint64_t addr) {
    if (breakpoint_count >= MAX_BREAKPOINTS) {
        printf("** maximum number of breakpoints reached.\n");
        return;
    }

    long data = ptrace(PTRACE_PEEKTEXT, child, addr, 0);
    breakpoints[breakpoint_index].address = addr;
    breakpoints[breakpoint_index].original_data = data;
    breakpoints[breakpoint_index].active = 1;
    ((uint8_t *)&data)[0] = INT3;
    ptrace(PTRACE_POKETEXT, child, addr, data);
    printf("** set a breakpoint at %p.\n", (void *)addr);

    breakpoint_count++;
    breakpoint_index++;
}

static void remove_breakpoint(pid_t child, int id) {
    if (id < 0 || id >= breakpoint_index || !breakpoints[id].active) {
        printf("** breakpoint %d does not exist.\n", id);
        return;
    }

    ptrace(PTRACE_POKETEXT, child, breakpoints[id].address, breakpoints[id].original_data);
    printf("** delete breakpoint %d.\n", id);

    breakpoints[id].active = 0;
    breakpoint_count--;
}

static void list_breakpoints() {
    if (breakpoint_count == 0) {
        printf("** no breakpoints.\n");
        return;
    }
    printf("Num     Address\n");
    for (int i = 0; i < breakpoint_index; i++) {
        if (breakpoints[i].active) {
            printf("%d       0x%lx\n", i, breakpoints[i].address);
        }
    }
}

static void patch_memory(pid_t child, uint64_t addr, uint64_t value, int len) {
    // int breakpoint_id = -1;
    // for (int i = 0; i < breakpoint_index; i++) {
    //     if (breakpoints[i].active && breakpoints[i].address == addr) {
    //         breakpoint_id = i;
    //         break;
    //     }
    // }

    // long data = ptrace(PTRACE_PEEKTEXT, child, addr, 0);
    // memcpy((void *)&data, &value, len);
    // ptrace(PTRACE_POKETEXT, child, addr, data);
    // printf("** patch memory at address 0x%lx.\n", addr);

    // if (breakpoint_id != -1) {
    //     breakpoints[breakpoint_id].original_data = ptrace(PTRACE_PEEKTEXT, child, addr, 0);
    //     ((uint8_t *)&data)[0] = INT3;
    //     ptrace(PTRACE_POKETEXT, child, addr, data);
    // }
    uint64_t mask = (1ULL << (len * 8)) -1;
    long data = ptrace(PTRACE_PEEKDATA, child, addr, NULL);
    value = (data & ~mask) | value;
    ptrace(PTRACE_PEEKDATA, child, addr, value);
    printf("** patch memory at address 0x%lx.\n", addr);
}

static void handle_syscall(pid_t child, int *in_syscall) {
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child, 0, &regs);
    if (*in_syscall) {
        printf("** leave a syscall(%llu) = %lld at %p.\n", regs.orig_rax, regs.rax, (void *)regs.rip);
        *in_syscall = 0;
    } else {
        printf("** enter a syscall(%llu) at %p.\n", regs.orig_rax, (void *)regs.rip);
        *in_syscall = 1;
    }
}

int main(int argc, char *argv[]) {
    char *line = NULL;
    size_t line_size = 0;
    bool is_loaded = false;
    int in_syscall = 0;

    if (argc < 2) {
        printf("(sdb) ");
        getline(&line, &line_size, stdin);
        while (!is_loaded) {
            if (strstr(line, "load ")) {
                char path[256];
                sscanf(line, "load %s", path);
                argv[1] = strdup(path);
                is_loaded = true;
            } else {
                printf("** please load a program first.\n(sdb) ");
                getline(&line, &line_size, stdin);
            }
        }
    }

    pid_t child = fork();
    if (child == 0) { // tracee
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        execvp(argv[1], argv + 1);
        perror("execvp");
        return -1;
    }

    // tracer
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        return -1;
    }

    int child_status;

    waitpid(child, &child_status, 0);
    if (WIFEXITED(child_status)) {
        return -1;
    }

    uint8_t *text = NULL;
    uint64_t text_size = 0;
    uint64_t offset = 0;
    get_text_section(argv[1], &text, &text_size, &offset);

    struct user_regs_struct regs;
    uint64_t restore_brk_addr = 0;

    ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACEFORK | PTRACE_O_TRACESYSGOOD);
    ptrace(PTRACE_GETREGS, child, 0, &regs);
    printf("** program '%s' loaded. entry point %p.\n", argv[1], (void *) regs.rip);
    disassemble(handle, &text[regs.rip - offset], text_size - (regs.rip - offset), regs.rip);

    do {
        printf("(sdb) ");
        getline(&line, &line_size, stdin);

        if (strstr(line, "break ")) {
            uint64_t brk_addr;
            sscanf(line, "break %lx", &brk_addr);
            add_breakpoint(child, brk_addr);
            continue;
        } else if (strcmp(line, "info reg\n") == 0) {
            ptrace(PTRACE_GETREGS, child, 0, &regs);
            print_registers(regs);
            continue;
        } else if (strcmp(line, "info break\n") == 0) {
            list_breakpoints();
            continue;
        } else if (strstr(line, "delete ") == line) {
            int id;
            sscanf(line, "delete %d", &id);
            remove_breakpoint(child, id);
            continue;
        } else if (strstr(line, "patch ") == line) {
            uint64_t addr, value;
            int len;
            sscanf(line, "patch %lx %lx %d", &addr, &value, &len);
            patch_memory(child, addr, value, len);
            continue;
        } else if (!isCmd(line)) {
            continue;
        }

        if (strcmp(line, "si\n") == 0) {
            ptrace(PTRACE_SINGLESTEP, child, 0, 0);
            waitpid(child, &child_status, 0);
        }

        if (strcmp(line, "cont\n") == 0) {
            ptrace(PTRACE_CONT, child, 0, 0);
            waitpid(child, &child_status, 0);
        }

        if (strcmp(line, "syscall\n") == 0) {
            ptrace(PTRACE_SYSCALL, child, 0, 0);
            waitpid(child, &child_status, 0);
            handle_syscall(child, &in_syscall);
            // continue;
        }

        if (restore_brk_addr) {
            long brk = ptrace(PTRACE_PEEKTEXT, child, restore_brk_addr, 0);
            ((uint8_t *) &brk)[0] = INT3;
            ptrace(PTRACE_POKETEXT, child, restore_brk_addr, brk);
        }

        if (WIFSTOPPED(child_status)) {
            ptrace(PTRACE_GETREGS, child, 0, &regs);

            long peek = ptrace(PTRACE_PEEKTEXT, child, regs.rip - 1, 0);

            if (((uint8_t *) &peek)[0] == INT3 && regs.rip - 1 != restore_brk_addr) {
                regs.rip = regs.rip - 1;
                printf("** hit a breakpoint at %p.\n", (void *) regs.rip);
                restore_brk_addr = regs.rip;
                ((uint8_t *) &peek)[0] = text[regs.rip - offset];
                ptrace(PTRACE_POKETEXT, child, regs.rip, peek);
                ptrace(PTRACE_SETREGS, child, 0, &regs);
            } else if (((uint8_t *) &peek)[1] == INT3) {
                printf("** hit a breakpoint at %p.\n", (void *) regs.rip);
                restore_brk_addr = regs.rip;
                ((uint8_t *) &peek)[1] = text[regs.rip - offset];
                ptrace(PTRACE_POKETEXT, child, regs.rip - 1, peek);
            } else {
                restore_brk_addr = 0;
            }

            disassemble(handle, &text[regs.rip - offset], text_size - (regs.rip - offset), regs.rip);
        }

    } while (!WIFEXITED(child_status));
    printf("** the target program terminated.\n");

    /* Do some cleanup and kill the anchor. */
    free(line);
    free(text);
    cs_close(&handle);
    return 0;
}
