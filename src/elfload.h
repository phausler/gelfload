#ifndef ELFLOAD_H
#define ELFLOAD_H

#include <sys/types.h>

#include "elfnative.h"

#define HOSTLIB_NOT  0
#define HOSTLIB_HOST 1
#define HOSTLIB_DL   2

/* Basic structure for ELF files mid-load */
struct ELF_File {
    char *nm;

    /* if this is actually a host library, this is set to 1 */
    char hostlib;

    /* the complete program, in memory */
    uint8_t *prog;
    size_t proglen;

    /* same pointer, actually */
    Elf32_Ehdr *ehdr32;
    Elf64_Ehdr *ehdr64;

    /* the size in memory of this file */
    ssize_t memsz;

    /* the minimum and maximum position of the loaded file, ideally */
    void *min, *max;

    /* the actual location where this file was loaded */
    void *loc;

    /* the offset of this file's real loaded location from its internal location */
    ssize_t offset;

    /* the dynamic entries table */
    Elf32_Dyn *dynamic32;
    Elf64_Dyn *dynamic64;

    /* the string table */
    char *strtab;

    /* and symbol table */
    Elf32_Sym *symtab32;
    Elf64_Sym *symtab64;

    /* with its associated hash table */
    Elf32_Word *hashtab32;
    Elf64_Word *hashtab64;
#define ELFFILE_NBUCKET32(f) ((f)->hashtab32[0])
#define ELFFILE_NBUCKET64(f) ((f)->hashtab64[0])
#define ELFFILE_NCHAIN32(f) ((f)->hashtab32[1])
#define ELFFILE_NCHAIN64(f) ((f)->hashtab64[1])
#define ELFFILE_BUCKET32(f, i) ((f)->hashtab32[(i) + 2])
#define ELFFILE_BUCKET64(f, i) ((f)->hashtab64[(i) + 2])
#define ELFFILE_CHAIN32(f, i) ((f)->hashtab32[(i) + ELFFILE_NBUCKET32(f) + 2])
#define ELFFILE_CHAIN64(f, i) ((f)->hashtab64[(i) + ELFFILE_NBUCKET64(f) + 2])

    /* relocation table(s) */
    Elf32_Rel *rel32;
    Elf64_Rel *rel64;
    size_t relsz;
    Elf32_Rela *rela32;
    Elf64_Rela *rela64;
    size_t relasz;
    void *jmprel;
    size_t jmprelsz;
};

struct ELF_File *loadELF(const char *nm, const char *instdir, int maybe);
void relocateELFs();
void relocateELF(int fileNo, struct ELF_File *f);
void initELF(struct ELF_File *except);
void readFile(const char *nm, const char *instdir, struct ELF_File *ef);
void closeFile(struct ELF_File *ef);
void *findELFSymbol(const char *nm, struct ELF_File *onlyin, int localin, int notin);
void *findELFSymbol32(const char *nm, struct ELF_File *onlyin, int localin, int notin,
                    Elf32_Sym **syminto);
void *findELFSymbol64(const char *nm, struct ELF_File *onlyin, int localin, int notin,
                    Elf64_Sym **syminto);
Elf32_Word elf_hash32(const unsigned char *name);
Elf64_Word elf_hash64(const unsigned char *name);

#endif
