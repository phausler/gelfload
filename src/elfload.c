#ifndef _GNU_SOURCE /* for RTLD_DEFAULT */
#define _GNU_SOURCE 1
#endif

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "bbuffer.h"

#include "config.h"

#ifdef HAVE_MMAP
#include <sys/mman.h>
#endif

#ifdef HAVE_DLFCN_H
#include <dlfcn.h>
#endif

#ifdef __WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

#include "elfload.h"
#include "elfload_dlfcn.h"

/* An array of files currently in the process of loading */
#define MAX_ELF_FILES 255
struct ELF_File elfFiles[MAX_ELF_FILES];
int elfFileCount = 0;

/* The function to actually load ELF files into memory */
struct ELF_File *loadELF(const char *nm, const char *instdir, int maybe)
{
    int i, fileNo, phdri;
    struct ELF_File *f;
    void *curphdrl;
    Elf32_Phdr *curphdr32;
    Elf64_Phdr *curphdr64;
    Elf32_Dyn *curdyn32;
    Elf64_Dyn *curdyn64;

    /* first, make sure it's not already loaded or loading */
    for (i = 0; i < elfFileCount; i++) {
        if (strcmp(elfFiles[i].nm, nm) == 0) return &(elfFiles[i]);
    }

    /* now start preparing to load it */
    fileNo = elfFileCount;
    f = &(elfFiles[fileNo]);
    memset(f, 0, sizeof(struct ELF_File));
    elfFileCount++;
    f->nm = strdup(nm);

    /* if this is a host library, circumvent all the ELF stuff and go straight for the host */
    if (strncmp(nm, "libhost_", 8) == 0) {
        f->hostlib = HOSTLIB_HOST;
#if defined(HAVE_DLFCN_H)
        if (strcmp(nm, "libhost_.so") == 0) {
            /* the entire host */
#ifdef RTLD_DEFAULT
            f->prog = RTLD_DEFAULT;
#else
            f->prog = dlopen(NULL, RTLD_NOW|RTLD_GLOBAL);
#endif
        } else {
            f->prog = dlopen(nm + 8, RTLD_NOW|RTLD_GLOBAL);

            if (f->prog == NULL) {
                /* try with an explicit path */
                char *fullpath;
                fullpath = malloc(strlen(elfload_dlinstdir) + strlen(nm) + 1);
                if (fullpath == NULL) {
                    perror("malloc");
                    exit(1);
                }
                sprintf(fullpath, "%s/../lib/%s", elfload_dlinstdir, nm + 8);
                f->prog = dlopen(fullpath, RTLD_NOW|RTLD_GLOBAL);
                free(fullpath);
            }

            if (f->prog == NULL) {
                fprintf(stderr, "Could not resolve host library %s: %s.\n", nm + 8, dlerror());
                exit(1);
            }
        }
#elif defined(__WIN32)
        if (strcmp(nm, "libhost_.so") == 0) {
            f->prog = LoadLibrary("msvcrt.dll");
        } else {
            f->prog = LoadLibrary(nm + 8);
        }
        if (f->prog == NULL) {
            fprintf(stderr, "Could not resolve host library %s.\n", nm + 8);
            exit(1);
        }
#else
        fprintf(stderr, "This version of elfload is not capable of loading the host library %s.\n",
                nm + 8);
        exit(1);
#endif
        return f;

    } else if (strncmp(nm, "libloader_", 10) == 0) {
        /* must be provided by the loader. Only dl.0 is provided right now */
        if (strcmp(nm, "libloader_dl.0") == 0) {
            f->hostlib = HOSTLIB_DL;

        } else {
            fprintf(stderr, "Loader lib %s unsupported.\n", nm);
            exit(1);

        }

        return f;
    }

    readFile(nm, instdir, f);

    /* make sure it's an ELF file */
    if (memcmp(f->prog, ELFMAG, SELFMAG) != 0) {
        if (!maybe) {
            fprintf(stderr, "%s does not appear to be an ELF file.\n", nm);
            exit(1);
        } else {
            return NULL;
        }
    }
    
    if (f->prog[EI_CLASS] == ELFCLASS32) {
        f->ehdr32 = (Elf32_Ehdr *)f->prog;
    } else if (f->prog[EI_CLASS] == ELFCLASS64) {
        f->ehdr64 = (Elf64_Ehdr *)f->prog;
    } else {
        if (!maybe) {
            fprintf(stderr, "%s does not appear to be a supported ELF file (32/64 bit).\n", nm);
            exit(1);
        } else {
            return NULL;
        }
    }
    
    /* FIXME: check endianness */

    /* must be an executable or .so to be loaded */
    if (f->ehdr32) {
        if (f->ehdr32->e_type != ET_EXEC &&
            f->ehdr32->e_type != ET_DYN) {
            if (!maybe) {
                fprintf(stderr, "%s is not an executable or shared object file.\n", nm);
                exit(1);
            } else {
                return NULL;
            }
        }
    } else {
        if (f->ehdr64->e_type != ET_EXEC &&
            f->ehdr64->e_type != ET_DYN) {
            if (!maybe) {
                fprintf(stderr, "%s is not an executable or shared object file.\n", nm);
                exit(1);
            } else {
                return NULL;
            }
        }
    }

    /* now go through program headers, to find the allocation space of this file */
    f->min = (void *) -1;
    f->max = 0;
    if (f->ehdr32) {
        curphdrl = f->prog + f->ehdr32->e_phoff - f->ehdr32->e_phentsize;
    } else {
        curphdrl = f->prog + f->ehdr64->e_phoff - f->ehdr64->e_phentsize;
    }


    for (phdri = 0; phdri < (f->ehdr32 ? f->ehdr32->e_phnum : f->ehdr64->e_phnum); phdri++) {
        curphdrl += (f->ehdr32 ? f->ehdr32->e_phentsize : f->ehdr64->e_phentsize);
        if (f->ehdr32) {
            curphdr32 = (Elf32_Phdr *) curphdrl;
            /* perhaps check its location */
            if (curphdr32->p_type == PT_LOAD) {
                /* adjust min/max */
                if ((void *) curphdr32->p_vaddr < f->min) {
                    f->min = (void *) curphdr32->p_vaddr;
                }
                if ((void *) curphdr32->p_vaddr + curphdr32->p_memsz > f->max) {
                    f->max = (void *) curphdr32->p_vaddr + curphdr32->p_memsz;
                }
                
            } else if (maybe && curphdr32->p_type == PT_INTERP) {
                /* if we're only maybe-loading, check the loader */
                if (strcmp((char *) (f->prog + curphdr32->p_offset), "/usr/bin/gelfload-ld")) {
                    /* wrong loader! */
                    return NULL;
                }
            }
        } else {
            curphdr64 = (Elf64_Phdr *) curphdrl;
            /* perhaps check its location */
            if (curphdr64->p_type == PT_LOAD) {
                /* adjust min/max */
                if ((void *) curphdr64->p_vaddr < f->min) {
                    f->min = (void *) curphdr64->p_vaddr;
                }
                if ((void *) curphdr64->p_vaddr + curphdr64->p_memsz > f->max) {
                    f->max = (void *) curphdr64->p_vaddr + curphdr64->p_memsz;
                }
                
            } else if (maybe && curphdr64->p_type == PT_INTERP) {
                /* if we're only maybe-loading, check the loader */
                if (strcmp((char *) (f->prog + curphdr64->p_offset), "/usr/bin/gelfload-ld")) {
                    /* wrong loader! */
                    return NULL;
                }
            }
        }

        
    }

    /* with this size info, we can allocate the space */
    f->memsz = f->max - f->min;
    
    /* if this is a binary, try to allocate it in place. elfload is addressed above 0x18000000 */
#if !__APPLE__
    if (f->ehdr->e_type == ET_EXEC && f->max < (void *) 0x18000000) {
        f->loc = bbuffer(f->min, f->memsz);

    } else {
#endif
        f->loc = bbuffer(NULL, f->memsz);
#if !__APPLE__
    }
#endif
    memset(f->loc, 0, f->memsz);

    f->offset = f->loc - f->min;

    /* we have the space, so load it in */
    if (f->ehdr32) {
        curphdrl = f->prog + f->ehdr32->e_phoff - f->ehdr32->e_phentsize;
        for (phdri = 0; phdri < f->ehdr32->e_phnum; phdri++) {
            curphdrl += f->ehdr32->e_phentsize;
            curphdr32 = (Elf32_Phdr *) curphdrl;
            
            /* perhaps load it in */
            if (curphdr32->p_type == PT_LOAD) {
                if (curphdr32->p_filesz > 0) {
                    /* OK, there's something to copy in, so do so */
                    memcpy((void *) curphdr32->p_vaddr + f->offset,
                           f->prog + curphdr32->p_offset,
                           curphdr32->p_filesz);
                }
                
            } else if (curphdr32->p_type == PT_DYNAMIC) {
                /* we need this to load in dependencies, et cetera */
                f->dynamic32 = (Elf32_Dyn *) (f->prog + curphdr32->p_offset);
                
            }
        }
    } else {
        curphdrl = f->prog + f->ehdr64->e_phoff - f->ehdr64->e_phentsize;
        for (phdri = 0; phdri < f->ehdr64->e_phnum; phdri++) {
            curphdrl += f->ehdr64->e_phentsize;
            curphdr64 = (Elf64_Phdr *) curphdrl;
            
            /* perhaps load it in */
            if (curphdr64->p_type == PT_LOAD) {
                if (curphdr64->p_filesz > 0) {
                    /* OK, there's something to copy in, so do so */
                    memcpy((void *) curphdr64->p_vaddr + f->offset,
                           f->prog + curphdr64->p_offset,
                           curphdr64->p_filesz);
                }
                
            } else if (curphdr64->p_type == PT_DYNAMIC) {
                /* we need this to load in dependencies, et cetera */
                f->dynamic64 = (Elf64_Dyn *) (f->prog + curphdr64->p_offset);
                
            }
        }
    }
    
    /* now go through dynamic entries, looking for basic vital info */
    if (f->ehdr32) {
        for (curdyn32 = f->dynamic32; curdyn32 && curdyn32->d_tag != DT_NULL; curdyn32++) {
            if (curdyn32->d_tag == DT_STRTAB) {
                f->strtab = (char *) (curdyn32->d_un.d_ptr + f->offset);
                
            } else if (curdyn32->d_tag == DT_SYMTAB) {
                f->symtab32 = (Elf32_Sym *) (curdyn32->d_un.d_ptr + f->offset);
                
            } else if (curdyn32->d_tag == DT_HASH) {
                f->hashtab32 = (Elf32_Word *) (curdyn32->d_un.d_ptr + f->offset);
                
            } else if (curdyn32->d_tag == DT_RELA) {
                f->rela32 = (Elf32_Rela *) (curdyn32->d_un.d_ptr + f->offset);
                
            } else if (curdyn32->d_tag == DT_RELASZ) {
                f->relasz = curdyn32->d_un.d_val;
                
            } else if (curdyn32->d_tag == DT_REL) {
                f->rel32 = (Elf32_Rel *) (curdyn32->d_un.d_ptr + f->offset);
                
            } else if (curdyn32->d_tag == DT_RELSZ) {
                f->relsz = curdyn32->d_un.d_val;
                
            } else if (curdyn32->d_tag == DT_JMPREL) {
                f->jmprel = (void *) (curdyn32->d_un.d_ptr + f->offset);
                
            } else if (curdyn32->d_tag == DT_PLTRELSZ) {
                f->jmprelsz = curdyn32->d_un.d_val;
                
            }
        }
    } else {
        for (curdyn64 = f->dynamic64; curdyn64 && curdyn64->d_tag != DT_NULL; curdyn64++) {
            if (curdyn64->d_tag == DT_STRTAB) {
                f->strtab = (char *) (curdyn64->d_un.d_ptr + f->offset);
                
            } else if (curdyn64->d_tag == DT_SYMTAB) {
                f->symtab64 = (Elf64_Sym *) (curdyn64->d_un.d_ptr + f->offset);
                
            } else if (curdyn64->d_tag == DT_HASH) {
                f->hashtab64 = (Elf64_Word *) (curdyn64->d_un.d_ptr + f->offset);
                
            } else if (curdyn64->d_tag == DT_RELA) {
                f->rela64 = (Elf64_Rela *) (curdyn64->d_un.d_ptr + f->offset);
                
            } else if (curdyn64->d_tag == DT_RELASZ) {
                f->relasz = curdyn64->d_un.d_val;
                
            } else if (curdyn64->d_tag == DT_REL) {
                f->rel64 = (Elf64_Rel *) (curdyn64->d_un.d_ptr + f->offset);
                
            } else if (curdyn64->d_tag == DT_RELSZ) {
                f->relsz = curdyn64->d_un.d_val;
                
            } else if (curdyn64->d_tag == DT_JMPREL) {
                f->jmprel = (void *) (curdyn64->d_un.d_ptr + f->offset);
                
            } else if (curdyn64->d_tag == DT_PLTRELSZ) {
                f->jmprelsz = curdyn64->d_un.d_val;
                
            }
        }
    }
    

    /* load in dependencies */
//    for (curdyn = f->dynamic; curdyn && curdyn->d_tag != DT_NULL; curdyn++) {
//        if (curdyn->d_tag == DT_NEEDED) {
//            loadELF(f->strtab + curdyn->d_un.d_val, instdir, 0);
//        }
//    }

    return f;
}

void relocateELFs()
{
    int i;

    for (i = elfFileCount - 1; i >= 0; i--) {
        relocateELF(i, &(elfFiles[i]));
    }
}

void relocateELF(int fileNo, struct ELF_File *f)
{
    /* do processor-specific relocation */
#define REL_P ((ssize_t) (currel->r_offset + f->offset))
#define REL_S32 ((ssize_t) (findELFSymbol32( \
                f->strtab + f->symtab32[ELF32_R_SYM(currel->r_info)].st_name, \
                NULL, fileNo, -1, NULL)))
#define REL_S64 ((ssize_t) (findELFSymbol64( \
                f->strtab + f->symtab64[ELF64_R_SYM(currel->r_info)].st_name, \
                NULL, fileNo, -1, NULL)))
#define REL_A (*((ssize_t *) REL_P))
#define WORD32_REL(to) REL_A = (int32_t) (to)
#define WORD64_REL(to) REL_A = (ssize_t) (to)

    /* we ought to have rel and symtab defined */
    if (f->ehdr32) {
        if (f->rela32 && f->symtab32) {
            Elf32_Rela *currel = f->rela32;
            for (; (void *) currel < (void *) f->rela32 + f->relasz; currel++) {
                switch (ELF32_R_TYPE(currel->r_info)) {
                    case R_X86_64_64:
                        WORD64_REL(REL_S32 + REL_A);
                        break;
                        
                    case R_X86_64_PC32:
                        WORD32_REL(REL_S32 + REL_A - REL_P);
                        break;
                        
                    case R_X86_64_COPY:
                    {
                        /* this is a bit more convoluted, as we need to find it in both places and copy */
                        Elf32_Sym *localsym, *sosym;
                        localsym = &(f->symtab32[ELF32_R_SYM(currel->r_info)]);
                        void *soptr = findELFSymbol32(
                                                    f->strtab + localsym->st_name,
                                                    NULL, -1, fileNo, &sosym);
                        
                        /* OK, we should have both, so copy it over */
                        if (localsym && sosym) {
                            memcpy((void *) (localsym->st_value + f->offset),
                                   soptr, sosym->st_size);
                        } else {
                            /* depend on localsym's size */
                            memcpy((void *) (localsym->st_value + f->offset),
                                   soptr, localsym->st_size);
                            
                        }
                        
                        break;
                    }
                        
                    case R_X86_64_GLOB_DAT:
                        WORD64_REL(REL_S32 + REL_A);
                        break;
                        
                    case R_X86_64_RELATIVE:
                        WORD64_REL(f->loc + REL_A);
                        break;
                        
                    default:
                        fprintf(stderr, "Unsupported relocation %d in %s\n", (int) ELF32_R_TYPE(currel->r_info), f->nm);
                }
            }
        }
    } else {
        if (f->rela64 && f->symtab64) {
            Elf64_Rela *currel = f->rela64;
            for (; (void *) currel < (void *) f->rela64 + f->relasz; currel++) {
                switch (ELF64_R_TYPE(currel->r_info)) {
                    case R_X86_64_64:
                        WORD64_REL(REL_S64 + REL_A);
                        break;
                        
                    case R_X86_64_PC32:
                        WORD32_REL(REL_S64 + REL_A - REL_P);
                        break;
                        
                    case R_X86_64_COPY:
                    {
                        /* this is a bit more convoluted, as we need to find it in both places and copy */
                        Elf64_Sym *localsym, *sosym;
                        localsym = &(f->symtab64[ELF64_R_SYM(currel->r_info)]);
                        void *soptr = findELFSymbol64(
                                                    f->strtab + localsym->st_name,
                                                    NULL, -1, fileNo, &sosym);
                        
                        /* OK, we should have both, so copy it over */
                        if (localsym && sosym) {
                            memcpy((void *) (localsym->st_value + f->offset),
                                   soptr, sosym->st_size);
                        } else {
                            /* depend on localsym's size */
                            memcpy((void *) (localsym->st_value + f->offset),
                                   soptr, localsym->st_size);
                            
                        }
                        
                        break;
                    }
                        
                    case R_X86_64_GLOB_DAT:
                        WORD64_REL(REL_S64 + REL_A);
                        break;
                        
                    case R_X86_64_RELATIVE:
                        WORD64_REL(f->loc + REL_A);
                        break;
                        
                    default:
                        fprintf(stderr, "Unsupported relocation %d in %s\n", (int) ELF64_R_TYPE(currel->r_info), f->nm);
                }
            }
        }
    }


    if (f->ehdr32) {
        if (f->jmprel && f->symtab32) {
            Elf32_Rela *currel = (Elf32_Rela *) f->jmprel;
            for (; (void *) currel < (void *) f->jmprel + f->jmprelsz; currel++) {
                switch (ELF32_R_TYPE(currel->r_info)) {
                    case R_X86_64_JUMP_SLOT:
                        WORD64_REL(REL_S32);
                        break;
                        
                    default:
                        fprintf(stderr, "Unsupported jmprel relocation %d in %s\n", (int) ELF32_R_TYPE(currel->r_info), f->nm);
                }
            }
        }
    } else {
        if (f->jmprel && f->symtab64) {
            Elf64_Rela *currel = (Elf64_Rela *) f->jmprel;
            for (; (void *) currel < (void *) f->jmprel + f->jmprelsz; currel++) {
                switch (ELF64_R_TYPE(currel->r_info)) {
                    case R_X86_64_JUMP_SLOT:
                        WORD64_REL(REL_S64);
                        break;
                        
                    default:
                        fprintf(stderr, "Unsupported jmprel relocation %d in %s\n", (int) ELF64_R_TYPE(currel->r_info), f->nm);
                }
            }
        }
    }
}

/* Initialize every ELF loaded /except/ for f (usually the binary) */
void initELF(struct ELF_File *except)
{
    int i;
    struct ELF_File *f;
    Elf32_Dyn *dyn32;
    Elf64_Dyn *dyn64;

    for (i = elfFileCount - 1; i >= 0; i--) {
        f = &(elfFiles[i]);
        if (f == except) continue;

        /* init is in the dynamic section */
        if (f->dynamic32 == NULL && f->dynamic64 == NULL) continue;
        if (f->ehdr32) {
            for (dyn32 = f->dynamic32; dyn32 && dyn32->d_tag != DT_NULL; dyn32++) {
                if (dyn32->d_tag == DT_INIT) {
                    /* call it */
                    ((void(*)()) (dyn32->d_un.d_ptr + f->offset))();
                    break;
                }
            }
        } else {
            for (dyn64 = f->dynamic64; dyn64 && dyn64->d_tag != DT_NULL; dyn64++) {
                if (dyn64->d_tag == DT_INIT) {
                    /* call it */
                    ((void(*)()) (dyn64->d_un.d_ptr + f->offset))();
                    break;
                }
            }

        }
    }
}

void *findELFSymbol(const char *nm, struct ELF_File *onlyin, int localin, int notin)
{
    void *sym = findELFSymbol32(nm, onlyin, localin, notin, NULL);
    if (sym == NULL) {
        sym = findELFSymbol64(nm, onlyin, localin, notin, NULL);
    }
    return sym;
}

/* Find a symbol within the currently loaded ELF files
 * localin: The number of the current file, where STB_LOCAL symbols are OK
 * notin: Do not bind to symbols in this file 
 * Either can be -1 */
void *findELFSymbol32(const char *nm, struct ELF_File *onlyin, int localin, int notin, Elf32_Sym **syminto)
{
    int i;
    struct ELF_File *f;
    Elf32_Word hash = elf_hash32((unsigned char *) nm);
    Elf32_Word bucket, index;
    Elf32_Sym *sym;
    void *hostsym;
    if (syminto) *syminto = NULL;

    if (nm[0] == '\0') return NULL;

    for (i = 0; i < elfFileCount; i++) {
        if (i == notin) continue;

        f = &(elfFiles[i]);
        if (onlyin && f != onlyin) continue;

        /* if this is a host library, just try the host method */
        if (f->hostlib == HOSTLIB_HOST) {
            char lsym[1024];
            snprintf(lsym, 1024, "gelfload__%s", nm);

#if defined(HAVE_DLFCN_H)
            hostsym = dlsym(f->prog, lsym);
            if (hostsym) return hostsym;
            hostsym = dlsym(f->prog, nm);
            if (hostsym) return hostsym;
            continue;
#elif defined(__WIN32)
            char csym[1024];
            int isimp = 0;

            /* Remove _imp__ if it's present */
            if (strncmp(nm, "_imp__", 6) == 0) {
                isimp = 1;
                nm += 6;
                snprintf(lsym, 1024, "gelfload__%s", nm);
            }

            /* Try adding a _ first, to get the cdecl version */
            snprintf(csym, 1024, "_%s", lsym);
            hostsym = GetProcAddress(f->prog, csym);
            if (hostsym == NULL)
                hostsym = GetProcAddress(f->prog, lsym);
            if (hostsym == NULL) {
                snprintf(csym, 1024, "_%s", nm);
                hostsym = GetProcAddress(f->proc, csym);
            }
            if (hostsym == NULL)
                hostsym = GetProcAddress(f->prog, nm);
            if (hostsym) {
                if (isimp) {
                    /* Need a pointer to this pointer */
                    void **pptr = (void **) malloc(sizeof(void*));
                    if (pptr == NULL) {
                        perror("malloc");
                        exit(1);
                    }
                    *pptr = hostsym;
                    return (void *) pptr;
                    
                } else {
                    return hostsym;

                }
            }
#endif
            continue;

        } else if (f->hostlib == HOSTLIB_DL) {
           hostsym = elfload_dl(nm);
           if (hostsym) return hostsym;
           continue;

        }

        /* figure out the bucket ... */
        bucket = hash % ELFFILE_NBUCKET32(f);

        /* then find the chain entry */
        index = ELFFILE_BUCKET32(f, bucket);

        /* and work our way through the chain */
        for (; index != STN_UNDEF; index = ELFFILE_CHAIN32(f, index)) {
            sym = &(f->symtab32[index]);

            /* see if it's defined */
            if (strcmp(f->strtab + sym->st_name, nm) == 0 &&
                (i == localin || ELF32_ST_BIND(sym->st_info) != STB_LOCAL) &&
                sym->st_shndx != SHN_UNDEF) {
                /* we found our symbol! */
                if (syminto != NULL) {
                    *syminto = sym;
                }
                return (void *) (sym->st_value + f->offset);
            }
        }
    }

    hostsym = dlsym(RTLD_SELF, nm);
    if (hostsym == NULL) {
        fprintf(stderr, "Symbol undefined: '%s'\n", nm);
    }
    return hostsym;
}

void *findELFSymbol64(const char *nm, struct ELF_File *onlyin, int localin, int notin, Elf64_Sym **syminto)
{
    int i;
    struct ELF_File *f;
    Elf64_Word hash = elf_hash64((unsigned char *) nm);
    Elf64_Word bucket, index;
    Elf64_Sym *sym;
    void *hostsym;
    if (syminto) *syminto = NULL;
    
    if (nm[0] == '\0') return NULL;
    
    for (i = 0; i < elfFileCount; i++) {
        if (i == notin) continue;
        
        f = &(elfFiles[i]);
        if (onlyin && f != onlyin) continue;
        
        /* if this is a host library, just try the host method */
        if (f->hostlib == HOSTLIB_HOST) {
            char lsym[1024];
            snprintf(lsym, 1024, "gelfload__%s", nm);
            
#if defined(HAVE_DLFCN_H)
            hostsym = dlsym(f->prog, lsym);
            if (hostsym) return hostsym;
            hostsym = dlsym(f->prog, nm);
            if (hostsym) return hostsym;
            continue;
#elif defined(__WIN64)
            char csym[1024];
            int isimp = 0;
            
            /* Remove _imp__ if it's present */
            if (strncmp(nm, "_imp__", 6) == 0) {
                isimp = 1;
                nm += 6;
                snprintf(lsym, 1024, "gelfload__%s", nm);
            }
            
            /* Try adding a _ first, to get the cdecl version */
            snprintf(csym, 1024, "_%s", lsym);
            hostsym = GetProcAddress(f->prog, csym);
            if (hostsym == NULL)
                hostsym = GetProcAddress(f->prog, lsym);
            if (hostsym == NULL) {
                snprintf(csym, 1024, "_%s", nm);
                hostsym = GetProcAddress(f->proc, csym);
            }
            if (hostsym == NULL)
                hostsym = GetProcAddress(f->prog, nm);
            if (hostsym) {
                if (isimp) {
                    /* Need a pointer to this pointer */
                    void **pptr = (void **) malloc(sizeof(void*));
                    if (pptr == NULL) {
                        perror("malloc");
                        exit(1);
                    }
                    *pptr = hostsym;
                    return (void *) pptr;
                    
                } else {
                    return hostsym;
                    
                }
            }
#endif
            continue;
            
        } else if (f->hostlib == HOSTLIB_DL) {
            hostsym = elfload_dl(nm);
            if (hostsym) return hostsym;
            continue;
            
        }
        
        /* figure out the bucket ... */
        bucket = hash % ELFFILE_NBUCKET64(f);
        
        /* then find the chain entry */
        index = ELFFILE_BUCKET64(f, bucket);
        
        /* and work our way through the chain */
        for (; index != STN_UNDEF; index = ELFFILE_CHAIN64(f, index)) {
            sym = &(f->symtab64[index]);
            
            /* see if it's defined */
            if (strcmp(f->strtab + sym->st_name, nm) == 0 &&
                (i == localin || ELF64_ST_BIND(sym->st_info) != STB_LOCAL) &&
                sym->st_shndx != SHN_UNDEF) {
                /* we found our symbol! */
                if (syminto != NULL) {
                    *syminto = sym;
                }
                return (void *) (sym->st_value + f->offset);
            }
        }
    }
    
    hostsym = dlsym(RTLD_SELF, nm);
    if (hostsym == NULL) {
        fprintf(stderr, "Symbol undefined: '%s'\n", nm);
    }
    return hostsym;
}

/* The standard ELF hash function */
Elf32_Word elf_hash32(const unsigned char *name)
{
    Elf32_Word h = 0, g;

    while (*name) {
        h = (h << 4) + *name++;
        if (g = h & 0xf0000000)
            h ^= g >> 24;
        h &= ~g;
    }
    return h;
}

Elf64_Word elf_hash64(const unsigned char *name)
{
    Elf64_Word h = 0, g;
    
    while (*name) {
        h = (h << 4) + *name++;
        if (g = h & 0xf0000000)
            h ^= g >> 24;
        h &= ~g;
    }
    return h;
}

/* A handy function to read a file or mmap it, as appropriate */
void readFile(const char *nm, const char *instdir, struct ELF_File *ef)
{
    /* try with instdir */
    char *longnm = malloc(strlen(nm) + strlen(instdir) + 18);
    if (longnm == NULL) {
        perror("malloc");
        exit(1);
    }
    sprintf(longnm, "%s/../lib/gelfload/%s", instdir, nm);

#ifdef HAVE_MMAP
{
    void *buf;
    struct stat sbuf;
    int fd;

    /* use mmap. First, open the file and get its length */
    fd = open(nm, O_RDONLY);
    if (fd == -1) {
        fd = open(longnm, O_RDONLY);

        if (fd == -1) {
            perror(nm);
            exit(1);
        }
    }
    free(longnm);
    if (fstat(fd, &sbuf) < 0) {
        perror(nm);
        exit(1);
    }

    /* then mmap it */
    buf = mmap(NULL, sbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (buf == NULL) {
        perror("mmap");
        exit(1);
    }

    close(fd);

    /* and put it in ef */
    ef->prog = buf;
    ef->proglen = sbuf.st_size;
}
#else
{
    char *buf;
    int bufsz, rdtotal, rd;
    FILE *f;

    /* OK, use stdio */
    f = fopen(nm, "rb");
    if (f == NULL) {
        f = fopen(longnm, "rb");

        if (f == NULL) {
            perror(nm);
            exit(1);
        }
    }
    free(longnm);
    
    /* start with a 512-byte buffer */
    bufsz = 512;
    buf = (char *) malloc(bufsz);
    if (buf == NULL) {
        perror("malloc");
        exit(1);
    }

    /* and read in the file */
    rdtotal = 0;
    while ((rd = fread(buf + rdtotal, 1, bufsz - rdtotal, f)) != 0) {
        rdtotal += rd;
        if (rdtotal != bufsz) {
            /* done reading */
            break;

        } else {
            bufsz <<= 1;
            buf = realloc(buf, bufsz);
            if (buf == NULL) {
                perror("realloc");
                exit(1);
            }
        }
    }
    if (ferror(f)) {
        perror(nm);
        exit(1);
    }
    fclose(f);

    /* now put it in ef */
    ef->prog = buf;
    ef->proglen = rdtotal;
}
#endif
}

/* The finalization function for readFile */
void closeFile(struct ELF_File *ef)
{
#ifdef HAVE_MMAP
    munmap(ef->prog, ef->proglen);
#else
    free(ef->prog);
#endif
}
