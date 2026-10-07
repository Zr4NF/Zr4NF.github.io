---
layout: post
title: "ret2dlreslove"
date: 2026-10-07 20:05:00 +0800
tags: ["CTF", "PWN"]
description: "Notes on ret2dlresolve and dynamic symbol resolution."
source_folder: "PWN/Stack Exploitation/ret2dlreslove"
lang: zh-CN
---
{% raw %}

# 结构体
## .dynamic

该节存放了许多`Elf64_Dyn`结构体，在IDA中位于got表的上面，保存了`动态链接器`所需要的`基本信息`，比如存放了`ELF`文件其他节的标识和起始地址。结构体定义如下所示。

```c
typedef struct {
    Elf64_Sxword d_tag;//动态段标识号  
    
    Elf64_Sxword d_un //动态段起始地址
} Elf64_Dyn;
```

其中关键字`d_tag`定义如下：

```c
/* Legal values for d_tag (dynamic entry type).  */
#define DT_NULL                0                /* Marks end of dynamic section */
#define DT_NEEDED              1                /* Name of needed library */
#define DT_PLTRELSZ            2                /* Size in bytes of PLT relocs */
#define DT_PLTGOT              3                /* Processor defined value */
#define DT_HASH                4                /* Address of symbol hash table */
#define DT_STRTAB              5                /* Address of string table */
#define DT_SYMTAB              6                /* Address of symbol table */
#define DT_RELA                7                /* Address of Rela relocs */
#define DT_RELASZ              8                /* Total size of Rela relocs */
#define DT_RELAENT             9                /* Size of one Rela reloc */
#define DT_STRSZ              10                /* Size of string table */
#define DT_SYMENT             11                /* Size of one symbol table entry */
#define DT_INIT               12                /* Address of init function */
#define DT_FINI               13                /* Address of termination function */
#define DT_SONAME             14                /* Name of shared object */
#define DT_RPATH              15                /* Library search path (deprecated) */
#define DT_SYMBOLIC           16                /* Start symbol search here */
#define DT_REL                17                /* Address of Rel relocs */
#define DT_RELSZ              18                /* Total size of Rel relocs */
#define DT_RELENT             19                /* Size of one Rel reloc */
#define DT_PLTREL             20                /* Type of reloc in PLT */
#define DT_DEBUG              21                /* For debugging; unspecified */
#define DT_TEXTREL            22                /* Reloc might modify .text */
#define DT_JMPREL             23                /* Address of PLT relocs */
#define DT_BIND_NOW           24                /* Process relocations of object */
#define DT_INIT_ARRAY         25                /* Array with addresses of init fct */
#define DT_FINI_ARRAY         26                /* Array with addresses of fini fct */
#define DT_INIT_ARRAYSZ       27                /* Size in bytes of DT_INIT_ARRAY */
#define DT_FINI_ARRAYSZ       28                /* Size in bytes of DT_FINI_ARRAY */
#define DT_RUNPATH            29                /* Library search path */
#define DT_FLAGS              30                /* Flags for the object being loaded */
#define DT_ENCODING           32                /* Start of encoded range */
#define DT_PREINIT_ARRAY      32                /* Array with addresses of preinit fct*/
#define DT_PREINIT_ARRAYSZ    33                /* size in bytes of DT_PREINIT_ARRAY */
#define DT_SYMTAB_SHNDX       34                /* Address of SYMTAB_SHNDX section */
#define DT_NUM                35                /* Number used */
```

## .rela.plt


该节存放了许多`Elf64_Rela`结构体，是对**函数引用**的修正，修正的位置在`got.plt`表，每个libc库函数都有自己的`Elf64_Rela`结构体。在程序入口附近，位于`LOAD`段。



```c
typedef struct {
    Elf64_Addr r_offset;  /* 表示重定位所作用的虚拟地址或相对基地址的偏移，got表地址 */ 
    Elf64_Xword r_info;   /* 这是一个复合值，重定位类型和符号表下标 */    
    Elf64_Sxword r_addend; /* Addend */
} Elf64_Rela;
```


`r_info`是一个复合值，其`高32位`表示该重定位项在`动态链接符号表.dynsym`中对应项的`下标`，`低32位`表示该重定位项的`重定向类型`。


**`重定位类型(Relocation Types)`**



```cpp
#define R_386_NONE     0  /* No reloc */
#define R_386_32       1  /* Direct 32 bit  */
#define R_386_PC32     2  /* PC relative 32 bit */
#define R_386_GOT32    3  /* 32 bit GOT entry */
#define R_386_PLT32    4  /* 32 bit PLT address */
#define R_386_COPY     5  /* Copy symbol at runtime */
#define R_386_GLOB_DAT 6  /* Create GOT entry */
#define R_386_JMP_SLOT 7  /* Create PLT entry */
#define R_386_RELATIVE 8  /* Adjust by program base */
......

/* AMD x86-64 relocations.  */
#define R_X86_64_NONE      0  /* No reloc */
#define R_X86_64_64        1  /* Direct 64 bit  */
#define R_X86_64_PC32      2  /* PC relative 32 bit signed */
#define R_X86_64_GOT32     3  /* 32 bit GOT entry */
#define R_X86_64_PLT32     4  /* 32 bit PLT address */
#define R_X86_64_COPY      5  /* Copy symbol at runtime */
#define R_X86_64_GLOB_DAT  6  /* Create GOT entry */
#define R_X86_64_JUMP_SLOT 7  /* Create PLT entry */
#define R_X86_64_RELATIVE  8  /* Adjust by program base */
#define R_X86_64_GOTPCREL  9  /* 32 bit signed PC relative offset to GOT */
......
```


**`32位ELF`**一般用来函数重定位的重定位类型就是`R_386_JMP_SLOT`类型,**`64位ELF`**函数重定位的重定位类型就是`R_X86_64_JUMP_SLOT`类型，源码对其的注释是`Create PLT entry`。这种类型的`函数重定位`都会在`ELF`中创建一个`PLT入口`。



## .rela.dyn

该节，用于普通动态重定位，**程序加载时处理**，常见定位项：
```cpp
 __libc_start_main
 __gmon_start__
 stdout
```

其中结构体也为`Elf64_Rela`。

## .dynsym


该节存放了许多`Elf64_Sym`结构体，同样地，每个`libc`函数都有自己的`Elf64_Sym`。在程序入口附近，位于`LOAD`段。

```c
typedef struct {
  Elf64_Word    st_name;  /* 符号名在关联字符串表中的偏移 */
  unsigned char st_info;  /* 符号绑定属性和符号类型 */
  unsigned char st_other; /* 符号可见性，低2位有效，0表示 STV_DEFAULT ，即是否在共享器内已知，已知则寻找对应的共享器，没有则在传入的共享器中寻找偏移*/
  Elf64_Section st_shndx; /* 符号所在节在节头表中的索引 */
  Elf64_Addr    st_value; /* 符号值：含义取决于 ELF 文件类型 */
  Elf64_Xword   st_size;  /* 符号大小，0表示大小未知或无大小 */
} Elf64_Sym;
```

`st_info`大小为 1 Btyes，高4位表示符号的绑定特征，低4位表示符号类型。


**绑定特征（高四位）**，

```c
#define STB_LOCAL   0       /* Local symbol  局部符号（本文件可见） */
#define STB_GLOBAL  1       /* Global symbol 全局符号（多文件可见） */
#define STB_WEAK    2       /* Weak symbol 弱符号，即遇到同名的符号优先弃用该符号的声明*/
#define STB_NUM     3       /* Number of defined types.  */
#define STB_LOOS    10      /* Start of OS-specific */
#define STB_GNU_UNIQUE  10      /* Unique symbol.  */
#define STB_HIOS    12      /* End of OS-specific */
#define STB_LOPROC  13      /* Start of processor-specific */
#define STB_HIPROC  15      /* End of processor-specific */
```
绑定特征`0,1,2`均可取。


**符号类型（低四位）**

```c
#define STT_NOTYPE      0   /* 符号类型未指定 */
#define STT_OBJECT      1   /* 符号是一个数据对象 */
#define STT_FUNC        2   /* 符号是一个代码对象 / 函数 */
#define STT_SECTION     3   /* 符号与某个节 section 相关联 */
#define STT_FILE        4   /* 符号名是文件名 */
#define STT_COMMON      5   /* 符号是一个 common 数据对象 */
#define STT_TLS         6   /* 符号是线程局部存储 TLS 数据对象 */
#define STT_NUM         7   /* 已定义类型的数量 */
#define STT_LOOS        10  /* 操作系统特定类型的起始值 */
#define STT_GNU_IFUNC   10  /* 符号是间接代码对象 GNU indirect function */
#define STT_HIOS        12  /* 操作系统特定类型的结束值 */
#define STT_LOPROC      13  /* 处理器特定类型的起始值 */
#define STT_HIPROC      15  /* 处理器特定类型的结束值 */
```


变量、函数分别取`1, 2` 即可。

那么稍微总结一下得到`st_info`取值的一般规律如下：
```makefile
绑定函数:        st_info = 0x12 例如: read,printf,__libc_start_main
绑定全局变量:    st_info = 0x11 例如: stdin，stdout,_IO_stdin_used
绑定弱变量:      st_info = 0x20 例如: __gmon_start__
```


**节头表**：

|节头表索引|节名|
|--:|---|
|0|`SHN_UNDEF` / 空节|
|1|`.text`|
|2|`.data`|
|3|`.bss`|
|4|`.rodata`|
## .dynstr


即字符串表（STRTAB），该节存放的是libc函数的符号名，就是一个一个的字符串，诸如此类'exit'、'read'。在程序入口附近，位于`LOAD`段。


## link_map

`link_map` 是 **glibc 动态链接器 ld-linux 用来描述“一个已加载 ELF 对象”的核心结构体**。

一个进程里每加载一个 ELF 对象，就会有一个对应的 `struct link_map`：

```
主程序        -> 一个 link_maplibc.so.6     -> 一个 link_mapld-linux      -> 一个 link_maplibpthread    -> 一个 link_map其他 so       -> 各自一个 link_map
```

它们通过链表串起来：

```
main link_map -> libc link_map -> ld-linux link_map -> ...
```

该结构体在 ld 中。

```cpp
/* 描述一个已加载共享对象的结构体。`l_next' 和 `l_prev'
   成员构成了一条链，链上包含所有在启动时加载的共享对象。

   这些数据结构位于运行时动态链接器使用的空间中；
   修改它们可能会造成灾难性后果。

   如果有必要，这个数据结构将来可能会发生变化。
   用户级程序必须避免定义这种类型的对象。 */

struct link_map
  {
    /* 前几个成员是与调试器通信协议的一部分。
       这与 SVR4 使用的格式相同。 */

    ElfW(Addr) l_addr;          /* ELF 文件中的地址与内存中地址之间的差值。 */
    char *l_name;               /* 找到该对象时使用的绝对文件名。 */
    ElfW(Dyn) *l_ld;            /* 该共享对象的动态段。 */
    struct link_map *l_next, *l_prev; /* 已加载对象链表。 */

    /* 后续所有成员都是动态链接器内部使用的。
       它们可能会在没有通知的情况下发生变化。 */

    /* 这个元素通常只会指向同一个类型对象本身；
       只有当 ld.so 被用于多个命名空间时，它才可能不同。 */
    struct link_map *l_real;

    /* 此 link_map 所属命名空间的编号。 */
    Lmid_t l_ns;

    struct libname_list *l_libname;

    /* 指向动态段的索引指针数组。
       [0,DT_NUM) 由处理器无关的 tag 进行索引。
       [DT_NUM,DT_NUM+DT_THISPROCNUM) 由 tag 减去 DT_LOPROC 后进行索引。
       [DT_NUM+DT_THISPROCNUM,DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM)
       由 DT_VERSIONTAGIDX(tagvalue) 进行索引。
       [DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM,
        DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM)
       由 DT_EXTRATAGIDX(tagvalue) 进行索引。
       [DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM,
        DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM+DT_VALNUM)
       由 DT_VALTAGIDX(tagvalue) 进行索引；
       [DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM+DT_VALNUM,
        DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM+DT_VALNUM+DT_ADDRNUM)
       由 DT_ADDRTAGIDX(tagvalue) 进行索引，参见 <elf.h>。 */

    ElfW(Dyn) *l_info[DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM
                      + DT_EXTRANUM + DT_VALNUM + DT_ADDRNUM];

    const ElfW(Phdr) *l_phdr;   /* 指向内存中程序头表的指针。 */
    ElfW(Addr) l_entry;         /* 程序入口点位置。 */
    ElfW(Half) l_phnum;         /* 程序头表项数量。 */
    ElfW(Half) l_ldnum;         /* 动态段表项数量。 */

    /* DT_NEEDED 依赖项以及它们的依赖项数组，
       按符号查找所需的依赖顺序排列，包括带重复项和不带重复项的情况。
       在依赖项被加载之前，这里没有表项。 */
    struct r_scope_elem l_searchlist;

    /* 我们需要一个特殊的搜索列表来处理带有 DT_SYMBOLIC 标记的对象。 */
    struct r_scope_elem l_symbolic_searchlist;

    /* 最先导致该对象被加载的依赖对象。 */
    struct link_map *l_loader;

    /* 版本名称数组。 */
    struct r_found_version *l_versions;
    unsigned int l_nversions;

    /* 符号哈希表。 */
    Elf_Symndx l_nbuckets;
    Elf32_Word l_gnu_bitmask_idxbits;
    Elf32_Word l_gnu_shift;
    const ElfW(Addr) *l_gnu_bitmask;

    union
    {
      const Elf32_Word *l_gnu_buckets;
      const Elf_Symndx *l_chain;
    };

    union
    {
      const Elf32_Word *l_gnu_chain_zero;
      const Elf_Symndx *l_buckets;
    };

    unsigned int l_direct_opencount; /* dlopen/dlclose 使用的引用计数。 */

    enum                        /* 该对象的来源。 */
      {
        lt_executable,          /* 主可执行程序。 */
        lt_library,             /* 主可执行程序需要的库。 */
        lt_loaded               /* 运行时额外加载的共享对象。 */
      } l_type:2;

    unsigned int l_dt_relr_ref:1; /* 如果引用了 GLIBC_ABI_DT_RELR，则非零。 */
    unsigned int l_relocated:1;   /* 如果该对象的重定位已完成，则非零。 */
    unsigned int l_init_called:1; /* 如果 DT_INIT 函数已被调用，则非零。 */
    unsigned int l_global:1;      /* 如果该对象位于 _dl_global_scope 中，则非零。 */
    unsigned int l_reserved:2;    /* 保留给内部使用。 */
    unsigned int l_main_map:1;    /* 如果这是主程序的 map，则非零。 */
    unsigned int l_visited:1;     /* 内部用于 map 依赖图遍历。 */
    unsigned int l_map_used:1;    /* 这两个 bit 用于 _dl_close_worker 中 */
    unsigned int l_map_done:1;    /* 遍历 map。 */

    unsigned int l_phdr_allocated:1; /* 如果 `l_phdr' 指向的数据结构是动态分配的，则非零。 */
    unsigned int l_soname_added:1;   /* 如果 SONAME 确定已经在 l_libname 链表中，则非零。 */
    unsigned int l_faked:1;          /* 如果这是一个没有关联文件的伪造描述符，则非零。 */

    unsigned int l_need_tls_init:1;  /* 如果重定位完成时应在该 link_map 上调用
                                        GL(dl_init_static_tls)，则非零。 */

    unsigned int l_auditing:1;       /* 如果该 DSO 用于 auditing，则非零。 */
    unsigned int l_audit_any_plt:1;  /* 如果至少有一个 audit 模块对 PLT 拦截感兴趣，则非零。 */

    unsigned int l_removed:1;        /* 如果该对象已被移除，不能再使用，则非零。 */

    unsigned int l_contiguous:1;     /* 如果段之间的空洞已被 mprotect 处理，
                                        或者根本不存在段间空洞，则非零。 */

    unsigned int l_free_initfini:1;  /* 如果 l_initfini 可以被释放，则非零；
                                        也就是说，它不是由 ld.so 中的 dummy malloc 分配的。 */

    unsigned int l_ld_readonly:1;    /* 如果动态段是只读的，则非零。 */

    unsigned int l_find_object_processed:1; /* 如果为零，说明 _dl_find_object_update
                                               还需要处理这个 lt_library map。 */

    /* 该 map 的 NODELETE 状态。
       只对类型为 lt_loaded 的 map 有效。

       lazy binding 会直接设置 l_nodelete_active，
       这可能发生在信号处理函数中。

       初始加载 DF_1_NODELETE 对象时会设置 l_nodelete_pending。
       重定位过程也可能设置 l_nodelete_pending。

       l_nodelete_pending 类型的 map 会在 dlopen 的最后阶段，
       即调用 ELF 构造函数之前，被提升为 l_nodelete_active 状态。

       dlclose 只会拒绝卸载 l_nodelete_active 类型的 map；
       pending 状态会被忽略。 */
    bool l_nodelete_active;
    bool l_nodelete_pending;

#include <link_map.h>

    /* 收集到的该对象自身 RPATH 目录信息。 */
    struct r_search_path_struct l_rpath_dirs;

    /* profiling 时收集到的重定位结果。 */
    struct reloc_result
    {
      DL_FIXUP_VALUE_TYPE addr;
      struct link_map *bound;
      unsigned int boundndx;
      uint32_t enterexit;
      unsigned int flags;

      /* 并发说明：
         该字段用于保护多线程环境下 relocation result 的并发初始化。
         更详细的说明见 elf/dl-runtime.c。 */
      unsigned int init;
    } *l_reloc_result;

    /* 如果可用，指向版本信息的指针。 */
    ElfW(Versym) *l_versyms;

    /* 表示该对象被找到时所在路径的字符串。 */
    const char *l_origin;

    /* 该对象内存映射的起始和结束地址。
       l_map_start 不一定等于 l_addr。 */
    ElfW(Addr) l_map_start, l_map_end;

    /* `l_scope' 的默认数组。 */
    struct r_scope_elem *l_scope_mem[4];

    /* 为 `l_scope' 分配的数组大小。 */
    size_t l_scope_max;

    /* 该数组定义此 link_map 的符号查找作用域。
       初始时最多有三个不同的作用域列表。 */
    struct r_scope_elem **l_scope;

    /* 类似的数组，但这里只包含局部作用域。
       偶尔会用到。 */
    struct r_scope_elem *l_local_scope[2];

    /* 该信息用于准确判断一个共享对象是否与已经加载的某个对象相同。 */
    struct r_file_id l_file_id;

    /* 收集到的该对象自身 RUNPATH 目录信息。 */
    struct r_search_path_struct l_runpath_dirs;

    /* 按 init 和 fini 调用顺序排列的对象列表。 */
    struct link_map **l_initfini;

    /* 通过符号绑定引入的依赖项列表。 */
    struct link_map_reldeps
      {
        unsigned int act;
        struct link_map *list[];
      } *l_reldeps;

    unsigned int l_reldepsmax;

    /* 如果该 DSO 正在被使用，则非零。 */
    unsigned int l_used;

    /* 各种标志字。 */
    ElfW(Word) l_feature_1;
    ElfW(Word) l_flags_1;
    ElfW(Word) l_flags;

    /* 在 `dl_close' 中临时使用。 */
    int l_idx;

    struct link_map_machine l_mach;

    struct
    {
      const ElfW(Sym) *sym;
      int type_class;
      struct link_map *value;
      const ElfW(Sym) *ret;
    } l_lookup_cache;

    /* 线程局部存储 TLS 相关信息。 */

    /* 初始化镜像的起始地址。 */
    void *l_tls_initimage;

    /* 初始化镜像大小。 */
    size_t l_tls_initimage_size;

    /* TLS 块大小。 */
    size_t l_tls_blocksize;

    /* TLS 块的对齐要求。 */
    size_t l_tls_align;

    /* 模块对齐后的第一个字节偏移。 */
    size_t l_tls_firstbyte_offset;

#ifndef NO_TLS_OFFSET
# define NO_TLS_OFFSET  0
#endif

#ifndef FORCED_DYNAMIC_TLS_OFFSET
# if NO_TLS_OFFSET == 0
#  define FORCED_DYNAMIC_TLS_OFFSET -1
# elif NO_TLS_OFFSET == -1
#  define FORCED_DYNAMIC_TLS_OFFSET -2
# else
#  error "FORCED_DYNAMIC_TLS_OFFSET is not defined"
# endif
#endif

    /* 对于启动时已经存在的对象：其在静态 TLS 块中的偏移。 */
    ptrdiff_t l_tls_offset;

    /* 模块在 dtv 数组中的索引。 */
    size_t l_tls_modid;

    /* 该 DSO 构造出的 thread_local 对象数量。
       该字段会被原子访问和修改，并不总是由 load lock 保护。
       另见 cxa_thread_atexit_impl.c 中的并发说明。 */
    size_t l_tls_dtor_count;

    /* 重定位完成后用于修改权限的信息。 */
    ElfW(Addr) l_relro_addr;
    size_t l_relro_size;

    unsigned long long int l_serial;
  };
```

无pie示例：
```cpp
{
  l_addr = 0,
  l_name = 0x7ffff7ffe8b8 "",
  l_ld = 0x403148,
  l_next = 0x7ffff7ffe8c0,
  l_prev = 0x0,
  l_real = 0x7ffff7ffe2e0,
  l_ns = 0,
  l_libname = 0x7ffff7ffe8a0,
  l_info = {0x0, 0x403148, 0x403228, 0x403218, 0x0, 0x4031c8, 0x4031d8, 0x403258, 0x403268, 0x403278, 0x4031e8, 0x4031f8, 
    0x403158, 0x403168, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x403238, 0x403208, 0x0, 0x403248, 0x0, 0x403178, 0x403198, 0x403188, 
    0x4031a8, 0x0 <repeats 13 times>, 0x403298, 0x403288, 0x0 <repeats 13 times>, 0x4032a8, 0x0 <repeats 25 times>, 0x4031b8},
  l_phdr = 0x400040,
  l_entry = 4198512,
  l_phnum = 12,
  l_ldnum = 0,
  l_searchlist = {
    r_list = 0x7ffff7fbb6c0,
    r_nlist = 3
  },
  l_symbolic_searchlist = {
    r_list = 0x7ffff7ffe898,
    r_nlist = 0
  },
  l_loader = 0x0,
  l_versions = 0x7ffff7fbb6e0,
  l_nversions = 4,
  l_nbuckets = 2,
  l_gnu_bitmask_idxbits = 0,
  l_gnu_shift = 6,
  l_gnu_bitmask = 0x400388,
  {
    l_gnu_buckets = 0x400390,
    l_chain = 0x400390
  },
  {
    l_gnu_chain_zero = 0x400384,
    l_buckets = 0x400384
  },
  l_direct_opencount = 1,
  l_type = lt_executable,
  l_dt_relr_ref = 0,
  l_relocated = 1,
  l_init_called = 1,
  l_global = 1,
  l_reserved = 0,
  l_main_map = 0,
  l_visited = 1,
  l_map_used = 0,
  l_map_done = 0,
  l_phdr_allocated = 0,
  l_soname_added = 0,
  l_faked = 0,
  l_need_tls_init = 0,
  l_auditing = 0,
  l_audit_any_plt = 0,
  l_removed = 0,
  l_contiguous = 1,
  l_free_initfini = 0,
  l_ld_readonly = 0,
  l_find_object_processed = 0,
  l_nodelete_active = false,
  l_nodelete_pending = false,
  l_has_jump_slot_reloc = false,
  l_property = lc_property_valid,
  l_x86_feature_1_and = 3,
  l_x86_isa_1_needed = 1,
  l_1_needed = 0,
  l_rpath_dirs = {
    dirs = 0xffffffffffffffff,
    malloced = 0
  },
  l_reloc_result = 0x0,
  l_versyms = 0x400486,
  l_origin = 0x0,
  l_map_start = 4194304,
  l_map_end = 4207472,
  l_scope_mem = {0x7ffff7ffe5d8, 0x0, 0x0, 0x0},
  l_scope_max = 4,
  l_scope = 0x7ffff7ffe680,
  l_local_scope = {0x7ffff7ffe5d8, 0x0},
  l_file_id = {
    dev = 0,
    ino = 0
  },
  l_runpath_dirs = {
    dirs = 0xffffffffffffffff,
    malloced = 0
  },
  l_initfini = 0x7ffff7fbb6a0,
  l_reldeps = 0x0,
  l_reldepsmax = 0,
  l_used = 1,
  l_feature_1 = 0,
  l_flags_1 = 0,
  l_flags = 0,
  l_idx = 0,
  l_mach = {
    plt = 0,
    gotplt = 0,
    tlsdesc_table = 0x0
  },
  l_lookup_cache = {
    sym = 0x400418,
    type_class = 2,
    value = 0x7ffff7fbb160,
    ret = 0x7ffff7c12910
  },
  l_tls_initimage = 0x0,
  l_tls_initimage_size = 0,
  l_tls_blocksize = 0,
  l_tls_align = 0,
  l_tls_firstbyte_offset = 0,
  l_tls_offset = 0,
  l_tls_modid = 0,
  l_tls_dtor_count = 0,
  l_relro_addr = 0,
  l_relro_size = 0,
  l_serial = 0
}
```

开pie实例：
```cpp
{
  l_addr = 93824992231424,
  l_name = 0x7ffff7ffe8b8 "",
  l_ld = 0x555555557150,
  l_next = 0x7ffff7ffe8c0,
  l_prev = 0x0,
  l_real = 0x7ffff7ffe2e0,
  l_ns = 0,
  l_libname = 0x7ffff7ffe8a0,
  l_info = {0x0, 0x555555557150, 0x555555557230, 0x555555557220, 0x0, 0x5555555571d0, 0x5555555571e0, 0x555555557260, 
    0x555555557270, 0x555555557280, 0x5555555571f0, 0x555555557200, 0x555555557160, 0x555555557170, 0x0, 0x0, 0x0, 0x0, 0x0, 
    0x0, 0x555555557240, 0x555555557210, 0x0, 0x555555557250, 0x0, 0x555555557180, 0x5555555571a0, 0x555555557190, 
    0x5555555571b0, 0x0 <repeats 13 times>, 0x5555555572b0, 0x5555555572a0, 0x0, 0x0, 0x555555557290, 0x0, 0x5555555572d0, 0x0, 
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5555555572c0, 0x0 <repeats 25 times>, 0x5555555571c0},
  l_phdr = 0x555555554040,
  l_entry = 93824992235648,
  l_phnum = 12,
  l_ldnum = 0,
  l_searchlist = {
    r_list = 0x7ffff7fbb6c0,
    r_nlist = 3
  },
  l_symbolic_searchlist = {
    r_list = 0x7ffff7ffe898,
    r_nlist = 0
  },
  l_loader = 0x0,
  l_versions = 0x7ffff7fbb6e0,
  l_nversions = 4,
  l_nbuckets = 2,
  l_gnu_bitmask_idxbits = 0,
  l_gnu_shift = 6,
  l_gnu_bitmask = 0x555555554388,
  {
    l_gnu_buckets = 0x555555554390,
    l_chain = 0x555555554390
  },
  {
    l_gnu_chain_zero = 0x55555555437c,
    l_buckets = 0x55555555437c
  },
  l_direct_opencount = 1,
  l_type = lt_executable,
  l_dt_relr_ref = 0,
  l_relocated = 1,
  l_init_called = 1,
  l_global = 1,
  l_reserved = 0,
  l_main_map = 0,
  l_visited = 1,
  l_map_used = 0,
  l_map_done = 0,
  l_phdr_allocated = 0,
  l_soname_added = 0,
  l_faked = 0,
  l_need_tls_init = 0,
  l_auditing = 0,
  l_audit_any_plt = 0,
  l_removed = 0,
  l_contiguous = 1,
  l_free_initfini = 0,
  l_ld_readonly = 0,
  l_find_object_processed = 0,
  l_nodelete_active = false,
  l_nodelete_pending = false,
  l_has_jump_slot_reloc = false,
  l_property = lc_property_valid,
  l_x86_feature_1_and = 3,
  l_x86_isa_1_needed = 1,
  l_1_needed = 0,
  l_rpath_dirs = {
    dirs = 0xffffffffffffffff,
    malloced = 0
  },
  l_reloc_result = 0x0,
  l_versyms = 0x555555554514,
  l_origin = 0x0,
  l_map_start = 93824992231424,
  l_map_end = 93824992244640,
  l_scope_mem = {0x7ffff7ffe5d8, 0x0, 0x0, 0x0},
  l_scope_max = 4,
  l_scope = 0x7ffff7ffe680,
  l_local_scope = {0x7ffff7ffe5d8, 0x0},
  l_file_id = {
    dev = 0,
    ino = 0
  },
  l_runpath_dirs = {
    dirs = 0xffffffffffffffff,
    malloced = 0
  },
  l_initfini = 0x7ffff7fbb6a0,
  l_reldeps = 0x0,
  l_reldepsmax = 0,
  l_used = 1,
  l_feature_1 = 0,
  l_flags_1 = 134217728,
  l_flags = 0,
  l_idx = 0,
  l_mach = {
    plt = 0,
    gotplt = 0,
    tlsdesc_table = 0x0
  },
  l_lookup_cache = {
    sym = 0x555555554448,
    type_class = 2,
    value = 0x7ffff7fbb160,
    ret = 0x7ffff7c12910
  },
  l_tls_initimage = 0x0,
  l_tls_initimage_size = 0,
  l_tls_blocksize = 0,
  l_tls_align = 0,
  l_tls_firstbyte_offset = 0,
  l_tls_offset = 0,
  l_tls_modid = 0,
  l_tls_dtor_count = 0,
  l_relro_addr = 0,
  l_relro_size = 0,
  l_serial = 0
}
pwndbg> p /x 93824992231424
$5 = 0x555555554000

```


# 宏


- `ELFW(` 是 glibc / ELF 代码里常见的宏，用来根据当前平台自动选择 **32 位 ELF 类型/宏** 或 **64 位 ELF 类型/宏**。

- 找 .dynamic 中的 tab 的地址
```cpp
/*找 .dynamic 中的 tab 的地址*/
#define D_PTR(map, i) \
  ((map)->i->d_un.d_ptr + (dl_relocate_ld (map) ? 0 : (map)->l_addr))

/* Return true if dynamic section in the shared library L should be
   relocated.  */
   /*判断是否开启pie*/
static inline bool
dl_relocate_ld (const struct link_map *l)
{
  /* Don't relocate dynamic section if it is readonly  */
  return !(l->l_ld_readonly || DL_RO_DYN_SECTION);
}

/*·.dynamic` 段里的 `Elf64_Dyn` 结构体*/
  typedef struct {
    Elf64_Sxword d_tag;
    union {
        Elf64_Xword d_val;
        Elf64_Addr  d_ptr;
    } d_un;
} Elf64_Dyn;
```

- 类型定义，用于定义需要绑定的函数所在的`link_map`
```cpp
typedef struct link_map *lookup_t;
```

- 处理偏移参数（参数从0开始，`.rela.plt`、`.rela.dyn`的参数分开计算）
```cpp
/*把 PLT 传给动态链接器的参数 `pltn` 转换成 `.rel.plt` / `.rela.plt` 重定位表里的 字节偏移*/
/*这里直接返回偏移，常规架构所传参数就是其在 tab 中的字节偏移*/
static inline uintptr_t
reloc_offset (uintptr_t plt0, uintptr_t pltn)
{
  return pltn;
}
```




# 函数

## `SYMBOL_ADDRESS(map, ref, map_set)`

 * 计算符号 ref 的运行时地址。
 
 * - 如果 ref == NULL，返回 0；
 * - 如果 ref 是 SHN_ABS 绝对符号(st_shndx == SHN_ABS)，直接返回`st_value`；
 * - 否则使用 map->l_addr 作为模块基址，加上 ref->st_value（`st_value + l_addr`）；
 * - map_set 为 true 时，表示调用者保证 map 有效，不额外检查 map 是否为 NULL。

## `elf_machine_fixup_plt`

```cpp
static inline ElfW(Addr)
elf_machine_fixup_plt (struct link_map *map, lookup_t t,
                       const ElfW(Sym) *refsym, const ElfW(Sym) *sym,
                       const ElfW(Rela) *reloc,
                       ElfW(Addr) *reloc_addr, ElfW(Addr) value)
{
  return *reloc_addr = value;
}
```


## `_dl_fixup()`

```cpp
_dl_fixup (
# ifdef ELF_MACHINE_RUNTIME_FIXUP_ARGS
	   ELF_MACHINE_RUNTIME_FIXUP_ARGS,
# endif
	   struct link_map *l, ElW(Word) reloc_arg)//    (link_map,offset)
{ 
 
  /*#define D_PTR(map, i) \       D_PTR是一个宏定义，用于通过linkmap寻址 glibc/sysdeps/generic/ldsodefs.h
  ((map)->i->d_un.d_ptr + (dl_relocate_ld (map) ? 0 : (map)->l_addr))*/
  //ELFW宏用来拼接字符串，在这里实际上是为了自动兼容32和64位,Elf32_Sym或Elf64_Sym
  const ElfW(Sym) *const symtab
    = (const void *) D_PTR (l, l_info[DT_SYMTAB]);
  const char *strtab = (const void *) D_PTR (l, l_info[DT_STRTAB]);
 
  const uintptr_t pltgot = (uintptr_t) D_PTR (l, l_info[DT_PLTGOT]);
  
  //通过link_map结构获取重定位表.rel.plt中所求函数的重定位项的地址
    //reloc_offset为所解析函数的重定位项在重定位表.rel.plt中的偏移
  const PLTREL *const reloc
    = (const void *) (D_PTR (l, l_info[DT_JMPREL])
		      + reloc_offset (pltgot, reloc_arg));
 
  //求出所求函数在动态链接符号表.dynsym中对应符号项的地址
  const ElfW(Sym) *sym = &symtab[ELFW(R_SYM) (reloc->r_info)];
  const ElfW(Sym) *refsym = sym;
 
  //l_addr是共享库或可执行文件加载基址，rel_addr是重定位需要修改内容的地址，也就是.got.plt中所求函数对应项
    //r_offset为相对虚拟地址，rel_addr为虚拟地址
  void *const rel_addr = (void *)(l->l_addr + reloc->r_offset);
 
  lookup_t result; //查找函数的结果，其为定义函数的共享对象的加载基地址，为 link_map 类型
  DL_FIXUP_VALUE_TYPE value;  //DL_FIXUP_VALUE_TYPE是fixup/profile_fixup返回值的类型。用于保存函数的真实地址。
 
  /* Sanity check that we're really looking at a PLT relocation.  */
   /* 安全性检查，我们需要确定它是一个PLT的重定位项 */  //r_info的低8位为重定位类型设置为7意味着它是一个PLT的重定位项
  assert (ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT);
 
   /* Look up the target symbol.  If the normal lookup rules are not
      used don't look in the global scope.  */
      /* 查找目标符号。如果未使用常规查找规则，则不要在全局范围内查找。 */
  /*判断是否是受保护符号*/
  if (__builtin_expect (ELFW(ST_VISIBILITY) (sym->st_other), 0) == 0)    //if(sym->st_other==0)
    {
      const struct r_found_version *version = NULL;
	 /*确认elf 的 link_map 中存有版本编号*/
	  if (l->l_info[VERSYMIDX (DT_VERSYM)] != NULL)
		{
		/*处理偏移成对应版本的偏移*/
		  const ElfW(Half) *vernum = (const void *) D_PTR (l, l_info[VERSYMIDX (DT_VERSYM)]);
		  ElfW(Half) ndx = vernum[ELFW(R_SYM) (reloc->r_info)] & 0x7fff;
		  version = &l->l_versions[ndx];
		  if (version->hash == 0)
		    version = NULL;
		}
 
      /* We need to keep the scope around so do some locking.  This is
	 not necessary for objects which cannot be unloaded or when
	 we are not using any threads (yet).  */
   /* 我们需要保持范围不变，因此需要进行一些锁定。 对于无法卸载的对象或单线程的对象，这不是必需的。  */
      int flags = DL_LOOKUP_ADD_DEPENDENCY;
      if (!RTLD_SINGLE_THREAD_P)
		{
		  THREAD_GSCOPE_SET_FLAG ();
		  flags |= DL_LOOKUP_GSCOPE_LOCK;
		}
 
#ifdef RTLD_ENABLE_FOREIGN_CALL
      RTLD_ENABLE_FOREIGN_CALL;
#endif
//strtab + sym->st_name为所解析函数的符号在字符串表中的地址，result为定义函数的共享对象的加载基地址即libc基地址
        //_dl_lookup_symbol_x的功能是在加载的共享对象的符号表中搜索符号的定义，其参数也许带有该符号的版本。
      result = _dl_lookup_symbol_x (strtab + sym->st_name, l, &sym, l->l_scope,version, ELF_RTYPE_CLASS_PLT, flags, NULL);
 
      /* We are done with the global scope.  */
      /* 我们已经完成了全局范围的工作。 */
      if (!RTLD_SINGLE_THREAD_P)
		THREAD_GSCOPE_RESET_FLAG ();
 
#ifdef RTLD_FINALIZE_FOREIGN_CALL
	      RTLD_FINALIZE_FOREIGN_CALL;
#endif
/* 当前result包含定义sym的共享对象的加载基地址（或link map）。 现在添加符号偏移量。 */
        //value为所求函数的真实内存地址
        //SYMBOL_ADDRESS(map, ref, map_set)：如果ref不是NULL，则使用映射MAP中的基地址来计算符号引用的地址。 
        //map_set 为 true 时，表示调用者保证 map 有效，不额外检查 map 是否为 NULL。
 
      /* Currently result contains the base load address (or link map)
	 of the object that defines sym.  Now add in the symbol
	 offset.  */
	   value = DL_FIXUP_MAKE_VALUE (result, SYMBOL_ADDRESS (result, sym, false));
    }
  else//未使用常规查找规则
    {/*我们已经找到符号了。模块(以及它的负载)
地址)也是已知的。* /
      /* We already found the symbol.  The module (and therefore its load
	 address) is also known.  */
      value = DL_FIXUP_MAKE_VALUE (l, SYMBOL_ADDRESS (l, sym, true));
      result = l;
    }
 
  /* And now perhaps the relocation addend.  */
  //现在也许是重新定位的加法。对不同架构返回不同的处理函数。
  //elf_machine_plt_value返回PLT重定位的最终值。在x86-64上JUMP_SLOT重定位忽略addend。
  value = elf_machine_plt_value (l, reloc, value);
 
  if (sym != NULL
      && __builtin_expect (ELFW(ST_TYPE) (sym->st_info) == STT_GNU_IFUNC, 0))
    value = elf_ifunc_invoke (DL_FIXUP_VALUE_ADDR (value));
 
##ifdef SHARED
  /* 审计检查点：当前产生了一个新的符号绑定。
     给审计库一个机会，让它可以修改绑定得到的地址 value，
     并告知动态链接器后续是否还需要继续审计。

     只有存在提供 la_symbind 回调函数的审计模块时，
     l_reloc_result 才会被分配。 */
  if (l->l_reloc_result != NULL)
    {
      /* 这是数组中的一个地址，用于保存之前重定位得到的结果。 */
      struct reloc_result *reloc_result
        = &l->l_reloc_result[reloc_index (pltgot, reloc_arg, sizeof (PLTREL))];

      unsigned int init = atomic_load_acquire (&reloc_result->init);

      if (init == 0)
        {
          _dl_audit_symbind (l, reloc_result, sym, &value, result);

          /* 保存本次结果，供后续再次执行时使用。 */
          if (__glibc_likely (! GLRO(dl_bind_not)))
            {
              reloc_result->addr = value;

              /* 保证前面的所有写操作都完成后，
                 再更新 init。详见下面的并发说明。 */
              atomic_store_release (&reloc_result->init, 1);
            }
        }
      else
        value = reloc_result->addr;
    }
#endif
 
  /* Finally, fix up the plt itself.  */
  /* 最后，修复PLT本身。 */
  if (__glibc_unlikely (GLRO(dl_bind_not)))
    return value;
//向所查找函数对应的GOT表中填写找到的函数的真实地址。
  return elf_machine_fixup_plt (l, result, refsym, sym, reloc, rel_addr, value);
}
```

## 执行流

elf中的link_map与`_dl_runtime_resolve_xsavec()`指针在`.bss`段中`.got`段开头

*下图省略所有被调用函数，调试模块，部分结构体，绿色为常规执行（判断返回为 ture），红色为可控执行流，蓝色为相加*
![IMG-20260430134356523](/assets/ctf/d45534460fda50ccceb1.webp)

# 利用思路

该方法最大的作用在无法泄露libc时可以调用libc中的函数，**其本质是向一个地址，写入一个值**，而这两个部分都可以在一定程度上被控制：

```cpp
*(l_addr_para + r_offset) = l_addr_choi + st_value
```

该利用并不只限制于覆盖got表段，可以覆盖**任意位置可被覆盖（可写）的能被调用的函数指针**，然后**调用 libc 任意位置的代码片段**（内核未开启ibt保护时）。

## 触发

汇编层面，延迟绑定第一次执行函数执行流如下：
```asm
call func@plt

.plt
jmp func@got

.got
push rela_off
jmp text_near

.text
push qword ptr [link_map_addr.got]
jmp qword ptr [_dl_runtime_resolve_xsavec.got]
```

所以，有如下两种触发方式：

- 用任意写覆盖部分指针、偏移，或进行伪造，利用未加载的函数触发
- 通过栈溢出，劫持执行流，在栈上布置两个指针（可以为真实指针或伪造的结构体指针）、返回地址，模拟执行

**触发前栈布局：**
```
   <- rsp
...
saved rbp   <- rbp
_dl_runtime_resolve_xsavec()
rela_off             
link_map_ptr
ret_addr
```

**出发后栈布局：**
```
rela_off              <-rsp
link_map_ptr
ret_addr
```

## NO RELRO

该模式下，上如所有表段中的结构体可写

有任意写可以根据以上执行流，覆盖任意偏移进行利用；
只有溢出，需泄露pie或无pie，泄露 ld 地址，伪造`link_map`。

这种情况下思路比较广泛，只需知道调用过程、各结构体位置，就可以根据具体情况利用。

## Partial RELRO

该模式下，所有表段不可被写，但是.bss段的`link_map`、`_dl_runtime_resolve_xsavec()`的指针可以被写

有任意写，可以覆盖`.bss`段指针，伪造`link_map`；
只有溢出，需泄露pie或无pie，需泄露 ld 地址，伪造`link_map`。


**伪造`link_map`：**

根据上面的执行流，可以有如下的利用思路：
![IMG-20260430145549670](/assets/ctf/9421fa2aefd7887a5f90.webp)

通过将`sym`结构体伪造在got表附近，使`st_value`与`st_other`命中合适位置

```cpp
*(l_addr_para + r_offset) = l_addr_choi + st_value
```

- 使`st_other`非 0 ，将执行流导向非常规流程（红色）
- 使`vt_value`为已经被写过的 libc 函数入口地址，此时`link_map`为通过参数传入的`link_map`，通过`l_addr`调整偏移，到目标代码段地址

- 由于调整了传入的`link_map`的`l_addr`，所以在写`rela`结构体时，需将`r_offset`设置为`target - l_addr`

以上思路，只是需要一个共享器内的地址，以及其版本，就能通过偏移计算调用共享器中的函数，调用 ld 的思路相同。

## FULL_RELERO

当开启`FULL_RELERO`时，整个`GOT`表将标记为`read-only`，并且所有的外部引用变量/函数都将在程序装载时由动态链接器解析完成。

此时`.got.plt`表中的第二项 表项`GOT[1]`装载的`link_map`地址 以及第二项 表项`GOT[2]`装载的`dl_runtime_resolve`函数地址将是0。

所以此时，利用方式与上面完全一样，仍然可以在`.got`表进行伪造，只是很难泄露 ld 的地址。

下面介绍一个结构体：
```cpp
/*
   运行时动态链接器使用的传统 rendezvous 结构，
   用于向调试器传递共享对象加载情况的详细信息。
 */
struct r_debug
{
  /* 该协议的版本号。它应该大于 0。 */
  int r_version;

  struct link_map *r_map;  /* 已加载对象链表的头指针。 */

  /*
     这是运行时链接器内部某个函数的地址。

     当链接器开始映射一个库、取消映射一个库时，
     以及当这种映射变化完成时，
     这个函数总是会被调用。

     如果调试器想要感知共享对象映射关系的变化，
     可以在这个地址处设置断点。
   */
  ElfW(Addr) r_brk;

  enum
  {
    /*
       当调用 `r_brk` 地址处的函数时，
       这个状态值描述当前正在发生的映射变化。
     */
    RT_CONSISTENT,  /* 映射变化已经完成。 */
    RT_ADD,         /* 开始添加一个新对象。 */
    RT_DELETE       /* 开始移除一个对象映射。 */
  } r_state;

  ElfW(Addr) r_ldbase;  /* 链接器自身被加载到的基地址。 */
};
```

是一个用于向调试器传递信息的结构体，也被定义在`.synamic`中：
```cpp
#define DT_DEBUG 21 /* For debugging; unspecified */
```

该结构体中有`link_map`的地址，此时，通过多次访问该`link_map`的双链表，找到另一非`FULL_RELERO`的程序，读取其got表中的地址就能找到`dl_runtime_resolve`的地址。

*注，`link_map`在 ld 的堆区中，其与 ld 中的函数相对偏移并不固定*
{% endraw %}
