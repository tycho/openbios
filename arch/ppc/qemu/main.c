/*
 *   Creation Date: <2002/10/02 22:24:24 samuel>
 *   Time-stamp: <2004/03/27 01:57:55 samuel>
 *
 *	<main.c>
 *
 *
 *
 *   Copyright (C) 2002, 2003, 2004 Samuel Rydh (samuel@ibrium.se)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation
 *
 */

#include "openbios/config.h"
#include "openbios/bindings.h"
#include "openbios/elfload.h"
#include "openbios/nvram.h"
#include "libc/diskio.h"
#include "libc/vsprintf.h"
#include "kernel.h"
#include "ofmem.h"
#define NO_QEMU_PROTOS
#include "openbios/fw_cfg.h"

//#define DEBUG_QEMU

#ifdef DEBUG_QEMU
#define SUBSYS_DPRINTF(subsys, fmt, args...) \
    do { printk("%s - %s: " fmt, subsys, __func__ , ##args); } while (0)
#else
#define SUBSYS_DPRINTF(subsys, fmt, args...) \
    do { } while (0)
#endif
#define CHRP_DPRINTF(fmt, args...) SUBSYS_DPRINTF("CHRP", fmt, ##args)
#define ELF_DPRINTF(fmt, args...) SUBSYS_DPRINTF("ELF", fmt, ##args)
#define XCOFF_DPRINTF(fmt, args...) SUBSYS_DPRINTF("XCOFF", fmt, ##args)
#define YABOOT_DPRINTF(fmt, args...) SUBSYS_DPRINTF("YABOOT", fmt, ##args)


/* XCOFF executable loader */
typedef struct COFF_filehdr_t {
    uint16_t f_magic;	/* magic number			*/
    uint16_t f_nscns;	/* number of sections		*/
    uint32_t f_timdat;	/* time & date stamp		*/
    uint32_t f_symptr;	/* file pointer to symtab	*/
    uint32_t f_nsyms;	/* number of symtab entries	*/
    uint16_t f_opthdr;	/* sizeof(optional hdr)		*/
    uint16_t f_flags;	/* flags			*/
} COFF_filehdr_t;

/* IBM RS/6000 */
#define U802WRMAGIC     0x02DA    /* writeable text segments **chh**      */
#define U802ROMAGIC     0x02DF    /* readonly sharable text segments      */
#define U802TOCMAGIC    0x02E1    /* readonly text segments and TOC       */
#define U802TOMAGIC     0x01DF

/*
 *   Bits for f_flags:
 *
 *	F_RELFLG	relocation info stripped from file
 *	F_EXEC		file is executable  (i.e. no unresolved external
 *			references)
 *	F_LNNO		line numbers stripped from file
 *	F_LSYMS		local symbols stripped from file
 *	F_MINMAL	this is a minimal object file (".m") output of fextract
 *	F_UPDATE	this is a fully bound update file, output of ogen
 *	F_SWABD		this file has had its bytes swabbed (in names)
 *	F_AR16WR	this file has the byte ordering of an AR16WR
 *			(e.g. 11/70) machine
 *	F_AR32WR	this file has the byte ordering of an AR32WR machine
 *			(e.g. vax and iNTEL 386)
 *	F_AR32W		this file has the byte ordering of an AR32W machine
 *			(e.g. 3b,maxi)
 *	F_PATCH		file contains "patch" list in optional header
 *	F_NODF		(minimal file only) no decision functions for
 *			replaced functions
 */

#define  COFF_F_RELFLG		0000001
#define  COFF_F_EXEC		0000002
#define  COFF_F_LNNO		0000004
#define  COFF_F_LSYMS		0000010
#define  COFF_F_MINMAL		0000020
#define  COFF_F_UPDATE		0000040
#define  COFF_F_SWABD		0000100
#define  COFF_F_AR16WR		0000200
#define  COFF_F_AR32WR		0000400
#define  COFF_F_AR32W		0001000
#define  COFF_F_PATCH		0002000
#define  COFF_F_NODF		0002000

typedef struct COFF_aouthdr_t {
    uint16_t magic;      /* type of file			  */
    uint16_t vstamp;     /* version stamp		          */
    uint32_t tsize;      /* text size in bytes, padded to FW bdry */
    uint32_t dsize;      /* initialized data "  "	          */
    uint32_t bsize;      /* uninitialized data "   "	          */
    uint32_t entry;	 /* entry pt.			          */
    uint32_t text_start; /* base of text used for this file       */
    uint32_t data_start; /* base of data used for this file       */
    uint32_t o_toc;	 /* address of TOC                        */
    uint16_t o_snentry;	 /* section number of entry point         */
    uint16_t o_sntext;	 /* section number of .text section       */
    uint16_t o_sndata;	 /* section number of .data section       */
    uint16_t o_sntoc;	 /* section number of TOC                 */
    uint16_t o_snloader; /* section number of .loader section     */
    uint16_t o_snbss;	 /* section number of .bss section        */
    uint16_t o_algntext; /* .text alignment                       */
    uint16_t o_algndata; /* .data alignment                       */
    uint16_t o_modtype;	 /* module type (??)                      */
    uint16_t o_cputype;	 /* cpu type                              */
    uint32_t o_maxstack; /* max stack size (??)                   */
    uint32_t o_maxdata;	 /* max data size (??)                    */
    char o_resv2[12];	 /* reserved                              */
} COFF_aouthdr_t;

#define AOUT_MAGIC	0x010b

typedef struct COFF_scnhdr_t {
    char s_name[8];	/* section name			    */
    uint32_t s_paddr;	/* physical address, aliased s_nlib */
    uint32_t s_vaddr;	/* virtual address		    */
    uint32_t s_size;	/* section size			    */
    uint32_t s_scnptr;	/* file ptr to raw data for section */
    uint32_t s_relptr;	/* file ptr to relocation	    */
    uint32_t s_lnnoptr;	/* file ptr to line numbers	    */
    uint16_t s_nreloc;	/* number of relocation entries	    */
    uint16_t s_nlnno;	/* number of line number entries    */
    uint32_t s_flags;	/* flags			    */
} COFF_scnhdr_t;


static int
load_xcoff(int fd, char **dest, char **entrypt, char **end)
{
    COFF_filehdr_t fhdr;
    COFF_aouthdr_t ahdr;
    COFF_scnhdr_t shdr;
    char *first, *last;
    uint64_t loffset, ept_offset;
    uint32_t offset, actual_entry;
    int i;

    XCOFF_DPRINTF("Loading '%s'\n", get_file_path(fd));

    loffset = tell(fd);

    if (read_io(fd, &fhdr, sizeof(COFF_filehdr_t)) < 0) {
        XCOFF_DPRINTF("Cannot load first bloc of file...\n");
        return -1;
    }
    if (fhdr.f_magic != U802WRMAGIC && fhdr.f_magic != U802ROMAGIC &&
        fhdr.f_magic != U802TOCMAGIC && fhdr.f_magic != U802TOMAGIC) {
        XCOFF_DPRINTF("Not a XCOFF file %02x\n", fhdr.f_magic);
        return -2;
    }
    if (fhdr.f_magic != 0x01DF && (fhdr.f_flags & COFF_F_EXEC) == 0) {
        XCOFF_DPRINTF("Not an executable XCOFF file %02x\n", fhdr.f_flags);
        return -2;
    }
    if (fhdr.f_opthdr != sizeof(COFF_aouthdr_t)) {
        XCOFF_DPRINTF("AOUT optional error size missmactch in XCOFF file\n");
        return -2;
    }
    if (read_io(fd, &ahdr, sizeof(COFF_aouthdr_t)) < 0) {
        XCOFF_DPRINTF("Cannot load XCOFF AOUT header...\n");
        return -1;
    }
    if (ahdr.magic != AOUT_MAGIC) {
        XCOFF_DPRINTF("Invalid AOUT optional header\n");
        return -2;
    }

    *entrypt = (char *)ahdr.entry;
    last = NULL;
    first = last - 4;
    offset = sizeof(COFF_filehdr_t) + sizeof(COFF_aouthdr_t);
    XCOFF_DPRINTF("XCOFF file with %d sections\n", fhdr.f_nscns);
    for (i = 0; i < fhdr.f_nscns; i++) {
        XCOFF_DPRINTF("Read next header (%0x)\n", offset);
        seek_io(fd, offset + loffset);
        if (read_io(fd, &shdr, sizeof(COFF_scnhdr_t)) < 0) {
            XCOFF_DPRINTF("Cannot load section header %d...\n", i);
            return -1;
        }
	if (strcmp(shdr.s_name, ".text") == 0 ||
            strcmp(shdr.s_name, ".data") == 0) {
            if ((char *)shdr.s_vaddr < first)
                first = (char *)shdr.s_vaddr;
            if ((char *)shdr.s_vaddr > last)
                last = (char *)shdr.s_vaddr;
            XCOFF_DPRINTF("Load '%s' section from %0x %0x to %0x (%0x)\n",
                    shdr.s_name, offset, shdr.s_scnptr,
                    shdr.s_vaddr, shdr.s_size);

            if (((ulong)(*entrypt) >= shdr.s_vaddr) &&
                ((ulong)(*entrypt) < shdr.s_vaddr + shdr.s_size)) {
                ept_offset = (ulong)(*entrypt) - shdr.s_vaddr + shdr.s_scnptr;
                XCOFF_DPRINTF("Found entry point offset in '%s': %llx\n",
                    shdr.s_name, ept_offset);
            }

            seek_io(fd, shdr.s_scnptr + loffset);

            if (read_io(fd, (void *)shdr.s_vaddr, shdr.s_size) < 0) {
                XCOFF_DPRINTF("Cannot load section %d...\n", i);
                return -1;
            }
        } else if (strcmp(shdr.s_name, ".bss") == 0) {
            if ((char *)shdr.s_vaddr < first)
                first = (char *)shdr.s_vaddr;
            if ((char *)shdr.s_vaddr > last)
                last = (char *)shdr.s_vaddr;
            XCOFF_DPRINTF("Erase '%s' section at %0x size: %0x\n",
                    shdr.s_name, shdr.s_vaddr, shdr.s_size);
            memset((void *)shdr.s_vaddr, 0, shdr.s_size);
        } else {
            XCOFF_DPRINTF("Skip '%s' section\n", shdr.s_name);
        }
        offset += sizeof(COFF_scnhdr_t);
    }
    *dest = first;
    *end = last;

    seek_io(fd, loffset + ept_offset);
    read_io(fd, &actual_entry, 4);
    *entrypt = (char*)actual_entry;
    XCOFF_DPRINTF("Found actual entry point: %08x\n",
        actual_entry);

    return 0;
}

static void
transfer_control_to_elf( ulong elf_entry )
{
	ELF_DPRINTF("Starting ELF boot loader\n");
        call_elf( 0, 0, elf_entry );

	fatal_error("call_elf returned unexpectedly\n");
}

static int
load_elf_rom( ulong *elf_entry, int fd )
{
	int i, lszz_offs, elf_offs;
        char *addr;
	Elf_ehdr ehdr;
	Elf_phdr *phdr;
	size_t s;

	ELF_DPRINTF("Loading '%s' from '%s'\n", get_file_path(fd),
	       get_volume_name(fd) );

	/* the ELF-image (usually) starts at offset 0x4000 */
	if( (elf_offs=find_elf(fd)) < 0 ) {
                ELF_DPRINTF("----> %s is not an ELF image\n", get_file_path(fd));
		return -1;
	}
	if( !(phdr=elf_readhdrs(fd, elf_offs, &ehdr)) ) {
		ELF_DPRINTF("elf_readhdrs failed\n");
		return -1;
	}

	*elf_entry = ehdr.e_entry;

	/* load segments. Compressed ROM-image assumed to be located immediately
	 * after the last segment */
	lszz_offs = elf_offs;
	for( i=0; i<ehdr.e_phnum; i++ ) {
		/* p_memsz, p_flags */
		s = MIN( phdr[i].p_filesz, phdr[i].p_memsz );
		seek_io( fd, elf_offs + phdr[i].p_offset );

		ELF_DPRINTF("filesz: %08lX memsz: %08lX p_offset: %08lX p_vaddr %08lX\n",
                   (ulong)phdr[i].p_filesz, (ulong)phdr[i].p_memsz, (ulong)phdr[i].p_offset,
                   (ulong)phdr[i].p_vaddr );

		if( phdr[i].p_vaddr != phdr[i].p_paddr )
			ELF_DPRINTF("WARNING: ELF segment virtual addr != physical addr\n");
		lszz_offs = MAX( lszz_offs, elf_offs + phdr[i].p_offset + phdr[i].p_filesz );
		if( !s )
			continue;
		if( ofmem_claim( phdr[i].p_vaddr, phdr[i].p_memsz, 0 ) == -1 )
			fatal_error("Claim failed!\n");

		addr = (char*)phdr[i].p_vaddr;
		if( read_io(fd, addr, s) != s ) {
			ELF_DPRINTF("read failed\n");
			return -1;
		}

		flush_icache_range( addr, addr+s );

		ELF_DPRINTF("ELF ROM-section loaded at %08lX (size %08lX)\n",
			    (ulong)phdr[i].p_vaddr, (ulong)phdr[i].p_memsz );
	}
	free( phdr );
	return lszz_offs;
}

static char *
get_device( const char *path )
{
	int i;
	static char buf[1024];

	for (i = 0; i < sizeof(buf) && path[i] && path[i] != ':'; i++)
		buf[i] = path[i];
	buf[i] = 0;

	return buf;
}

static int
get_partition( const char *path )
{
	while ( *path && *path != ':' )
		path++;

	if (!*path)
		return 0;
	path++;

	if (!strchr(path, ','))	/* check if there is a ',' */
		return 0;

	return atol(path);
}

static char *
get_filename( const char * path , char **dirname)
{
	static char buf[1024];
	char *filename;

	while ( *path && *path != ':' )
		path++;

	if (!*path) {
		*dirname = NULL;
		return NULL;
	}
	path++;

	while ( *path && isdigit(*path) )
		path++;

	if (*path == ',')
		path++;

	strncpy(buf, path, sizeof(buf));
	buf[sizeof(buf) - 1] = 0;

	filename = strrchr(buf, '\\');
	if (filename) {
		*dirname = buf;
		(*filename++) = 0;
	} else {
		*dirname = NULL;
		filename = buf;
	}

	return filename;
}

static void
encode_bootpath( const char *spec, const char *args )
{
	char path[1024];
	phandle_t chosen_ph = find_dev("/chosen");
	char *filename, *directory;

	filename = get_filename(spec, &directory);
	snprintf(path, sizeof(path), "%s:%d,%s\\%s", get_device(spec),
		 get_partition(spec), directory, filename);

        ELF_DPRINTF("bootpath %s bootargs %s\n", path, args);
	set_property( chosen_ph, "bootpath", path, strlen(spec)+1 );
	if (args)
		set_property( chosen_ph, "bootargs", args, strlen(args)+1 );
}

/************************************************************************/
/*	qemu booting							*/
/************************************************************************/
static void
try_path(const char *path, const char *param)
{
    ulong elf_entry;
    int fd, ret;

    ELF_DPRINTF("Trying %s %s\n", path, param);
    if ((fd = open_io(path)) == -1) {
        ELF_DPRINTF("Can't open %s\n", path);
        return;
    }
    ret = load_elf_rom( &elf_entry, fd );
    if (ret < 0)
        return;
    close_io( fd );
    encode_bootpath( path, param );

    update_nvram();
    ELF_DPRINTF("Transfering control to %s %s\n",
                path, param);
    transfer_control_to_elf( elf_entry );
    /* won't come here */
}

/*
  Parse SGML structure like:
  <chrp-boot>
  <description>Debian/GNU Linux Installation on IBM CHRP hardware</description>
  <os-name>Debian/GNU Linux for PowerPC</os-name>
  <boot-script>boot &device;:\install\yaboot</boot-script>
  <icon size=64,64 color-space=3,3,2>

  CHRP system bindings are described at:
  http://playground.sun.com/1275/bindings/chrp/chrp1_7a.ps
*/
static void
try_chrp_script(const char *of_path, const char *param, const char *script_path)
{
    int fd, len, tag, taglen, script, scriptlen, entity;
    char tagbuf[256], bootscript[256], c;
    char *device, *filename, *directory;
    void *dest, *entrypt, *end;
    int partition;

    device = get_device(of_path);
    partition = get_partition(of_path);
    filename = get_filename(of_path, &directory);

    /* read boot script */

    snprintf(bootscript, sizeof(bootscript), "%s:%d,%s",
             device, partition, script_path);

    CHRP_DPRINTF("Trying %s\n", bootscript);
    if ((fd = open_io(bootscript)) == -1) {
        ELF_DPRINTF("Can't open %s\n", bootscript);
        return;
    }
    len = read_io(fd, tagbuf, 11);
    tagbuf[11] = '\0';
    if (len < 0 || strcasecmp(tagbuf, "<chrp-boot>") != 0)
        goto badf;

    tag = 0;
    taglen = 0;
    script = 0;
    scriptlen = 0;
    entity = 0;
    do {
        len = read_io(fd, &c, 1);
        if (len < 0)
            goto badf;
        if (c == '<') {
            script = 0;
            tag = 1;
            taglen = 0;
        } else if (c == '>') {
            tag = 0;
            tagbuf[taglen] = '\0';
            if (strcasecmp(tagbuf, "boot-script") == 0)
                script = 1;
            else if (strcasecmp(tagbuf, "/boot-script") == 0)
                bootscript[scriptlen] = '\0';
            else if (strcasecmp(tagbuf, "/chrp-boot") == 0)
		break;
        } else if (tag && taglen < sizeof(tagbuf)) {
            tagbuf[taglen++] = c;
        } else if (script && c == '&') {
            entity = 1;
            taglen = 0;
        } else if (entity && c ==';') {
            entity = 0;
            tagbuf[taglen] = '\0';
            if (strcasecmp(tagbuf, "device") == 0) {
                strcpy(bootscript + scriptlen, device);
                scriptlen += strlen(device);
            } else if (strcasecmp(tagbuf, "partition") == 0) {
		sprintf(bootscript + scriptlen, "%d", partition);
                scriptlen = strlen(bootscript);
            } else if (strcasecmp(tagbuf, "directory") == 0) {
                strcpy(bootscript + scriptlen, directory);
                scriptlen += strlen(directory);
            } else if (strcasecmp(tagbuf, "filename") == 0) {
                strcpy(bootscript + scriptlen, filename);
                scriptlen += strlen(filename);
            } else if (strcasecmp(tagbuf, "full-path") == 0) {
                strcpy(bootscript + scriptlen, of_path);
                scriptlen += strlen(of_path);
            } else { /* unknown, keep it */
                bootscript[scriptlen] = '&';
                strcpy(bootscript + scriptlen + 1, tagbuf);
                scriptlen += taglen + 1;
                bootscript[scriptlen] = ';';
                scriptlen++;
            }
        } else if (entity && taglen < sizeof(tagbuf)) {
            tagbuf[taglen++] = c;
        } else if (script && scriptlen < sizeof(bootscript)) {
            bootscript[scriptlen++] = c;
        }
    } while (1);

    CHRP_DPRINTF("got bootscript %s\n", bootscript);

    encode_bootpath(of_path, param);

    feval(bootscript);

    /*
        check for an embedded XCOFF binary

        XXX: This is a hack which can be removed when the Forth
        interpreter properly handles CHRP scripts used by Mac OS X.
     */

    /* eat newline */
    if (read_io(fd, tagbuf, 1) < 0)
        goto badf;

    /* eat '\x04', ASCII 'end-of-transmission' */
    if (read_io(fd, tagbuf, 1) < 0)
        goto badf;

    /* next bytes should be XCOFF magic */
    dest = entrypt = end = NULL;
    if(load_xcoff(fd, (void*)&dest, (void*)&entrypt, (void*)&end) < 0)
        goto badf;

    transfer_control_to_elf((ulong)entrypt);

 badf:
    close_io( fd );
}

#define QUIK_SECOND_BASEADDR	0x3e0000
#define QUIK_FIRST_BASEADDR	0x3f4000
#define QUIK_SECOND_SIZE	(QUIK_FIRST_BASEADDR - QUIK_SECOND_BASEADDR)
#define QUIK_FIRST_INFO_OFF	0x2c8

struct first_info {
	char		quik_vers[8];
	int		nblocks;
	int		blocksize;
	unsigned	second_base;
	int		conf_part;
	char		conf_file[32];
	unsigned	blknos[64];
};

static void
quik_startup( void )
{
	int fd;
	int len;
	const char *path = "hd:2";
	union {
		char buffer[1024];
		int first_word;
		struct {
			char pad[QUIK_FIRST_INFO_OFF];
			struct first_info fi;
		} fi;
	} u;
	phandle_t ph;

	if ((fd = open_io(path)) == -1) {
		ELF_DPRINTF("Can't open %s\n", path);
		return;
	}

	seek_io(fd, 0);
	len = read_io(fd, u.buffer, sizeof(u));
	close_io( fd );

	if (len == -1) {
		ELF_DPRINTF("Can't read %s\n", path);
		return;
	}

	/* is it quik ? */

	if (memcmp(u.fi.fi.quik_vers, "QUIK", 4))
		return;

	ph = find_dev("/options");
	set_property(ph, "boot-device", path, strlen(path) + 1);
	ph = find_dev("/chosen");
	set_property(ph, "bootargs", "Linux", 6);

	if( ofmem_claim( QUIK_FIRST_BASEADDR, len, 0 ) == -1 )
		fatal_error("Claim failed!\n");

	memcpy((char*)QUIK_FIRST_BASEADDR, u.buffer, len);

	/* quik fist level doesn't claim second level memory */

	if( ofmem_claim( QUIK_SECOND_BASEADDR, QUIK_SECOND_SIZE, 0 ) == -1 )
		fatal_error("Claim failed!\n");

	call_elf(0, 0, QUIK_FIRST_BASEADDR);

        return;
}

static void
yaboot_startup( void )
{
        static const char * const chrp_paths[] = { "ppc\\bootinfo.txt", "System\\Library\\CoreServices\\BootX" };
        static const char * const elf_paths[] = { "hd:2,\\ofclient", "hd:2,\\yaboot" };
        static const char * const args[] = { "", "conf=hd:2,\\yaboot.conf" };
        char *path = pop_fstr_copy(), *param;
        int i;

	param = strchr(path, ' ');
	if (param) {
		*param = 0;
		param++;
	}

        if (!path) {
            YABOOT_DPRINTF("Entering boot, no path\n");
            push_str("boot-device");
            push_str("/options");
            fword("(find-dev)");
            POP();
            fword("get-package-property");
            if (!POP()) {
                path = pop_fstr_copy();
                param = strchr(path, ' ');
                if (param) {
                    *param = '\0';
                    param++;
                } else {
                    push_str("boot-args");
                    push_str("/options");
                    fword("(find-dev)");
                    POP();
                    fword("get-package-property");
                    POP();
                    param = pop_fstr_copy();
                }
                try_path(path, param);
	        for( i=0; i < sizeof(chrp_paths) / sizeof(chrp_paths[0]); i++ ) {
	            try_chrp_script(path, param, chrp_paths[i]);
	        }
            } else {
                uint16_t boot_device = fw_cfg_read_i16(FW_CFG_BOOT_DEVICE);
                switch (boot_device) {
                case 'c':
                    path = strdup("hd:0");
                    break;
                default:
                case 'd':
                    path = strdup("cd:0");
                    break;
                }
	        for( i=0; i < sizeof(chrp_paths) / sizeof(chrp_paths[0]); i++ ) {
	            try_chrp_script(path, param, chrp_paths[i]);
	        }
            }
        } else {
            YABOOT_DPRINTF("Entering boot, path %s\n", path);
            try_path(path, param);
            for( i=0; i < sizeof(chrp_paths) / sizeof(chrp_paths[0]); i++ ) {
                try_chrp_script(path, param, chrp_paths[i]);
            }
        }
        for( i=0; i < sizeof(elf_paths) / sizeof(elf_paths[0]); i++ ) {
            try_path(elf_paths[i], args[i]);
        }
	printk("*** Boot failure! No secondary bootloader specified ***\n");
}

static void check_preloaded_kernel(void)
{
    unsigned long kernel_image, kernel_size;
    unsigned long initrd_image, initrd_size;
    const char * kernel_cmdline;

    kernel_size = fw_cfg_read_i32(FW_CFG_KERNEL_SIZE);
    if (kernel_size) {
        kernel_image = fw_cfg_read_i32(FW_CFG_KERNEL_ADDR);
        kernel_cmdline = (const char *) fw_cfg_read_i32(FW_CFG_KERNEL_CMDLINE);
        initrd_image = fw_cfg_read_i32(FW_CFG_INITRD_ADDR);
        initrd_size = fw_cfg_read_i32(FW_CFG_INITRD_SIZE);
        printk("[ppc] Kernel already loaded (0x%8.8lx + 0x%8.8lx) "
               "(initrd 0x%8.8lx + 0x%8.8lx)\n",
               kernel_image, kernel_size, initrd_image, initrd_size);
        if (kernel_cmdline) {
               phandle_t ph;
	       printk("[ppc] Kernel command line: %s\n", kernel_cmdline);
	       ph = find_dev("/chosen");
               set_property(ph, "bootargs", strdup(kernel_cmdline), strlen(kernel_cmdline) + 1);
        }
        call_elf(initrd_image, initrd_size, kernel_image);
    }
}

/************************************************************************/
/*	entry								*/
/************************************************************************/

void
boot( void )
{
        uint16_t boot_device = fw_cfg_read_i16(FW_CFG_BOOT_DEVICE);

	fword("update-chosen");
	if (boot_device == 'm') {
	        check_preloaded_kernel();
	}
	if (boot_device == 'c') {
		quik_startup();
	}
	yaboot_startup();
}
