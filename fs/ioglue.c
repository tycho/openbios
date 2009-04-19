/*
 *   Creation Date: <2001/05/06 22:27:09 samuel>
 *   Time-stamp: <2003/12/12 02:24:56 samuel>
 *
 *	<fs.c>
 *
 *     	I/O API used by the filesystem code
 *
 *   Copyright (C) 2001, 2002, 2003 Samuel Rydh (samuel@ibrium.se)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation
 *
 */

#include "openbios/config.h"
#include "openbios/bindings.h"
#include "openbios/fs.h"
#include "libc/diskio.h"
#include "os.h"
#include "hfs_mdb.h"

/************************************************************************/
/*	functions used by the various filesystems			*/
/************************************************************************/

// XXX: This is sloppy... Make the os_* functions have a private state structure.
static ulong s_offset = 0;

char *
get_hfs_vol_name( int fd, char *buf, int size )
{
	char sect[512];
	hfs_mdb_t *mdb = (hfs_mdb_t*)&sect;

	seek_io( fd, 0x400 );
	read_io( fd, sect, sizeof(sect) );
	if( hfs_get_ushort(mdb->drSigWord) == HFS_SIGNATURE ) {
		unsigned int n = mdb->drVN[0];
		if( n >= size )
			n = size - 1;
		memcpy( buf, &mdb->drVN[1], n );
		buf[n] = 0;
	} else if( hfs_get_ushort(mdb->drSigWord) == HFS_PLUS_SIGNATURE ) {
		strncpy( buf, "Unembedded HFS+", size );
	} else {
		strncpy( buf, "Error", size );
	}
	return buf;
}

void
os_set_offset(ulong offset)
{
	s_offset = offset;
}

ulong
os_read( int fd, void *buf, ulong len, int blksize_bits )
{
	/* printk("os_read %d\n", (int)len); */

	int cnt = read_io( fd, buf, len << blksize_bits );
	return (cnt > 0)? (cnt >> blksize_bits) : cnt;
}

ulong
os_seek( int fd, ulong blknum, int blksize_bits )
{
	/* printk("os_seek %d\n", blknum ); */
	llong offs = ((llong)blknum << blksize_bits) + s_offset;

	/* offset == -1 means seek to EOF */
	if( (int)blknum == -1 )
		offs = -1;

	if( seek_io(fd, offs) ) {
		/* printk("os_seek failure\n"); */
		return (ulong)-1;
	}

	if( (int)blknum == -1 ) {
		if( (offs=tell(fd)) < 0 )
			return -1;
		blknum = offs >> blksize_bits;
	}
	return blknum;
}

int
os_same( int fd1, int fd2 )
{
	return fd1 == fd2;
}
