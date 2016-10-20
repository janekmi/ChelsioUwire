/*
 * file functions that can be shared by the user space cli programs.
 */

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

int os_file_size(char *fname, unsigned long *sz)
{
	struct stat stbuf;
	int     rv = stat(fname, &stbuf);
	if (rv) {
		return -1;
	}
	*sz = stbuf.st_size;
	return 0;
}
