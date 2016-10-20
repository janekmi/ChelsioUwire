#ifndef __KERNEL__
#include <string.h>
#endif
#include <platdef.h>
#include <cudbg_if.h>
#include <cudbg_lib_common.h>

struct cudbg_flash_sec_info sec_info;

int get_scratch_buff(struct cudbg_buffer *pdbg_buff, u32 size,
		     struct cudbg_buffer *pscratch_buff)
{
	u32 scratch_offset;
	int rc = 0;

	scratch_offset = pdbg_buff->size - size;

	if (pdbg_buff->offset > (int)scratch_offset || pdbg_buff->size < size) {
		rc = CUDBG_STATUS_NO_SCRATCH_MEM;
		goto err;
	} else {
		pscratch_buff->data = (char *)pdbg_buff->data + scratch_offset;
		pscratch_buff->offset = 0;
		pscratch_buff->size = size;
		pdbg_buff->size -= size;
	}

err:
	return rc;
}

void release_scratch_buff(struct cudbg_buffer *pscratch_buff,
			  struct cudbg_buffer *pdbg_buff)
{
	pdbg_buff->size += pscratch_buff->size;
	pscratch_buff->data = NULL;
	pscratch_buff->offset = 0;
	pscratch_buff->size = 0;
}

struct cudbg_private g_context;
int cudbg_hello(struct cudbg_init *dbg_init, void **handle)
{
    int rc = 0;
    memset(&g_context, 0, sizeof(struct cudbg_private));
    memcpy(&(g_context.dbg_init), dbg_init, sizeof(struct cudbg_init));
    *handle = (void *) &g_context;
    return rc;
}

void reset_sec_info(void)
{
	memset(&sec_info, 0, sizeof(struct cudbg_flash_sec_info));
}

int cudbg_bye(void *handle)
{
	reset_sec_info();
	return 0;
}

int cudbg_reset_bitmap(void *handle, unsigned long *bitmap, int bitmap_count)
{
	struct cudbg_init *cudbg_init = NULL;
	int i;

	if (!bitmap_count)
		return -1;

	cudbg_init = &(((struct cudbg_private *)handle)->dbg_init);

	memset(cudbg_init->dbg_bitmap, 0, sizeof(cudbg_init->dbg_bitmap));

	for (i = 0; i < bitmap_count; i++)
		set_dbg_bitmap(cudbg_init->dbg_bitmap, bitmap[i]);

	return 0;
}
