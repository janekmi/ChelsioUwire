/*
 * chiscsi_sgvec.c -- iscsi scattergather list structures
 */

#include <common/os_builtin.h>
#include <iscsi_structs.h>
#include <iscsi_global.h>

static void chiscsi_sgvec_display(char *caption, chiscsi_sgvec *sgl,
				int priv, int data)
{
	chiscsi_sgvec *sg = sgl;
	int i = 0;

	for (; sg; i++, sg = sg->sg_next) {
		os_log_info("%s, sg %d,0x%p, flag 0x%x, len %u, 0x%p=0x%p+0x%x,"
			" dma 0x%llx.\n",
			caption, i, sg, sg->sg_flag, sg->sg_length,
			sg->sg_addr, sg->sg_page, sg->sg_offset,
			sg->sg_dma_addr);
		if (priv) {
			os_log_info("%s: sg %d, boff %u, 0x%p, 0x%lx,0x%lx\n",
				caption, i, sg->sg_boff, sg->sg_next,
				sg->sg_private[0], sg->sg_private[1]);	
		}
		if (data && sg->sg_addr) /* dump data out */
			iscsi_display_byte_string("sglist data", sg->sg_addr, 0,
						  sg->sg_length, NULL, 0);
	}
}

void chiscsi_sglist_free_memory(chiscsi_sgvec * sglist, int sgcnt)
{
	int     i;
	for (i = 0; i < sgcnt; i++, sglist++) {
		if (sglist->sg_flag & CHISCSI_SG_BUF_ALLOC) {
			os_free(sglist->sg_addr);
			sglist->sg_addr = NULL;
		} else if (sglist->sg_flag & CHISCSI_SG_PAGE_ALLOC) {
			os_free_one_page(sglist->sg_page);
			sglist->sg_page = NULL;
			sglist->sg_addr = NULL;
		}
	}
}

INLINE void chiscsi_sglist_free(chiscsi_sgvec * sglist, int sgcnt,
			      int free_mem)
{
	if (sglist) {
		if (free_mem)
			chiscsi_sglist_free_memory(sglist, sgcnt);
		os_free(sglist);
	}
}

chiscsi_sgvec *chiscsi_sglist_alloc(int sgcnt)
{
	chiscsi_sgvec *sglist;

	sglist = os_alloc(sizeof(chiscsi_sgvec) * sgcnt, 1, 1);
	if (!sglist)
		return NULL;
	/* os_alloc does memset() */

	return sglist;
}

/* add one buffer, calling routine should set the proper sg_length */
int chiscsi_sglist_add_buffer(chiscsi_sgvec * sg, int size, int wait)
{
	sg->sg_addr = os_alloc(size, wait, 1);
	if (!sg->sg_addr)
		return -ISCSI_ENOMEM;
	sg->sg_flag = CHISCSI_SG_BUF_ALLOC;

	/* os_alloc and os_alloc_big does memset() */
	sg->sg_length = size;

	return 0;
}

/* sglist should have >= pgcnt element, 
   calling routine should set the proper sg_length */
int chiscsi_sglist_add_pages(chiscsi_sgvec * sglist, int pgcnt, int wait)
{
	int     i;
	chiscsi_sgvec *sg = sglist;

	for (i = 0; i < pgcnt; i++, sg++) {
		sg->sg_page = os_alloc_one_page(wait, &sg->sg_addr);
		if (!sg->sg_page) {
			chiscsi_sglist_free_memory(sglist, i);
			return -ISCSI_ENOMEM;
		}

		sg->sg_length = os_page_size;
		sg->sg_flag |= CHISCSI_SG_PAGE_ALLOC;
		memset(sg->sg_addr, 0, os_page_size);
		sg->sg_next = sg + 1;
	}
	sglist[pgcnt -1].sg_next = NULL;

	return 0;
}

/* allocate and fill sglist with "pgmax" pages,
   calling routine should set the proper sg_length */
chiscsi_sgvec *chiscsi_sglist_alloc_with_page(int pgmax, int wait)
{
	chiscsi_sgvec *sglist;
	int     rv;

	sglist = os_alloc(sizeof(chiscsi_sgvec) * pgmax, wait, 1);
	if (!sglist)
		return NULL;
	/* os_alloc does memset() */

	rv = chiscsi_sglist_add_pages(sglist, pgmax, wait);
	if (rv < 0) {
		chiscsi_sglist_free(sglist, pgmax, 0);
		return NULL;
	}

	return sglist;
}

/* allocate one sglist with "max_size" buffer,
   calling routine should set the proper sg_length */
chiscsi_sgvec *chiscsi_sglist_alloc_with_buffer(int size, int wait)
{
	chiscsi_sgvec *sglist;
	int     rv;

	sglist = os_alloc(sizeof(chiscsi_sgvec), wait, 1);
	if (!sglist)
		return NULL;
	/* os_alloc does memset() */

	rv = chiscsi_sglist_add_buffer(sglist, size, wait);
	if (rv < 0) {
		os_free(sglist);
		return NULL;
	}

	return sglist;
}

/** 
 * chiscsi_sglist_find_offset -- search for the offset in a sglist
 * 				(sg, sgidx and sgoffset)
 * 	sglist: the scatterlist
 *	sgmax: # of entries in the sglist
 *	offset: data offset
 *
 * !! NOTE: offset is relative to sg_length (i.e., offset into sgl) 
 *
 * returns sgidx (the index into the sglist)
 */
int chiscsi_sglist_find_offset(chiscsi_sgvec *sgl, unsigned int sgmax,
			     unsigned int offset, unsigned int *sgoffset_p)
{
	int i = 0;
	chiscsi_sgvec *sg = sgl;
	unsigned int tlen = 0;

	if (!offset) {
		*sgoffset_p = 0;
		return 0;
	}

	for (; sg && i < sgmax; i++, sg = sg->sg_next) {
		tlen += sg->sg_length;
		if (tlen > offset)
			break;
	}

	if (tlen < offset || !sg) {
		os_log_info("sgl buffer not ready: offset %u.\n", offset);
		chiscsi_sgvec_display("sgl buffer", sgl, 1, 0); 
		return sgmax;
	}

	*sgoffset_p = sg->sg_length - (tlen - offset);
	return i;
}

/** 
 * chiscsi_sglist_find_boff -- search for the sg_boff offset in a sglist
 * 				(sg, sgidx and sgoffset)
 * 	sglist: the scatterlist
 *	sgmax: # of entries in the sglist
 *	offset: data offset
 *
 * !! NOTE: offset is relative to sg_boff (i.e., offset into total xfer length
 *
 * returns sgidx (the index into the sglist)
 */
int chiscsi_sglist_find_boff(chiscsi_sgvec *sgl, unsigned int sgmax,
			     unsigned int boff, unsigned int *sgoffset_p)
{
	int i = 0;
	chiscsi_sgvec *sg = sgl;
	chiscsi_sgvec *prev = NULL;

	if (sg->sg_boff > boff) {
		os_log_info("sgl buffer done: boff %u < %u.\n",
			boff, sg->sg_boff);
		return sgmax;
	}

	for (; sg && i < sgmax; prev = sg, i++, sg = sg->sg_next) {
		if (sg->sg_boff >= boff)
			break;
	}

	if (!sg)
		sg = prev;

	if (sg->sg_boff > boff) {
		i--;
		sg = prev;
	}

	if (!sg) {
		os_log_info("sgl buffer not ready: boff %u.\n", boff);
		chiscsi_sgvec_display("sgl buffer", sgl, 1, 0); 
		return sgmax;
	}

	*sgoffset_p = boff - sg->sg_boff;

	return i;
}

/* copy data (may not be page-aligned) from fsg to page-aligned tsg
   at offset. 
   calling routine should make sure the data is mapped, if needed.
 */
int chiscsi_sglist_copy_sgdata(unsigned int offset,
			   chiscsi_sgvec * fsg, unsigned int fsgcnt,
			   chiscsi_sgvec * tsg, unsigned int tsgcnt)
{
	unsigned int fidx = 0;
	unsigned int tidx = 0;
	unsigned int fsglen, tsglen;
	unsigned int fsgoffset = 0, tsgoffset = 0;
	unsigned char *fsgaddr;
	unsigned char *tsgaddr;
	int     copied = 0;

	if (!fsgcnt || !fsg || !tsg || !tsgcnt) {
		os_log_info("%s: fsg 0x%u/%p, tsg %u/0x%p.\n",
			__func__, fsgcnt, fsg, tsgcnt, tsg);
		return -ISCSI_EINVAL;
	}

	/* find the tidx */
	if (offset) {
		tidx = chiscsi_sglist_find_offset(tsg, tsgcnt, offset,
						&tsgoffset);
		if (tidx >= tsgcnt)
			return 0;
		tsg += tidx;
	}

	tsgaddr = tsg->sg_addr;
	tsglen = tsg->sg_length - tsgoffset;

	fsglen = fsg->sg_length;
	fsgaddr = fsg->sg_addr;
	if (!fsgaddr) {
		os_log_warn("sgcopy data, fsg 0, addr NULL, flag 0x%x.\n",
			    fsg->sg_flag);
		return -ISCSI_ENULL;
	}

	for (fidx = 0; fidx < fsgcnt && tidx < tsgcnt;) {
		unsigned int copy;
		copy = MINIMUM(fsglen, tsglen);

		memcpy(tsgaddr + tsgoffset, fsgaddr + fsgoffset, copy);

		/* move the fsg */
		fsglen -= copy;
		if (!fsglen) {
			fidx++;
			fsg++;
			fsglen = fsg->sg_length;
			fsgaddr = fsg->sg_addr;
			fsgoffset = 0;
		} else
			fsgoffset += copy;

		/* move the tsg */
		tsglen -= copy;
		if (!tsglen) {
			tidx++;
			tsg++;
			tsglen = tsg->sg_length;
			tsgaddr = tsg->sg_addr;
			tsgoffset = 0;
		} else
			tsgoffset += copy;

		copied += copy;
	}

	return copied;
}

/* copy data (may not be page-aligned) from fsg to tsg */
int chiscsi_sglist_copy(chiscsi_sgvec * fsg, unsigned int fsgcnt, unsigned int foff,
		      chiscsi_sgvec * tsg, unsigned int tsgcnt, unsigned int toff)
{
	unsigned int fidx = 0;
	unsigned int tidx = 0;
	unsigned int fsglen, tsglen;
	unsigned int fsgoffset = 0, tsgoffset = 0;
	unsigned char *fsgaddr;
	unsigned char *tsgaddr;
	int     copied = 0;

	if (!fsgcnt || !fsg || !tsg || !tsgcnt) {
		os_log_info("%s: fsg 0x%u/%p, tsg %u/0x%p.\n",
			__func__, fsgcnt, fsg, tsgcnt, tsg);
		return -ISCSI_EINVAL;
	}

	if (foff) {
		fidx = chiscsi_sglist_find_offset(fsg, fsgcnt, foff, &fsgoffset);
		if (fidx >= fsgcnt)
			return 0;
		fsg += fidx;
	}
	if (toff) {
		tidx = chiscsi_sglist_find_offset(tsg, tsgcnt, toff, &tsgoffset);
		if (tidx >= tsgcnt)
			return 0;
		tsg += tidx;
	}

	tsgaddr = tsg->sg_addr;
	tsglen = tsg->sg_length - tsgoffset;

	fsgaddr = fsg->sg_addr;
	fsglen = fsg->sg_length - fsgoffset;

	if (!fsgaddr) {
		os_log_warn("sgcopy data, fsg 0, addr NULL, flag 0x%x.\n",
			    fsg->sg_flag);
		return -ISCSI_ENULL;
	}

	for (fidx = 0; fidx < fsgcnt && tidx < tsgcnt;) {
		unsigned int copy;
		copy = MINIMUM(fsglen, tsglen);

		memcpy(tsgaddr + tsgoffset, fsgaddr + fsgoffset, copy);

		/* move the fsg */
		fsglen -= copy;
		if (!fsglen) {
			fidx++;
			fsg++;
			fsglen = fsg->sg_length;
			fsgaddr = fsg->sg_addr;
			fsgoffset = 0;
		} else
			fsgoffset += copy;

		/* move the tsg */
		tsglen -= copy;
		if (!tsglen) {
			tidx++;
			tsg++;
			tsglen = tsg->sg_length;
			tsgaddr = tsg->sg_addr;
			tsgoffset = 0;
		} else
			tsgoffset += copy;

		copied += copy;
	}

	return copied;
}

/**
 * chiscsi_sglist_copy_bufdata -- copy data from a buffer to a sglist
 */
int chiscsi_sglist_copy_bufdata(unsigned char *buf, int buflen,
			     chiscsi_sgvec * sglist, unsigned int sgmax)
{
	int i;
	int copied = 0;
	for (i = 0; i < sgmax && buflen; i++, sglist++) {
		int copy = MINIMUM(sglist->sg_length, buflen);
		memcpy(sglist->sg_addr, buf, copy);
		buflen -= copy;
		buf += copy;
		copied += copy;
	}
	return copied;
}


/* compare 2 sglist */
int chiscsi_sglist_compare(chiscsi_sgvec * sg1, int sg1cnt,
			 chiscsi_sgvec * sg2, int sg2cnt)
{
	int     v1, v2;
	int     len1, len2;
	unsigned char *p1, *p2;
	int     rv, len;

	p1 = p2 = NULL;
	len1 = len2 = 0;
	v1 = v2 = 0;
	while ((v1 < sg1cnt) && (v2 < sg2cnt)) {
		if (!len1) {
			p1 = sg1[v1].sg_addr;
			len1 = sg1[v1].sg_length;
		}
		if (!len2) {
			p2 = sg2[v2].sg_addr;
			len2 = sg2[v2].sg_length;
		}
		if (len1 < len2)
			len = len1;
		else
			len = len2;
		rv = memcmp(p1, p2, len);
		if (rv)
			return rv;
		p1 += len;
		p2 += len;
		len1 -= len;
		len2 -= len;
		if (!len1)
			v1++;
		if (!len2)
			v2++;
	}

	if (v1 < sg1cnt)
		return 1;
	else if (v2 < sg2cnt)
		return -1;
	return 0;
}

int chiscsi_sglist_check_pattern(chiscsi_sgvec *sglist, int sgmax, int offset,
			       int len, unsigned char pattern)
{
	unsigned char *byte;
	unsigned int pos, pos_max = offset + len;
	unsigned int sgidx = 0;
	unsigned int sgoffset = 0;
	unsigned int sglen;

	if (offset) {
		sgidx = chiscsi_sglist_find_offset(sglist, sgmax, offset,
						&sgoffset);
		if (sgidx >= sgmax)
			return -ISCSI_EINVAL;
	}

	sglen = sglist[sgidx].sg_length - sgoffset;
	byte = sglist[sgidx].sg_addr + sgoffset;
	for (pos = offset; pos < pos_max; pos++, byte++, sglen--) {
		if (!sglen) {
			sgidx++;
			sglen = sglist[sgidx].sg_length;
			byte = sglist[sgidx].sg_addr;
		}

		if (*byte != pattern) {
			os_log_error("sgl %u/%u, %u+%u, pos %u, 0x%x!=0x%x.\n",
				     sgidx, sgmax, offset, len, pos, *byte,
				     pattern);
			return -ISCSI_EMISMATCH;
		}
	}

	return 0;
}

int chiscsi_sglist_display(char *caption, chiscsi_sgvec * sglist,
			 unsigned int sgcnt, char *obuf, int obuflen, int data)
{
	chiscsi_sgvec *sg = sglist;
	int     i, j;
	int     len = 0;

	for (i = 0; i < sgcnt; i++, sg++) {
		if (obuf) {
			len += sprintf(obuf + len,
				"%s: sg 0x%p, %d, flag 0x%x, len 0x%x, "
				"addr 0x%p=0x%p+0x%x, dma 0x%llx.\n",
				caption, sg, i, sg->sg_flag, sg->sg_length, 
				sg->sg_addr, sg->sg_page, sg->sg_offset,
				sg->sg_dma_addr);
			for (j = 0; j < SGVEC_PRIV_MAX; j++)
				len += sprintf(obuf + len, " 0x%lx,",
						sg->sg_private[j]);
			len--;
			if (len >= obuflen)
				goto out;
		} else {
			os_log_info("%s: sg 0x%p, %d, flag 0x%x, len 0x%x, "
				"addr 0x%p=0x%p+0x%x, dma 0x%llx.\n",
				caption, sg, i, sg->sg_flag, sg->sg_length, 
				sg->sg_addr, sg->sg_page, sg->sg_offset,
				sg->sg_dma_addr);
		}

		if (data) {	/* dump data out */
			iscsi_display_byte_string("sglist data", sg->sg_addr, 0,
						  sg->sg_length,
						  obuf ? obuf + len : NULL,
						  obuflen);

		}
	}
out:
	return (len < obuflen ? len : obuflen);
}

void chiscsi_sgl_display(char *caption, chiscsi_sgl *sgl, int priv, int data)
{
	os_log_info("%s chiscsi_sgl 0x%p, 0x%x, %u,%u, vecs %u,0x%p,0x%p.\n",
		caption, sgl, sgl->sgl_flag, sgl->sgl_boff, sgl->sgl_length,
		sgl->sgl_vecs_nr, sgl->sgl_vecs, sgl->sgl_vec_last);

	if (sgl->sgl_vecs_nr)
		chiscsi_sgvec_display(caption, (chiscsi_sgvec *)sgl->sgl_vecs, priv, data);
}
