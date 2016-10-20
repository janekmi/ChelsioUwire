#ifndef __ISCSI_SGVEC_H__
#define __ISCSI_SGVEC_H__

/* iscsi scatter-gather list */
typedef struct chiscsi_sgl chiscsi_sgl;
typedef struct chiscsi_sgvec chiscsi_sgvec;

struct chiscsi_sgl {
	unsigned int sgl_flag;
#define ISCSI_SGLF_LOCAL	0x1
	unsigned int sgl_boff;
	unsigned int sgl_length;
	unsigned int sgl_vecs_nr;
	chiscsi_sgvec *sgl_vec_last;
	unsigned char *sgl_vecs;
};

enum private_fields {
	SGVEC_PRIV_MPOOL,
	SGVEC_PRIV_HEAD,

	SGVEC_PRIV_MAX
};

struct chiscsi_sgvec {
	unsigned int sg_flag;
#define CHISCSI_SG_SBUF_DMABLE		0x1
#define CHISCSI_SG_SBUF_DMA_ONLY	0x2	/*private*/
#define CHISCSI_SG_SBUF_DMA_READ	0x4
#define CHISCSI_SG_SBUF_SHARE		0x8

#define CHISCSI_SG_BUF_ALLOC		0x10
#define CHISCSI_SG_PAGE_ALLOC		0x20
#define CHISCSI_SG_SBUF_MAP_NEEDED	0x40
#define CHISCSI_SG_SBUF_MAPPED		0x80

#define CHISCSI_SG_SBUF_LISTHEAD	0x100
#define CHISCSI_SG_SBUF_LISTTAIL	0x200
#define CHISCSI_SG_SBUF_XFER_DONE	0x400


	void *sg_page;
	unsigned char *sg_addr;	/* addr = page_address(sg_page) + sg_offset */
	unsigned long long sg_dma_addr; /* physical address */
	unsigned int sg_offset;	/* used w/ sg_page: offset into the page */
	unsigned int sg_length;

	/*
	 * NOTE:
	 * private to the iscsi stack, do NOT touch!
	 */
        unsigned int sg_boff;
        chiscsi_sgvec *sg_next;
	unsigned long sg_private[SGVEC_PRIV_MAX];
};

#define chiscsi_sgvec_dump(sgl,cnt) \
	do { \
		int __i; \
		chiscsi_sgvec *__sg = sgl; \
		for (__i = 0; __i < (cnt); __i++, __sg++) \
			os_log_info("chiscsi_sgvec %d, 0x%p, pg 0x%p, off %u, len %u, addr 0x%p.\n", \
				    __i, __sg, __sg->sg_page, __sg->sg_offset, __sg->sg_length, __sg->sg_addr); \
	}while(0)

/*
 * copy data (may not be page-aligned) from fsg to page-aligned tsg at offset. 
 * calling routine should make sure the data is mapped, if needed.
 */
int chiscsi_sglist_copy_sgdata(unsigned int, chiscsi_sgvec *, unsigned int, chiscsi_sgvec *, unsigned int);

/* scatterlist traverse */
int chiscsi_sglist_find_offset(chiscsi_sgvec *, unsigned int, unsigned int,
				unsigned int *); 
int chiscsi_sglist_find_boff(chiscsi_sgvec *, unsigned int, unsigned int,
				unsigned int *);
 
#endif /* ifndef __ISCSI_SGVEC_H__ */
