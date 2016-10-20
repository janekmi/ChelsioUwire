#ifndef __ISCSI_SCATTERLIST_API_H__
#define __ISCSI_SCATTERLIST_API_H__

/* allocation & free */
void    chiscsi_sglist_free_memory(chiscsi_sgvec *, int);
void    chiscsi_sglist_free(chiscsi_sgvec *, int, int);
chiscsi_sgvec *chiscsi_sglist_alloc(int);
chiscsi_sgvec *chiscsi_sglist_alloc_with_page(int, int);
chiscsi_sgvec *chiscsi_sglist_alloc_with_buffer(int, int);

/* add pages or buffer */
int     chiscsi_sglist_add_buffer(chiscsi_sgvec *, int, int);
int     chiscsi_sglist_add_pages(chiscsi_sgvec *, int, int);

/* data */
int chiscsi_sglist_copy(chiscsi_sgvec *fsg, unsigned int fsgcnt, unsigned int foff,
		chiscsi_sgvec * tsg, unsigned int tsgcnt, unsigned int toff);

int 	chiscsi_sglist_copy_bufdata(unsigned char *, int, 
				 chiscsi_sgvec *, unsigned int);

int     chiscsi_sglist_compare(chiscsi_sgvec *, int, chiscsi_sgvec *,
			     int);
int	chiscsi_sglist_check_pattern(chiscsi_sgvec *sglist, int sgmax, int offset,
				   int len, unsigned char pattern);

/* debug */
int     chiscsi_sglist_display(char *, chiscsi_sgvec *, unsigned int, char *,
			     int, int);
void chiscsi_sgl_display(char *caption, chiscsi_sgl *sgl, int priv, int data);


#endif /* ifndef __ISCSI_SCATTERLIST_API_H__ */
