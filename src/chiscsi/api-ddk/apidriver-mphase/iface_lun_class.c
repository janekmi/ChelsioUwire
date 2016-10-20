#include <asm/system.h>
#include <asm/uaccess.h>
#include <linux/smp.h>
#include <linux/smp_lock.h>
#include <linux/spinlock.h>
#include <linux/kthread.h>
#include <linux/pci.h>

#include "iface.h"
#include "storage_kthread.h"
#include "storage_driver.h"

#define DMA_THRESHOLD	2048
#define API_LU_CLASS	"API_TEST_DISK"

chiscsi_target_lun_class lun_class_storage;
int	debug1 = 0;
int	debug2 = 0;
int 	overflow = 0;
int 	underflow = 0;
extern void 	*page_addr;
extern void 	*addr;

/* dummy free_page */
void free_single_page(void *pg) 
{
	/* since this is a dummy free just set to NULL*/
	pg = NULL;
}

void free_memory(void *pg) 
{
	/* since this is a dummy free just set to NULL*/
	pg = NULL;
}
/* allocate/free the scmd information struct for each sc rcved*/
iface_scmd_info *iface_scmd_info_alloc(void)
{
	iface_scmd_info *scmd_info;
	int size = sizeof(iface_scmd_info) + sizeof(spinlock_t);

        scmd_info = kmalloc(size, GFP_KERNEL);
        if (!scmd_info)
                return NULL;
	memset(scmd_info, 0, size);
	scmd_info->lock = scmd_info + 1;
	spin_lock_init((spinlock_t *)scmd_info->lock);

        return scmd_info;
}

void iface_scmd_info_free(iface_scmd_info *scmd_info)
{
	struct pci_dev *pdev;

	if (scmd_info) {
		/*unmap the page that was mapped for this sc*/
		if (scmd_info->sc->sc_offload_pdev) {
			pdev = (struct pci_dev *)scmd_info->sc->sc_offload_pdev;
			pci_unmap_page(pdev, scmd_info->mapping,
					BUFFER_PAGE_SIZE,
                                        PCI_DMA_BIDIRECTIONAL);
		}
		kfree(scmd_info);
	}
}

/*display functions for dbug*/
static void sgvec_display(char *caption, storage_sglist *sgl)
{
        storage_sglist *sg = sgl;
	chiscsi_sgvec *sgvec;
        int i = 0;

        for (; sg; i++, sg = sg->sglist_next) {
		if( sg == NULL)
			return;
		sgvec = sg->sgvec;
		printk("%s: %d, sg 0x%p, flag 0x%x, len %u, "
                        "addr 0x%p=0x%p+0x%x, dma 0x%llx.\n",
                        caption, i, sgvec, sgvec->sg_flag, sgvec->sg_length,
                        sgvec->sg_addr, sgvec->sg_page, sgvec->sg_offset,
                        sgvec->sg_dma_addr);
        }
}

static void sc_sgl_display(char *caption, scmd_sgl *sgl)
{
	storage_sglist *sg = (storage_sglist *)sgl->sgl_vecs;
	
	printk("%s, scmd_sgl 0x%p, %u+%u, nr %u, vec 0x%p,0x%p.\n",
                caption, sgl, sgl->sgl_boff, sgl->sgl_length, sgl->sgl_vecs_nr,
                sgl->sgl_vecs, sgl->sgl_vec_last);

        if (sgl->sgl_vecs_nr && !sg ) {
                sgvec_display(caption, sg);
	}
}

/* Find the scmd_info in q for corresponding sc */
iface_scmd_info *scmd_in_lun_queue(chiscsi_scsi_command *sc)
{
	iface_scmd_info *scmd_info;
	chiscsi_queue *q;

	if (!sc) {
		printk ("%s: Invalid chiscsi_scsi_command ptr.\n", __func__);
		return NULL;
	}

	q = lun[sc->sc_lun].scinfoq[0];
	if (!q)
		return NULL; 
		 
	spin_lock((spinlock_t *)q->q_lock);
	scmd_info_qsearch_by_sc(nolock, q, scmd_info, sc);
	spin_unlock((spinlock_t *)q->q_lock);

	if (!scmd_info)
		return NULL;
	else 
		return scmd_info;
}

void *get_scmd_info_ptr(chiscsi_scsi_command *sc, int alloc)
{
	iface_scmd_info *scmd_info = NULL;
	chiscsi_queue *q;
	struct pci_dev *pdev;
	dma_addr_t mapping;

	if (!sc) {
		printk ("%s: Invalid chiscsi_scsi_command ptr.\n", __func__);
		return NULL;
	}

	q = lun[sc->sc_lun].scinfoq[0];
	if (!q)
		return NULL;
	
	scmd_info = scmd_in_lun_queue(sc);	
	
	if (!scmd_info && alloc) {
		/*allocate and queue the scsi command information*/
		scmd_info = iface_scmd_info_alloc();
		if (!scmd_info)
			return NULL;

		scmd_info->sc = sc;
		scmd_info->mapping = 0UL;
		/*since we use the same page for test purpose map it here*/
		if (sc->sc_offload_pdev) {
			pdev = (struct pci_dev *)sc->sc_offload_pdev;
			mapping = pci_map_page(pdev, page_addr, 0, BUFFER_PAGE_SIZE,
					PCI_DMA_BIDIRECTIONAL);
			scmd_info->mapping = mapping;
		}
		spin_lock((spinlock_t *)q->q_lock);
		scmd_info_enqueue(nolock, q, scmd_info);
		spin_unlock((spinlock_t *)q->q_lock);
	} 

	return scmd_info;
}

/*****************************************/
/* allocation and disallocation of pages */
/*****************************************/

/* storage_scmd_alloc_pages:
 * -builds the sglist as and when buffers are available
 * -multiphase_max_alloc > page size is not supported in 
 *  this sample driver
 */
static unsigned int multiphase_max_alloc = BUFFER_PAGE_SIZE;
static int storage_scmd_alloc_pages(chiscsi_scsi_command *sc)
{
	iface_scmd_info *scmd_info;
	scmd_sgl *sc_sgl;
	storage_sglist *sg_list = NULL, *sgp;
	unsigned int nr_pages, boff, len;
	unsigned long sglen;
	chiscsi_sgvec *sgvec_list;
	int i;
	int dma = 0;
	unsigned int offset = 0;

	if(!sc) {
		printk("%s: sc NULL\n", __func__);
		return -EINVAL;
	}

	scmd_info = get_scmd_info_ptr(sc, 0);
	if(!scmd_info) {
		printk ("%s: scmd_info NULL\n", __func__);
		return -EINVAL;
	}

	if (sc->sc_xfer_len > DMA_THRESHOLD)
		dma = 1;

	sc_sgl = &scmd_info->sc_sgl;
	if (!sc_sgl) {
		printk ("%s: No SG list for sc 0x%p\n", __func__, sc);
		return -EINVAL;
	}
	
	spin_lock((spinlock_t *)scmd_info->lock);
	boff = sc_sgl->sgl_boff + sc_sgl->sgl_length;
	len = min(sc->sc_xfer_len - boff, multiphase_max_alloc);
#if 0
        if ((sc_sgl->sgl_boff+sc_sgl->sgl_length) == 0) {
                len = 3072;
                offset = 1024;
        }
#endif
	if(debug1)
		printk("%s: boff %u, sgl_boff %u, sgl_length %u, len %u\n", 
			__func__, boff, sc_sgl->sgl_boff, sc_sgl->sgl_length, len);	

	if (overflow || underflow)	/* for sake of testing */
		len = multiphase_max_alloc;

	if (debug2 && sc_sgl)
		sc_sgl_display("storage_scmd_alloc 1", sc_sgl);

	nr_pages = (len + BUFFER_PAGE_SIZE - 1) >> BUFFER_PAGE_SHIFT;
	sglen = nr_pages << BUFFER_PAGE_SHIFT;

	/*no need to allocate space*/
	if (!sc->sc_xfer_len) {
		spin_unlock((spinlock_t *)scmd_info->lock);
		return 0;
	}

	/* Allocate storage sglist to hold sgvec list*/
        sg_list = kmalloc(sizeof(storage_sglist), GFP_KERNEL);
        if (!sg_list) {
                spin_unlock((spinlock_t *)scmd_info->lock);
                return -ENOMEM;
        }
        memset(sg_list, 0, sizeof(storage_sglist));

        /* Allocate and populate sgvec list */
        sgvec_list = kmalloc(sizeof(chiscsi_sgvec) * nr_pages, GFP_KERNEL);
        if (!sgvec_list) {
                spin_unlock((spinlock_t *)scmd_info->lock);
                return -ENOMEM;
        }
        memset(sgvec_list, 0, sizeof(chiscsi_sgvec) * nr_pages);

	/* allocate pages */
	sg_list->sgvec = sgvec_list;
	sg_list->sgvec->sg_flag |= CHISCSI_SG_SBUF_LISTHEAD;
	for (i = 0, sgp = sg_list; i < nr_pages; i++, sgp++) {
		/*For testing purpose just allocate same page all the time*/
		sgp->sgvec->sg_page = page_addr;
		if (!sgp->sgvec->sg_page) {
			for (--i; i >= 0; i--, sgp--)
				free_single_page(sgp->sgvec->sg_page);
			kfree(sgp);
			spin_unlock((spinlock_t *)scmd_info->lock);
			return -ENOMEM;
		}
		sgp->sgvec->sg_addr = (unsigned char *) (page_address(sgp->sgvec->sg_page));
		memset(sgp->sgvec->sg_addr, 0x5a, BUFFER_PAGE_SIZE); /*Some pattern to test*/
		sgp->sgvec->sg_offset = 0;
		sgp->sgvec->sg_length = BUFFER_PAGE_SIZE;
		sgp->sglist_next = sgp + 1;
		if (dma) { 
			sg_list->sgvec->sg_flag |= CHISCSI_SG_SBUF_DMABLE;
			sgp->sgvec->sg_dma_addr = scmd_info->mapping + offset;
			sgp->sgvec->sg_page = NULL;
	
			if (debug1 && sg_list) {
				printk ("%s: DMA %u, sg_flag 0x%x sg_dma_addr 0x%llx sg_len %u sglist_next 0x%p\n",
					 __func__, dma, sg_list->sgvec->sg_flag, sgp->sgvec->sg_dma_addr,
					sgp->sgvec->sg_length, sgp->sglist_next);
			}
		}

		if (debug1 && sgp) 
			printk("storage sc itt 0x%x, off %u, alloc page %d, 0x%p. sg_addr 0x%p\n",
				sc->sc_itt, boff, i, sgp->sgvec->sg_page, sgp->sgvec->sg_addr);

	}
	
	if(nr_pages > 0)
		sg_list[nr_pages - 1].sglist_next = NULL;

	if ((sglen > len) && (nr_pages > 0)) {
		sg_list[nr_pages - 1].sgvec->sg_length -= sglen - len;
	}

	for (i = 0, sgp = sg_list; i < nr_pages; i++, sgp++) {
		sgp->sglist_boff = boff;
		boff += sgp->sgvec->sg_length;
	}

	/* there could be buffers already there, be careful not to
	   over-write that info. */
	if (!sc_sgl->sgl_vecs) {
		sc_sgl->sgl_vecs = (unsigned char *)sg_list;
		sc_sgl->sgl_boff = sg_list->sglist_boff;
		sc_sgl->sgl_length = len;
		sc_sgl->sgl_vecs_nr = nr_pages;
	} else {
		sc_sgl->sgl_length += len;
		sc_sgl->sgl_vecs_nr += nr_pages;
		sc_sgl->sgl_vec_last->sglist_next = sg_list;
	}
	sc_sgl->sgl_vec_last = sg_list + nr_pages - 1;

	if (debug2 && sc_sgl)
		sc_sgl_display("storage_scmd_alloc 2", sc_sgl);
	spin_unlock((spinlock_t *)scmd_info->lock);

	return 0;
}

static int storage_scmd_free_all_pages(chiscsi_scsi_command *sc)
{
	iface_scmd_info *scmd_info;
	scmd_sgl *sc_sgl;
	storage_sglist *sgl;
	storage_sglist *sg;

	if (!sc)
		return -EINVAL;
		
	scmd_info = get_scmd_info_ptr(sc, 0);	
	if (!scmd_info) { 
		printk ("%s: BAD scmd_info 0x%p\n", __func__, scmd_info);
		return -EINVAL;
	}
	
	sc_sgl = &scmd_info->sc_sgl;
	if (!sc_sgl)
		return -EINVAL;

	sg = sgl = (storage_sglist *)sc_sgl->sgl_vecs;
	if (!sg)
		return -EINVAL;

	while (sg) {
		if (sg->sgvec->sg_flag & CHISCSI_SG_SBUF_LISTHEAD) {
			storage_sglist *next;
			for (next = sg->sglist_next; next; next = next->sglist_next) {
				if (next->sgvec->sg_flag & CHISCSI_SG_SBUF_LISTHEAD)
					break;
			}
			kfree(sg->sgvec);
			kfree(sg);
			sg = next;
		} else
			sg = sg->sglist_next;
	}
	
	sc_sgl->sgl_boff += sc_sgl->sgl_length;
	sc_sgl->sgl_length = 0;
	sc_sgl->sgl_vecs_nr = 0;
	sc_sgl->sgl_vecs = NULL;
	sc_sgl->sgl_vec_last = NULL;
	return 0;
}

static int storage_scmd_free_pages_by_offset(chiscsi_scsi_command *sc,
				 	unsigned int boff, unsigned int len)
{
	iface_scmd_info *scmd_info;
	scmd_sgl *sc_sgl;
	storage_sglist *sgl;
	storage_sglist *sg_last, *sg;
	unsigned int sgcnt;
	unsigned int off = boff + len;
	int i;

	if (!sc)
		return -EINVAL;
	
	scmd_info = get_scmd_info_ptr(sc, 0);	
	sc_sgl = &scmd_info->sc_sgl;
	sgl = (storage_sglist *)sc_sgl->sgl_vecs;
	sgcnt = sc_sgl->sgl_vecs_nr;

	if (debug2 && sc_sgl)
		sc_sgl_display("storage_scmd_free 1", sc_sgl);

	spin_lock((spinlock_t *)scmd_info->lock);
	/* should always be in-order */
	if (sgl->sglist_boff != boff) {
		printk("%s: itt 0x%x, boff %u != sgl head %u.\n",
			__func__, sc->sc_itt, boff, sgl->sglist_boff); 
		goto err_out;
	}

	if (len < sgl->sgvec->sg_length) {
		printk("%s: itt 0x%x, not enough data %u > %u.\n",
			__func__, sc->sc_itt, len, sgl->sgvec->sg_length);
		goto err_out;
	}
	if (!(sgl->sgvec->sg_flag & CHISCSI_SG_SBUF_LISTHEAD)) {
		printk("%s: itt 0x%x, not on sgl boundary %u.\n",
			__func__, sc->sc_itt, boff);
		goto err_out;
	}

	if (off == (sc_sgl->sgl_length + sc_sgl->sgl_boff))
		sg_last = sc_sgl->sgl_vec_last;
	else {
		storage_sglist *prev = NULL;

		for (i=0, sg=sgl; i < sgcnt; i++, prev = sg, sg = sg->sglist_next)
			if (sg->sglist_boff == off)
				break;
		if (!sg) {
			printk("%s: itt 0x%x, NO sg ends %u+%u.\n",
				__func__, sc->sc_itt, boff, len);
			goto err_out;
		}
		sg_last = prev;
	}

	if (sg_last && sg_last->sglist_next &&
		!(sg_last->sglist_next->sgvec->sg_flag & CHISCSI_SG_SBUF_LISTHEAD)) {
		printk("%s: itt 0x%x, %u+%u, last not end of burst %u,%u.\n",
			__func__, sc->sc_itt, boff, len, sg_last->sglist_boff,
			sg_last->sgvec->sg_length);
			goto err_out;
	}

	for (sg = sgl, i = 1; sg != sg_last; i++, sg = sg->sglist_next) {
		free_single_page(sg->sgvec->sg_page);
	}
	free_single_page(sg_last->sgvec->sg_page);

	sc_sgl->sgl_boff = boff + len;
	sc_sgl->sgl_length -= len;
	sc_sgl->sgl_vecs_nr -= i;
	sc_sgl->sgl_vecs = (unsigned char *)sg_last->sglist_next;

	sg = sgl;
	while (sg != sg_last) {
		if (sg->sgvec->sg_flag & CHISCSI_SG_SBUF_LISTHEAD) {
			storage_sglist *next;
			for (next = sg->sglist_next; next; next = next->sglist_next) {
				if (next->sgvec->sg_flag & CHISCSI_SG_SBUF_LISTHEAD)
					break;
				if (next == sg_last)
					sg_last = NULL;
			}
			kfree(sg->sgvec);
			kfree(sg);
			sg = next;
		} else
			sg = sg->sglist_next;
	}
	if (sg_last && sg_last->sgvec->sg_flag & CHISCSI_SG_SBUF_LISTHEAD) {
		kfree(sg_last->sgvec);
		kfree(sg_last);
	}
	
	if (debug2 && sc_sgl)
		sc_sgl_display("storage_scmd_free 2", sc_sgl);
	
	spin_unlock((spinlock_t *)scmd_info->lock);
	return 0;

err_out:
	spin_unlock((spinlock_t *)scmd_info->lock);
	return -EINVAL;
}

static int storage_scmd_free_pages(chiscsi_scsi_command *sc,
				unsigned int boff, unsigned int len)
{
	if (!boff && len == sc->sc_xfer_len)
		return storage_scmd_free_all_pages(sc);
	else
		return storage_scmd_free_pages_by_offset(sc, boff, len);
}

/* Execute all scsi commands*/
static int storage_scmd_execute(iface_scmd_info *scmd_info, chiscsi_sgvec *sgl,
				unsigned int sgcnt, unsigned int boff,
				unsigned int blen)
{
	chiscsi_scsi_command *sc;
	int ln;
	unsigned long long pos; 
	int rv = 0;
	int res_cnt = 0;

	if (!scmd_info) { 
		printk ("%s: BAD scmd_info 0x%p\n", __func__, scmd_info);
		return -EINVAL;
	}
	
	sc = scmd_info->sc;
	ln = sc->sc_lun;
	pos = sc->sc_lba << lun[ln].sect_shift;

	if (debug1)
		printk ("%s: lun %d, sc 0x%p, sgcnt %u, boff %u, blen %u, "
			"pos %llu, lba %llu, sess 0x%p, itt 0x%x\n", 
			__func__, ln, sc, sgcnt, boff, blen, pos, sc->sc_lba, 
			sc->sc_sess, sc->sc_itt);

	/*use locks since this function executed by 
	  target thread as well as storage thread */	
	spin_lock((spinlock_t *)scmd_info->lock);

	/* parse cdb to determine nonrwio cmd*/
        parse_cdb_rw_info(sc);
	pos += boff;
	if (pos >= lun[ln].size) {
		printk("%s, rw beyond limit, pos %llu >= %llu.\n",
			    API_LU_CLASS, pos, lun[ln].size);
		spin_unlock((spinlock_t *)scmd_info->lock);
		return -EINVAL;
	}

	//display_byte_string("WRITE DATA", (unsigned char *) (page_address(page_addr)), BUFFER_PAGE_SIZE);
	
	/* for testing, underflow-allocate less pages, for */
	if (underflow) {
		if (boff + blen + 2*BUFFER_PAGE_SIZE > sc->sc_xfer_len)
			res_cnt = 1;
		else res_cnt = 0;
	} else if (overflow) {
		if ((boff+blen)%sc->sc_xfer_len < BUFFER_PAGE_SIZE)
			res_cnt = 1;
		else res_cnt = 0;
	}

	/*If CH_SFP_FLAG_RWIO flag is not set,it is a non rwio command*/
	if (!scmd_test_bit(sc, CH_SFP_RWIO_BIT)) {
                rv = iscsi_target_lu_scsi_non_rwio_cmd_respond(sc);
                if (rv < 0) {
                	spin_unlock((spinlock_t *)scmd_info->lock); 
			return -EINVAL;
		}
        } else {
		/* read or write data is discarded */
		if (sc->sc_flag & SC_FLAG_WRITE) {
			if(debug1)
				printk("%s: execute W, off %u, len %u, pos %llx\n", 	
					__func__, boff, blen, pos);

			/* execute the write command here and free after that*/
			write_command_execute(scmd_info, boff, blen, pos);
			spin_unlock((spinlock_t *)scmd_info->lock);
			storage_scmd_free_pages(sc, boff, blen);
			spin_lock((spinlock_t *)scmd_info->lock);
		} else {
			/*bring all read data here */
			/* we already have pages allocated */
			spin_unlock((spinlock_t *)scmd_info->lock);
			read_command_execute(scmd_info, boff, blen, pos, res_cnt);
			spin_lock((spinlock_t *)scmd_info->lock);
		}
	}

	if (debug1 && sgl)	
		printk("%s: sc itt 0x%x, 0x%p boff %u blen %u sgcnt %u exe done, call chiscsi_exe_status.\n",
			__func__, sc->sc_itt, sgl, boff, blen, sgcnt);
	
	spin_unlock((spinlock_t *)scmd_info->lock);
	
	/*execution status callback*/
	chiscsi_scsi_cmd_execution_status(sc, (unsigned char *)sgl, sgcnt,
					boff, blen);

	return 0;
}

/*scmd rcvd, submit to storage driver for execution*/
static int storage_scsi_cmd_cdb_rcved(chiscsi_scsi_command *sc)
{
	iface_scmd_info *scmd_info;
	scmd_sgl *sc_sgl; 
	storage_sglist *sgl;
	chiscsi_sgvec *sgvec = NULL;
	int rv;

	if (!sc) {
		printk("%s sc is NULL \n", __func__);
		return -EINVAL;
	}

	scmd_info = get_scmd_info_ptr(sc, 1);	
	if (!scmd_info)
		return -EINVAL;

	sc_sgl = &scmd_info->sc_sgl;
	if (!sc_sgl)
		return -EINVAL;	

	if (debug1 && sc) 
		printk("%s: itt 0x%x sc rcvd sc 0x%p \n", __func__, sc->sc_itt, sc);

	if (!sc_sgl->sgl_boff) {
		/* initial allocation */
		rv = storage_scmd_alloc_pages(sc);
		if (rv < 0)
			return rv;

		sgl = (storage_sglist *)sc_sgl->sgl_vecs;
		if (sgl)
			sgvec = sgl->sgvec;

		/* if read then start the execution */
		if (sc->sc_flag & SC_FLAG_READ) {
			if(debug1 && sgvec)
                                printk("%s: Read Request. sg_addr 0x%p sg_dma_addr 0x%llx\n",
                                        __func__, sgvec->sg_addr, sgvec->sg_dma_addr );

			rv = storage_scmd_execute(scmd_info,
					sgvec,
					sc_sgl->sgl_vecs_nr,
					sc_sgl->sgl_boff,
					sc_sgl->sgl_length);
			if (rv < 0)
				return rv;
		} else {
			/* for write allocate buffers and let the target know */
			if (debug1 && sc_sgl)
				printk("%s: itt 0x%x, sg 0x%p %u+%u/%u.\n", 
					__func__, sc->sc_itt, sc_sgl->sgl_vecs,
                	        	sc_sgl->sgl_boff, sc_sgl->sgl_length, 
					sc->sc_xfer_len);
			if (debug1 && sgvec)
				printk("%s: Write Request. sg_addr 0x%p sg_dma_addr 0x%llx, , sgvec 0x%p"
					" call chiscsi_scsi_cmd_buffer_ready.\n",
					__func__, sgvec->sg_addr, sgvec->sg_dma_addr, sgl->sgvec);

			/* buffer ready callback */
			chiscsi_scsi_cmd_buffer_ready(sc, (unsigned char *)sgl->sgvec,
					sc_sgl->sgl_vecs_nr, sc_sgl->sgl_boff,
					sc_sgl->sgl_length);
		}
	}
	
	if (debug1 && sc_sgl) 
		printk("%s: itt 0x%x, %u+%u/%u.\n", __func__, sc->sc_itt, 
			sc_sgl->sgl_boff, sc_sgl->sgl_length, sc->sc_xfer_len);

	/* if allocated buffers are not enough then storage driver should 
	   take over and allocate any more buffers/execute commands
	   This would free up the iscsi target thread */
	if (((sc_sgl->sgl_boff + sc_sgl->sgl_length) < sc->sc_xfer_len)) {
		pass_scmd_to_storage_thread(sc);
	}

	return 0;
}

static void storage_scsi_cmd_data_xfer_status(chiscsi_scsi_command *sc,
				unsigned char *xfer_sreq_buf,
				unsigned int xfer_sgcnt,
				unsigned int xfer_offset,
				unsigned int xfer_buflen)
{
	iface_scmd_info *scmd_info;
	scmd_sgl *sc_sgl;
	storage_sglist *sg; 
	unsigned int len = xfer_buflen;
	chiscsi_queue *q;

	if (!sc) {
		printk("%s: sc is NULL\n", __func__);
		return;
	}

	scmd_info = get_scmd_info_ptr(sc, 0);	
	if (!scmd_info) {
		printk("%s: ERR! Can not find scmd_info ptr\n", __func__);
		return;
	}

	sc_sgl = &scmd_info->sc_sgl;
	if(!sc_sgl) {
		printk("%s: ERR! sc_sgl is NULL.\n", __func__);
		return;
	}
		
	sg = (storage_sglist *)sc_sgl->sgl_vecs; 
	if (!sg) {
		printk("%s, itt 0x%x, sg is NULL (%u+%u).\n",
			__func__, sc->sc_itt, xfer_offset, xfer_buflen);
		return;
	}

	q = lun[sc->sc_lun].scinfoq[0]; 

	if (debug1)
		printk("%s, sc itt 0x%x, flag 0x%x, buf 0x%p, %u,%u+%u.\n", 
			__func__, sc->sc_itt, sc->sc_flag, xfer_sreq_buf, 
			xfer_sgcnt, xfer_offset, xfer_buflen);

	if (debug1 && sg)
		printk("%s, sg_dma_addr 0x%llx, sg_addr 0x%p, sg_len %u\n", 
			__func__, sg->sgvec->sg_dma_addr, sg->sgvec->sg_addr, sg->sgvec->sg_length );
	
	if (debug2 && sc_sgl) 
		sc_sgl_display("storage_xfer_status 1", sc_sgl);

	if (!xfer_offset && (xfer_buflen == sc->sc_xfer_len)) {
		/* All the execution is done */
		if (sc->sc_flag & SC_FLAG_READ) {
			if (debug1)
				printk("%s: Read Command, xfer_sreq_buf 0x%p, xfer_sgcnt %u, xfer_offset 0x%u,"
					" xfer_buflen %u, call storage_scmd_execute.\n", 
					__func__, xfer_sreq_buf, xfer_sgcnt, xfer_offset, xfer_buflen);
			storage_scmd_free_pages(sc, xfer_offset, xfer_buflen);
		} else {
			if (debug1)
				printk("%s: Write Command, xfer_sreq_buf 0x%p, xfer_sgcnt %u, xfer_offset 0x%u,"
					" xfer_buflen %u, call storage_scmd_execute.\n", 
					__func__, xfer_sreq_buf, xfer_sgcnt, xfer_offset, xfer_buflen);
			storage_scmd_execute(scmd_info, (chiscsi_sgvec *)xfer_sreq_buf,
					xfer_sgcnt, xfer_offset, xfer_buflen);
		}

		/*since the scmd is completely done here remove from queue and free scmd_info*/
		spin_lock((spinlock_t *)q->q_lock);
		scmd_info_ch_qremove(nolock, q, scmd_info);
		iface_scmd_info_free(scmd_info);
		spin_unlock((spinlock_t *)q->q_lock);

		return;
	}

	/*find sg with xfer_offset*/
	for (; sg; sg = sg->sglist_next) {
		if (sg->sglist_boff == xfer_offset) {
			break;
		}
	}

	if (!sg) {
		printk("%s, itt 0x%x, can NOT find %u+%u.\n",
			__func__, sc->sc_itt, xfer_offset, xfer_buflen);
		return;
	}
	
	/* this sg does not match the sreq buffer given by API*/
	if (sg->sgvec != (chiscsi_sgvec *)xfer_sreq_buf) {
		printk("%s, itt 0x%x, %u+%u NOT match 0x%p!= 0x%p.\n",
			__func__, sc->sc_itt, xfer_offset, xfer_buflen, sg,
			xfer_sreq_buf);
		return;
	}
	if (!(sg->sgvec->sg_flag & CHISCSI_SG_SBUF_LISTHEAD)) {
		printk("%s, itt 0x%x, %u+%u NOT start of burst 0x%p.\n",
			__func__, sc->sc_itt, xfer_offset, xfer_buflen, sg);
		return;
	}

	while (len && sg) {
		len -= sg->sgvec->sg_length;
		sg->sgvec->sg_flag |= CHISCSI_SG_SBUF_XFER_DONE;
		sg = sg->sglist_next;
	}

	if (sg && !(sg->sgvec->sg_flag & CHISCSI_SG_SBUF_LISTHEAD))
		printk("%s, itt 0x%x, %u+%u NOT end of burst 0x%p.\n",
			__func__, sc->sc_itt, xfer_offset, xfer_buflen, sg);

	/* go to storage thread to see more allocation/execution to be done?*/
	if (scmd_info) {
		if (debug1) {
			if(sc->sc_flag & SC_FLAG_READ)
				printk("%s: Executing buffers, sc 0x%p, xfer_left %u, xfer_length %u\n",
					__func__, sc, sc->sc_xfer_left, sc->sc_xfer_len);
			else
				printk("%s: Allocating buffer, sc 0x%p, xfer_left %u, xfer_length %u\n",
					 __func__, sc, sc->sc_xfer_left, sc->sc_xfer_len);
		}
		if (debug1)
			printk("%s: sc 0x%p, call pass_scmd_to_storage_thread\n", __func__, sc);
		pass_scmd_to_storage_thread(sc);
	}
}

/* Storage thread work:
 * Allocate/free more buffers and execute queued scsi commands 
 */
static int storage_thread_work(chiscsi_scsi_command *sc)
{
	iface_scmd_info *scmd_info;
	scmd_sgl *sc_sgl;
	storage_sglist *sgl, *sg;
	unsigned int len = 0;
	int write; 
	chiscsi_queue *q;
	int rv;

	if (!sc)
		return -EINVAL;

	scmd_info = get_scmd_info_ptr(sc, 0);	
	sc_sgl = &scmd_info->sc_sgl;
	sgl = (storage_sglist *)sc_sgl->sgl_vecs; 
	sg = sgl;
	write = (sc->sc_flag & SC_FLAG_WRITE) ? 1:0;
	q = lun[sc->sc_lun].scinfoq[0]; 

	if (!sg || !sc_sgl) {
		printk("%s: No Buffers available to execute for sc 0x%p\n", 
				__func__, sc );
		return -EINVAL;
	}

	if (debug1 && sg && sc_sgl)
                printk("thread work itt 0x%x, sg 0x%p, sgnext 0x%p,  %u+%u/%u.\n", sc->sc_itt, sg,
				sg->sglist_next,sc_sgl->sgl_boff, sc_sgl->sgl_length, sc->sc_xfer_len);

#if 0
	/* code segment to test chiscsi_scsi_cmd_abort(sc) */
        sc->sc_response = ISCSI_RESPONSE_TARGET_FAILURE; 
        sc->sc_status = SCSI_STATUS_CHECK_CONDITION; 
        sc->sc_sense_key = SCSI_SENSE_ABORTED_COMMAND; 
        sc->sc_sense_asc = 0x44; /* internal target failure */ 
        sc->sc_sense_ascq = 0; 

	chiscsi_scsi_cmd_abort(sc);
	return 0;
#endif

	/* any read/write data done? */
	if (sg && (sg->sgvec->sg_flag & CHISCSI_SG_SBUF_XFER_DONE)) {
		unsigned int sgcnt = 1;
		len += sg->sgvec->sg_length;
		if (sg->sglist_next) {
			for (sg = sg->sglist_next; sg; sgcnt++, sg = sg->sglist_next)
				if (sg->sgvec->sg_flag & CHISCSI_SG_SBUF_XFER_DONE)
					len += sg->sgvec->sg_length;
				else
					break;
		}
		
		if (debug1)
			printk("%s: itt 0x%x, data buffer xfer done, %u+%u, sg %u.\n", 
				__func__, sc->sc_itt, sg->sglist_boff, len, sgcnt);
		
		if (write) 
			storage_scmd_execute(scmd_info, (chiscsi_sgvec *)sgl->sgvec, sgcnt, sgl->sglist_boff, len);
		else
			storage_scmd_free_pages(sc, sgl->sglist_boff, len);


		/*if the scmd is completely done here remove from queue and free scmd_info*/
		if (!sc_sgl->sgl_length && ((sc_sgl->sgl_boff + sc_sgl->sgl_length) 
			== sc->sc_xfer_len)) {
			spin_lock((spinlock_t *)q->q_lock);
			scmd_info_ch_qremove(nolock, q, scmd_info);
			iface_scmd_info_free(scmd_info);
			spin_unlock((spinlock_t *)q->q_lock);
		}
	}

	/* need to allocate more buffers? */
	if ((sc_sgl->sgl_boff + sc_sgl->sgl_length) < sc->sc_xfer_len) {
		unsigned int boff = sc_sgl->sgl_boff + sc_sgl->sgl_length;
		unsigned int blen = sc_sgl->sgl_length;
		storage_sglist *sglist = sc_sgl->sgl_vec_last;
		unsigned int nvecs = sc_sgl->sgl_vecs_nr;

		rv = storage_scmd_alloc_pages(sc);
		if (rv < 0)
			return rv;

		blen = sc_sgl->sgl_length - blen;
		nvecs = sc_sgl->sgl_vecs_nr - nvecs;
	
		if (!sglist) {
			sglist = (storage_sglist *)sc_sgl->sgl_vecs;
		} else {
			if (sglist->sglist_next) {
				sglist = sglist->sglist_next;
			} else {
				sglist = (storage_sglist *)sc_sgl->sgl_vecs;
			}
		}

		if (write) {
			if (debug1 && sglist)
				printk("thread buf ready: itt 0x%x, sg 0x%p %u+%u/%u.\n", 
					sc->sc_itt, sglist, sc_sgl->sgl_boff, sc_sgl->sgl_length, 
					sc->sc_xfer_len);
			chiscsi_scsi_cmd_buffer_ready(sc, (unsigned char *)sglist->sgvec,
					nvecs, boff, blen);
		} else {
			storage_scmd_execute(scmd_info, sglist->sgvec, nvecs, boff, blen);
		}
	}

	if (debug1 && sc_sgl) 
		printk("%s: itt 0x%x, %u+%u/%u.\n", __func__, sc->sc_itt, sc_sgl->sgl_boff, 
				 sc_sgl->sgl_length, sc->sc_xfer_len);

	if (debug2 && sc_sgl ) 
		sc_sgl_display("storage_scmd_work done", sc_sgl);
	

	if (((sc_sgl->sgl_boff + sc_sgl->sgl_length) < sc->sc_xfer_len)) {
		pass_scmd_to_storage_thread(sc);
	} 

	//chiscsi_iscsi_command_dump(sc);
	return 0;
}

/* called when tmf was received by iSCSI stack and need to abort sc */
static int storage_scsi_cmd_abort(chiscsi_scsi_command *sc)
{
	iface_scmd_info *scmd_info;
	chiscsi_queue *q;

	if (!sc)
		return -EINVAL;

	scmd_info = get_scmd_info_ptr(sc, 0);	
	q = lun[sc->sc_lun].scinfoq[0]; 

	printk("%s: abort sc itt 0x%x \n", __func__, sc->sc_itt);
	scmd_info->flag = MARK_ABORT_SCMD;

	/* setup error codes, (this is an example) */
        sc->sc_response = ISCSI_RESPONSE_TARGET_FAILURE; 
        sc->sc_status = SCSI_STATUS_CHECK_CONDITION; 
        sc->sc_sense_key = SCSI_SENSE_ABORTED_COMMAND; 
        sc->sc_sense_asc = 0x44; /* internal target failure */ 
        sc->sc_sense_ascq = 0; 

	/*free the scmd_info if abort related work is done*/
	spin_lock((spinlock_t *)q->q_lock);
	scmd_info_ch_qremove(nolock, q, scmd_info);
	iface_scmd_info_free(scmd_info);
	spin_unlock((spinlock_t *)q->q_lock);
	
	chiscsi_scsi_cmd_abort_status(sc);

	return 0;
}

/* called when tmf is received and we should execute the tmf command and send response */
static int storage_tmf_execute(unsigned long hndl, unsigned char immediate_cmd,
                           unsigned char tmf_func, unsigned int lun_num,
			   chiscsi_scsi_command *sc)
{
	iface_scmd_info *scmd_info;
	int tmf_response = ISCSI_TMF_FUNCTION_ABORT_TASK; /* example*/
	chiscsi_queue *q;

	if(!sc)
		return -EINVAL;

	scmd_info = get_scmd_info_ptr(sc, 0);
	if (!scmd_info)
		return -EINVAL;	

	scmd_info->flag = MARK_TMF_SCMD;
	
	q = lun[sc->sc_lun].scinfoq[0]; 

	printk("%s: execute TMF sc itt 0x%x \n", __FUNCTION__, sc->sc_itt);

	/*since this scmd_info is not MARK_FOR_WORK queue we can free it here*/
	spin_lock((spinlock_t *)q->q_lock);
	scmd_info_ch_qremove(nolock, q, scmd_info);
	iface_scmd_info_free(scmd_info);
	spin_unlock((spinlock_t *)q->q_lock);

	chiscsi_tmf_execution_done(hndl, tmf_response, sc);

	return 0;
}

static void storage_scsi_cmd_data_abort_status(unsigned int sc_lun, unsigned int sc_cmdsn,
				unsigned int sc_itt, unsigned int sc_xfer_sgcnt, 
				unsigned char *sc_sgl_sgl_vecs, void *sc_sdev_hndl) 
{
	printk("%s sc 0x%x abort successful!\n", __FUNCTION__, sc_itt);
	/* cleanup any chiscsi_scsi_command related infomration */
}


chiscsi_target_lun_class lun_class_storage = {
	.property = (1 << LUN_CLASS_SCSI_PASS_THRU_BIT) |
		    (1 << LUN_CLASS_MULTI_PHASE_DATA_BIT) |
		    (1 << LUN_CLASS_HAS_CMD_QUEUE_BIT),
	.class_name = API_LU_CLASS,
	.fp_config_parse_options = NULL,
	.fp_attach = NULL,
	.fp_reattach = NULL,
	.fp_detach = NULL,
	.fp_queued_scsi_cmd_exe = storage_thread_work,
	.fp_scsi_cmd_cdb_rcved = storage_scsi_cmd_cdb_rcved,
	.fp_scsi_cmd_data_xfer_status = storage_scsi_cmd_data_xfer_status,
	.fp_scsi_cmd_abort = storage_scsi_cmd_abort,
	.fp_scsi_cmd_abort_status = storage_scsi_cmd_data_abort_status,
	.fp_tmf_execute = storage_tmf_execute,
};
