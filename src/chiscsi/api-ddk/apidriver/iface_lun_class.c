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

#define DMA_THRESHOLD   2048
#define API_LU_CLASS    "API_TEST_DISK"

chiscsi_target_lun_class lun_class_storage;
int     debug1 = 0;
int     debug2 = 0;
int     overflow = 0;
int     underflow = 0;
extern void     *page_addr;
extern void     *addr;

/* dummy free_page */
void free_single_page(void *pg) 
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
					PAGE_SIZE,
                                        PCI_DMA_BIDIRECTIONAL);
		}
		kfree(scmd_info);
	}
}

/*display functions for dbug*/
static void sgvec_display(char *caption, chiscsi_sgvec *sgl, unsigned int nr)
{
        chiscsi_sgvec *sgvec = sgl;
        int i = 0;

        for (; sgvec && i < nr; i++, sgvec++) {
                printk("%s: %d, sg 0x%p, flag 0x%x, len %u, "
                        "addr 0x%p=0x%p+0x%x, dma 0x%llx.\n",
                        caption, i, sgvec, sgvec->sg_flag, sgvec->sg_length,
                        sgvec->sg_addr, sgvec->sg_page, sgvec->sg_offset,
                        sgvec->sg_dma_addr);
        }
}

static void sc_sgl_display(char *caption, scmd_sgl *sgl)
{
        printk("%s, scmd_sgl 0x%p, %u+%u, nr %u, vec 0x%p,0x%p.\n",
                caption, sgl, sgl->sgl_boff, sgl->sgl_length, sgl->sgl_vecs_nr,
                sgl->sgl_vecs, sgl->sgl_vec_last);

        if (sgl->sgl_vecs_nr) {
                sgvec_display(caption, (chiscsi_sgvec *)&sgl->sgl_vecs, sgl->sgl_vecs_nr);
	}
}

/* Find the scmd_info in q for corresponding sc */
iface_scmd_info *scmd_in_lun_queue(chiscsi_scsi_command *sc)
{
	iface_scmd_info *scmd_info;
	chiscsi_queue *q = lun[sc->sc_lun].scinfoq[0]; 

        if (!sc) {
                printk ("%s: Invalid chiscsi_scsi_command ptr.\n", __func__);
                return NULL;
        }

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
	chiscsi_queue *q = lun[sc->sc_lun].scinfoq[0];
	struct pci_dev *pdev;
	dma_addr_t mapping;

        if (!sc) {
                printk ("%s: Invalid chiscsi_scsi_command ptr.\n", __func__);
                return NULL;
        }

	scmd_info = scmd_in_lun_queue(sc);	
	if (!scmd_info && alloc) {
		/*allocate and queue the scsi command information*/
		scmd_info = iface_scmd_info_alloc();
		scmd_info->sc = sc;
		scmd_info->mapping = 0UL;
		/*since we use the same page for test purpose map it here*/
		if (sc->sc_offload_pdev) {
			pdev = (struct pci_dev *)sc->sc_offload_pdev;
			mapping = pci_map_page(pdev, page_addr, 0, PAGE_SIZE,
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

static int storage_scmd_alloc_pages(chiscsi_scsi_command *sc)
{
	iface_scmd_info *scmd_info = get_scmd_info_ptr(sc, 0);
	scmd_sgl *sc_sgl = &scmd_info->sc_sgl;
	chiscsi_sgvec *sglist = NULL, *sgp;
	unsigned int nr_pages, len;
	unsigned long sglen;
	int i;
	int dma = 0;

	/* If DMABLE then get dma address */
	if (sc->sc_xfer_len > DMA_THRESHOLD)
		dma = 0;

	/* caluclate len */
	len = sc->sc_xfer_len;
	nr_pages = (len + PAGE_SIZE - 1) >> PAGE_SHIFT;
	sglen = nr_pages << PAGE_SHIFT;

	/*no need to allocate space*/
	if (!sc->sc_xfer_len) {
		return 0;
	}

        /* Allocate and populate sgvec list */
        sglist = kmalloc(sizeof(chiscsi_sgvec) * nr_pages, GFP_KERNEL);
        if (!sglist) {
                return -ENOMEM;
        }
        memset(sglist, 0, sizeof(chiscsi_sgvec) * nr_pages);

	/* allocate pages */
	sgp = sglist;
	for (i = 0; i < nr_pages; i++, sgp++) {
		/*For testing purpose just allocate same page all the time*/
		sgp->sg_page = page_addr;
		if (!sgp->sg_page) {
			for (--i; i >= 0; i--, sgp--)
				free_single_page(sgp->sg_page);
			kfree(sgp);
			return -ENOMEM;
		}
		sgp->sg_addr = (unsigned char *) (page_address(sgp->sg_page));
		sgp->sg_offset = 0;
		sgp->sg_length = PAGE_SIZE;
		memset(sgp->sg_addr, 0x5a, PAGE_SIZE); /*Some pattern to test*/
		if (dma) { 
			sgp->sg_flag |= CHISCSI_SG_SBUF_DMABLE;
			sgp->sg_dma_addr = scmd_info->mapping;
			sgp->sg_page = NULL;
		}

	}

        if (sglen > len)
                sglist[nr_pages - 1].sg_length -= sglen - len;

	sc_sgl->sgl_vecs = (unsigned char *)sglist;
        sc_sgl->sgl_vec_last = sglist + nr_pages - 1;
        sc_sgl->sgl_vecs_nr = nr_pages;
	sc_sgl->sgl_boff = sglist->sg_offset; /*offset of the first page if any */
	sc_sgl->sgl_length = len;

	if (debug2)
		sc_sgl_display("alloc 2", sc_sgl);

	return 0;
}

static int storage_scmd_free_all_pages(chiscsi_scsi_command *sc)
{
	iface_scmd_info *scmd_info = get_scmd_info_ptr(sc, 0);	
	scmd_sgl *sc_sgl = &scmd_info->sc_sgl;
	chiscsi_sgvec *sgl = (chiscsi_sgvec *)sc_sgl->sgl_vecs;
	chiscsi_sgvec *sg;
	unsigned int sgcnt = sc_sgl->sgl_vecs_nr;

	//spin_lock((spinlock_t *)scmd_info->lock);
	if (!sgcnt) {
                kfree(sgl);
        } else if (sgl) {
		sg = sgl;
		while (sg) {
			free_single_page(sg->sg_page);
			sg++;
		}
                kfree(sgl);
        }
        sc_sgl->sgl_vecs_nr = 0;
        sc_sgl->sgl_vecs = NULL;
        sc_sgl->sgl_vec_last = NULL;

	//spin_unlock((spinlock_t *)scmd_info->lock);

	return 0;
}

/* Execute all scsi commands*/
static int storage_scmd_execute(iface_scmd_info *scmd_info, chiscsi_scsi_command *sc)
{
	scmd_sgl *sc_sgl = &scmd_info->sc_sgl;
	int ln = sc->sc_lun;
	unsigned long long pos = sc->sc_lba << lun[ln].sect_shift;
	int rv = 0;
	
	/*use locks since this function executed by 
	  target thread as well as storage thread */	
	//spin_lock((spinlock_t *)scmd_info->lock);

	/* parse cdb to determine nonrwio cmd*/
        parse_cdb_rw_info(sc);
	if (pos >= lun[ln].size) {
		printk("%s, rw beyond limit, pos %llu >= %llu.\n",
			    "TESTDISK", pos, lun[ln].size);
	}

	/*If CH_SFP_FLAG_RWIO flag is not set,it is a non rwio command*/
	if (!scmd_test_bit(sc, CH_SFP_RWIO_BIT)) {
                rv = iscsi_target_lu_scsi_non_rwio_cmd_respond(sc);
                if (rv < 0)
                        return -1;
        } else {
		/* read or write data is discarded */
		if (sc->sc_flag & SC_FLAG_WRITE) {
			/* execute the write command here and free after that*/
			write_command_execute(scmd_info, pos);
			storage_scmd_free_all_pages(sc);
		} else {
			/*bring all read data here */
			/* we already have pages allocated */
			read_command_execute(scmd_info, pos);
		}
	}

	if (debug1)	
		printk("%s: sc itt 0x%x, 0x%p sgcnt %u exe done, call chiscsi_exe_status.\n",
			__func__, sc->sc_itt, sc_sgl->sgl_vecs, sc_sgl->sgl_vecs_nr);

	
	//spin_unlock((spinlock_t *)scmd_info->lock);
	if (debug2)
		sc_sgl_display("scmd_execute", sc_sgl);

	/*execution status callback*/
	chiscsi_scsi_cmd_execution_status(sc, (unsigned char *)sc_sgl->sgl_vecs, sc_sgl->sgl_vecs_nr,
					sc_sgl->sgl_boff, (sc_sgl->sgl_length + sc_sgl->sgl_boff));
	return 0;
}

/*scmd rcvd, submit to storage driver for execution*/
/* Entry point */
static int storage_scsi_cmd_cdb_rcved(chiscsi_scsi_command *sc)
{
	iface_scmd_info *scmd_info = get_scmd_info_ptr(sc, 1);	
	scmd_sgl *sc_sgl = &scmd_info->sc_sgl;
	int rv;

//	printk("%s: itt 0x%x sc rcvd sc 0x%p \n", __func__, sc->sc_itt, sc);

	if (!sc_sgl->sgl_boff) {
		/* initial allocation */
		rv = storage_scmd_alloc_pages(sc);
		if (rv < 0)
			return rv;

		/* if read then start the execution */
		if (sc->sc_flag & SC_FLAG_READ) {
			rv = storage_scmd_execute(scmd_info, sc);
			if (rv < 0)
				return rv;
		} else {
			/* for write allocate buffers and let the target know */
//			printk("%s: itt 0x%x, sg 0x%p %u+%u/%u.\n", __func__, sc->sc_itt, sc_sgl->sgl_vecs,
  //                      	sc_sgl->sgl_boff, sc_sgl->sgl_length, sc->sc_xfer_len);
			/* buffer ready callback */
			chiscsi_scsi_cmd_buffer_ready(sc, (unsigned char *)sc_sgl->sgl_vecs,
				sc_sgl->sgl_vecs_nr, sc_sgl->sgl_boff, sc_sgl->sgl_length);
		}
	}
	
	return 0;
}

static void storage_scsi_cmd_data_xfer_status(chiscsi_scsi_command *sc,
				unsigned char *xfer_sreq_buf,
				unsigned int xfer_sgcnt,
				unsigned int xfer_offset,
				unsigned int xfer_buflen)
{
	iface_scmd_info *scmd_info = get_scmd_info_ptr(sc, 0);	
	scmd_sgl *sc_sgl = &scmd_info->sc_sgl;
	chiscsi_queue *q = lun[sc->sc_lun].scinfoq[0]; 
	
        if (sc_sgl->sgl_vecs != xfer_sreq_buf ||
            sc_sgl->sgl_vecs_nr != xfer_sgcnt ||
            sc_sgl->sgl_boff != xfer_offset ||
            sc_sgl->sgl_length != xfer_buflen) {
                printk("%s: itt 0x%x, SGL mismatch: 0x%p/0x%p, %u/%u, %u/%u+%u/%u.\n",
                        __func__, sc->sc_itt, sc_sgl->sgl_vecs, xfer_sreq_buf,
                        sc_sgl->sgl_vecs_nr, xfer_sgcnt, sc_sgl->sgl_boff,
                        xfer_offset, sc_sgl->sgl_length, xfer_buflen);
        }


		/* All the execution is done */
	if (sc->sc_flag & SC_FLAG_READ) {
		storage_scmd_free_all_pages(sc);
	} else {
		/* write: all data received */
		/*find the chiscsi_sgvec with the given buffer */
		storage_scmd_execute(scmd_info, sc);
	}

	/*since the scmd is completely done here remove from queue and free scmd_info*/
	spin_lock((spinlock_t *)q->q_lock);
	scmd_info_ch_qremove(nolock, q, scmd_info);
	iface_scmd_info_free(scmd_info);
	spin_unlock((spinlock_t *)q->q_lock);
}

/* Storage thread work:
 * Allocate/free more buffers and execute queued scsi commands 
 */
static int storage_thread_work(chiscsi_scsi_command *sc)
{
	iface_scmd_info *scmd_info = get_scmd_info_ptr(sc, 0);	
	scmd_sgl *sc_sgl = &scmd_info->sc_sgl;
	chiscsi_queue *q = lun[sc->sc_lun].scinfoq[0]; 


		/* All the execution is done */
	if (sc->sc_flag & SC_FLAG_READ) {
		storage_scmd_free_all_pages(sc);
	} else {
		/* write: all data received */
		/*find the chiscsi_sgvec with the given buffer */
		storage_scmd_execute(scmd_info, sc);
	}

		/*since the scmd is completely done here remove from queue and free scmd_info*/
		spin_lock((spinlock_t *)q->q_lock);
		scmd_info_ch_qremove(nolock, q, scmd_info);
		iface_scmd_info_free(scmd_info);
		spin_unlock((spinlock_t *)q->q_lock);

	if (debug2) {
		printk("%s: itt 0x%x, %u+%u/%u.\n", __func__, sc->sc_itt, sc_sgl->sgl_boff, 
				 sc_sgl->sgl_length, sc->sc_xfer_len);
	}

	return 0;
}

/* called when tmf was received by iSCSI stack and need to abort sc */
static int storage_scsi_cmd_abort(chiscsi_scsi_command *sc)
{
	iface_scmd_info *scmd_info = get_scmd_info_ptr(sc, 0);	
	chiscsi_queue *q = lun[sc->sc_lun].scinfoq[0]; 
	scmd_info->flag = MARK_ABORT_SCMD;

	printk("%s: abort sc itt 0x%x \n", __FUNCTION__, sc->sc_itt);

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
	iface_scmd_info *scmd_info = get_scmd_info_ptr(sc, 0);	
	int tmf_response = ISCSI_TMF_FUNCTION_ABORT_TASK; /* example*/
	chiscsi_queue *q = lun[sc->sc_lun].scinfoq[0]; 
	scmd_info->flag = MARK_TMF_SCMD;

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
		    (1 << LUN_CLASS_HAS_CMD_QUEUE_BIT),
	.class_name = "TESTDISK",
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
