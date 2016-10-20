/*
 *  Copyright (C) 2008-2014 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 * 
 * Description:
 * 
 */

#ifndef __CSIO_OS_HW_H__
#define __CSIO_OS_HW_H__

#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/device.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_transport_fc.h>
#include <linux/cdev.h>

#include <csio_hw.h>
#ifdef __CSIO_FOISCSI_ENABLED__
#include <csio_os_foiscsi.h>
#endif

extern struct device_attribute *csio_hw_attrs[];

#define CSIO_CDEVFILE		KBUILD_MODNAME	
#define CSIO_MAX_LUN		0xFFFF
#define CSIO_MAX_QUEUE		2048
#define CSIO_MAX_PCIFN		1024	
#define CSIO_MAX_CMINORS	CSIO_MAX_PCIFN
#define CSIO_MAX_CMD_PER_LUN	32
#define CSIO_MAX_DDP_BUF_SIZE	(1024 * 1024)	/* 1MB */
#define CSIO_MAX_SECTOR_SIZE	128	/* 64k max IO size  */
#define CSIO_FOISCSI_MAX_SECTOR_SIZE   8192 /*  4MB max io size */


/* MSIX and queues */
#define CSIO_FWD_INTR_IQ	1	/* No of Forward interrupt iq for
					 * INTX/MSI mode */
#define CSIO_EXTRA_MSI_IQS	2	/* Extra iqs for INTX/MSI mode
                                         (Forward intr iq + fw iq) */
#define CSIO_EXTRA_VECS		2	/* non-data + FW evt */
#define CSIO_MAX_SCSI_CPU	128		
#define CSIO_MAX_SCSI_QSETS	(CSIO_MAX_SCSI_CPU * CSIO_MAX_T4PORTS)
#define CSIO_MAX_MSIX_VECS	(CSIO_MAX_SCSI_QSETS + CSIO_EXTRA_VECS)
#define CSIO_INTR_WRSIZE	128
#define CSIO_INTR_IQSIZE	((CSIO_MAX_MSIX_VECS + 1) * CSIO_INTR_WRSIZE)

struct csio_msix_entries {
	unsigned short	vector; 	/* Vector assigned by pci_enable_msix */
	void 		*dev_id;	/* Priv object associated w/ this msix*/
	char		desc[24];	/* Description of this vector */
};

struct csio_scsi_qset {
	int		iq_idx;		/* Ingress index */ 
	int		eq_idx;		/* Egress index */
	uint32_t	intr_idx;	/* MSIX Vector index */
};

struct csio_scsi_cpu_info {
	int16_t	max_cpus;
#ifdef __CSIO_TARGET__
	int16_t cur_iq_cpu;
#endif /* __CSIO_TARGET__ */
};

struct csio_os_chip_ops;

struct csio_os_hw {
	struct csio_hw 	hw;		/* Common hw structure */	
	struct pci_dev 	*pdev;		/* PCI device */	

	/* SCSI queue sets */
	uint32_t num_sqsets;		/* Number of SCSI queue sets */
	uint32_t num_scsi_msix_cpus;	/* Number of CPUs that will be used 
					 * for ingress processing.
					 */
	struct csio_scsi_qset sqset[CSIO_MAX_T4PORTS][CSIO_MAX_SCSI_CPU];
	struct csio_scsi_cpu_info scsi_cpu_info[CSIO_MAX_T4PORTS];

	/* MSIX vectors */
	struct csio_msix_entries msix_entries[CSIO_MAX_MSIX_VECS];
	
	/* BAR register addresses */
	void __iomem *vbar0; 		/* Virtual address of PCI BAR 0 */
	void __iomem *vbar1; 		/* Virtual address of PCI BAR 1 */
	void __iomem *vbar2; 		/* Virtual address of PCI BAR 2 */
	void __iomem *vbar3; 		/* Virtual address of PCI BAR 3 */

	struct cdev cdev;		/* ioctl */
	
	/* HW trace buffers */	
	csio_trace_buf_t	trace_buf;		/* Trace buffer */
#ifdef CSIO_DATA_CAPTURE
	csio_dcap_buf_t         dcap_buf;      /* Data capture buf */
#endif
	/* T4/T5 Specific Functions for OS related operations */
	struct csio_os_chip_ops *os_chip_ops;
	
	/* FC transport */
	struct fc_host_statistics fch_stats;
};

/********************************************************/
/*  T4/T5 Specific Functions for OS related operations	*/
/********************************************************/
#define FW4_FNAME "cxgb4/t4fw.bin"
#define FW5_FNAME "cxgb4/t5fw.bin"
#define FW6_FNAME "cxgb4/t6fw.bin"
#define FW4_CFNAME "cxgb4/t4-config.txt"
#define FW5_CFNAME "cxgb4/t5-config.txt"
#define FW6_CFNAME "cxgb4/t6-config.txt"
#define FW4_FPGA_CFNAME "cxgb4/t4-config_fpga.txt"
#define FW5_FPGA_CFNAME "cxgb4/t5-config_fpga.txt"
#define FW6_FPGA_CFNAME "cxgb4/t6-config_fpga.txt"
#define PHY_AQ1202_FIRMWARE "cxgb4/aq1202_fw.cld"
#define PHY_BCM84834_FIRMWARE "cxgb4/bcm8483.bin"

/*
 * We use the below macro in csio_probe(), hence we are comparing
 * with device ids directly instead of using chip_id (which gets
 * initialized later in the code).
 */
#define CSIO_IS_T4_FPGA(_dev)		(((_dev) == CH_PCI_FN_MASK(PF_FPGA,0xa000)) || \
		                 	((_dev) == CH_PCI_FN_MASK(PF_FPGA,0xa001)))

struct mem_desc;

struct csio_os_chip_ops {
	void (*chip_debugfs_create_ext_mem)(struct csio_os_hw *);
	void (*chip_meminfo_sge_prep)(struct csio_os_hw *, struct mem_desc *);
	uint32_t (*chip_meminfo_show_ext_mem)(struct csio_os_hw *,
			struct mem_desc *, uint32_t *, uint32_t *, uint32_t);
};


/********************************************************/
/*  End of T4/T5 Specific Functions			*/
/********************************************************/

#define CSIO_PCI_BUS(oshw)		((oshw)->pdev->bus->number)
#define CSIO_PCI_DEV(oshw)		(PCI_SLOT((oshw)->pdev->devfn))
#define CSIO_PCI_FUNC(oshw)		(PCI_FUNC((oshw)->pdev->devfn))

/* Interrupt enable/disable routines */
csio_retval_t csio_request_irqs(struct csio_os_hw *);
void csio_intr_enable(struct csio_os_hw *);
void csio_intr_disable(struct csio_os_hw *, bool);

#endif /* ifndef __CSIO_OS_HW_H__ */
