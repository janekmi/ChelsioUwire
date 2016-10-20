#ifndef __ISCSI_TAG_H__
#define __ISCSI_TAG_H__

#include <common/iscsi_scsi_command.h>

#define ISCSI_INVALID_TAG	0xFFFFFFFF

/**
 * struct cxgbi_ulp2_tag_format - cxgbi ulp2 tag format for an iscsi entity
 * 
 * @sw_bits:    # of bits used by iscsi software layer
 * @rsvd_bits:  # of bits used by h/w
 * @rsvd_shift: h/w bits shift left
 * @rsvd_mask:  reserved bit mask
 */
struct cxgbi_ulp2_tag_format {
        unsigned char sw_bits;
        unsigned char rsvd_bits;
        unsigned char rsvd_shift;
        unsigned char filler[1];
        unsigned int rsvd_mask;
};

void iscsi_target_task_tag_release_woff(void *odevp, unsigned int ddp_tag);
unsigned int iscsi_tag_replace_sw_bits(void *dev, unsigned int tag,
					unsigned int idx, unsigned int r2t);
int iscsi_tag_reserve(chiscsi_scsi_command *sc);
void iscsi_tag_release(chiscsi_scsi_command *sc);
int iscsi_tag_update_r2tsn(chiscsi_scsi_command *sc, unsigned int r2tsn,
			unsigned int *new_tag);
unsigned int iscsi_tag_get_sw_tag(iscsi_socket *isock, unsigned int tag);
void iscsi_tag_decode_sw_tag(unsigned int sw_tag, unsigned int *idx,
                                unsigned int *r2tsn);

int iscsi_target_task_tag_get_woff(void *isock,
			unsigned int idx, unsigned int r2t,
			unsigned int sgcnt, chiscsi_sgvec *sgl, unsigned int,
			unsigned int xferoff, unsigned int buflen,
			unsigned int *sw_tag, unsigned int *ddp_tag,
			void *pi_info,
			struct chiscsi_tag_ppod *ppod_info);


#endif /* ifndef __ISCSI_TAG_H__ */
