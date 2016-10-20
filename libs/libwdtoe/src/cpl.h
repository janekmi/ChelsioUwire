#ifndef __LIBWDTOE_CPL_H__
#define __LIBWDTOE_CPL_H__

#include "t4.h"
#include "t4_msg.h"

void process_cpl(const __be64 *rsp, const __be64 *rsp_end, u8 opcode);
#endif
