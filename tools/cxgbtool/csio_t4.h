/******************************************************************************
 *
 * Copyright (c) Chelsio Communications.  All rights reserved.
 *
 *   THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY
 *   KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
 *   IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR
 *   PURPOSE.
 *
 * Module Name:
 *
 *    csio_t4.h
 *
 * Abstract:
 *
 *    csio_t4.h -  contains the T4 specific definitions & headers.
 *
 * Environment:
 *
 *    User mode
 *
 * Revision History:
 *
 *	Gokul TV - 22-Jul-10 -	Creation
 *
 *****************************************************************************/

#ifndef __CSIO_T4_H___
#define __CSIO_T4_H___

#include <t4_regs.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _field_desc {
	const char *name;
	uint32_t start;
	uint32_t width;
}FIELD_DESC, *PFIELD_DESC, field_desc_t;

typedef struct _field_desc_ex {
    const char *name;     /* field name */
    uint16_t start; /* start bit position */
    uint16_t end;   /* end bit position */
    uint8_t shift;  /* # of low-order bits omitted and implicitly 0 */
    uint8_t hex;    /* print field in hex instead of decimal */
    uint8_t islog2; /* field contains the base-2 log of the value */
}FIELD_DESC_EX, *PFIELD_DESC_EX, field_desc_ex_t;

field_desc_t tp_la0[] = {
	{ "RcfOpCodeOut", 60, 4 },
	{ "State", 56, 4 },
	{ "WcfState", 52, 4 },
	{ "RcfOpcSrcOut", 50, 2 },
	{ "CRxError", 49, 1 },
	{ "ERxError", 48, 1 },
	{ "SanityFailed", 47, 1 },
	{ "SpuriousMsg", 46, 1 },
	{ "FlushInputMsg", 45, 1 },
	{ "FlushInputCpl", 44, 1 },
	{ "RssUpBit", 43, 1 },
	{ "RssFilterHit", 42, 1 },
	{ "Tid", 32, 10 },
	{ "InitTcb", 31, 1 },
	{ "LineNumber", 24, 7 },
	{ "Emsg", 23, 1 },
	{ "EdataOut", 22, 1 },
	{ "Cmsg", 21, 1 },
	{ "CdataOut", 20, 1 },
	{ "EreadPdu", 19, 1 },
	{ "CreadPdu", 18, 1 },
	{ "TunnelPkt", 17, 1 },
	{ "RcfPeerFin", 16, 1 },
	{ "RcfReasonOut", 12, 4 },
	{ "TxCchannel", 10, 2 },
	{ "RcfTxChannel", 8, 2 },
	{ "RxEchannel", 6, 2 },
	{ "RcfRxChannel", 5, 1 },
	{ "RcfDataOutDrdy", 4, 1 },
	{ "RxDvld", 3, 1 },
	{ "RxOoDvld", 2, 1 },
	{ "RxCongestion", 1, 1 },
	{ "TxCongestion", 0, 1 },
	{ NULL }
};

field_desc_t tp_la1[] = {
		{ "CplCmdIn", 56, 8 },
		{ "CplCmdOut", 48, 8 },
		{ "ESynOut", 47, 1 },
		{ "EAckOut", 46, 1 },
		{ "EFinOut", 45, 1 },
		{ "ERstOut", 44, 1 },
		{ "SynIn", 43, 1 },
		{ "AckIn", 42, 1 },
		{ "FinIn", 41, 1 },
		{ "RstIn", 40, 1 },
		{ "DataIn", 39, 1 },
		{ "DataInVld", 38, 1 },
		{ "PadIn", 37, 1 },
		{ "RxBufEmpty", 36, 1 },
		{ "RxDdp", 35, 1 },
		{ "RxFbCongestion", 34, 1 },
		{ "TxFbCongestion", 33, 1 },
		{ "TxPktSumSrdy", 32, 1 },
		{ "RcfUlpType", 28, 4 },
		{ "Eread", 27, 1 },
		{ "Ebypass", 26, 1 },
		{ "Esave", 25, 1 },
		{ "Static0", 24, 1 },
		{ "Cread", 23, 1 },
		{ "Cbypass", 22, 1 },
		{ "Csave", 21, 1 },
		{ "CPktOut", 20, 1 },
		{ "RxPagePoolFull", 18, 2 },
		{ "RxLpbkPkt", 17, 1 },
		{ "TxLpbkPkt", 16, 1 },
		{ "RxVfValid", 15, 1 },
		{ "SynLearned", 14, 1 },
		{ "SetDelEntry", 13, 1 },
		{ "SetInvEntry", 12, 1 },
		{ "CpcmdDvld", 11, 1 },
		{ "CpcmdSave", 10, 1 },
		{ "RxPstructsFull", 8, 2 },
		{ "EpcmdDvld", 7, 1 },
		{ "EpcmdFlush", 6, 1 },
		{ "EpcmdTrimPrefix", 5, 1 },
		{ "EpcmdTrimPostfix", 4, 1 },
		{ "ERssIp4Pkt", 3, 1 },
		{ "ERssIp6Pkt", 2, 1 },
		{ "ERssTcpUdpPkt", 1, 1 },
		{ "ERssFceFipPkt", 0, 1 },
		{ NULL }
	};

#define FIELD(name, start, end) { name, start, end, 0, 0, 0 }
#define FIELD1(name, start) FIELD(name, start, start)

field_desc_ex_t egress[] = {
		FIELD1("StatusPgNS:", 180),
		FIELD1("StatusPgRO:", 179),
		FIELD1("FetchNS:", 178),
		FIELD1("FetchRO:", 177),
		FIELD1("Valid:", 176),
		FIELD("PCIeDataChannel:", 174, 175),
		FIELD1("DCAEgrQEn:", 173),
		FIELD("DCACPUID:", 168, 172),
		FIELD1("FCThreshOverride:", 167),
		FIELD("WRLength:", 162, 166),
		FIELD1("WRLengthKnown:", 161),
		FIELD1("ReschedulePending:", 160),
		FIELD1("OnChipQueue:", 159),
		FIELD1("FetchSizeMode", 158),
		{ "FetchBurstMin:", 156, 157, 4, 0, 1 },
		{ "FetchBurstMax:", 153, 154, 6, 0, 1 },
		FIELD("uPToken:", 133, 152),
		FIELD1("uPTokenEn:", 132),
		FIELD1("UserModeIO:", 131),
		FIELD("uPFLCredits:", 123, 130),
		FIELD1("uPFLCreditEn:", 122),
		FIELD("FID:", 111, 121),
		FIELD("HostFCMode:", 109, 110),
		FIELD1("HostFCOwner:", 108),
		{ "CIDXFlushThresh:", 105, 107, 0, 0, 1 },
		FIELD("CIDX:", 89, 104),
		FIELD("PIDX:", 73, 88),
		{ "BaseAddress:", 18, 72, 9, 1 },
		FIELD("QueueSize:", 2, 17),
		FIELD1("QueueType:", 1),
		FIELD1("CachePriority:", 0),
		{ NULL }
	};

field_desc_ex_t fl[] = {
		FIELD1("StatusPgNS:", 180),
		FIELD1("StatusPgRO:", 179),
		FIELD1("FetchNS:", 178),
		FIELD1("FetchRO:", 177),
		FIELD1("Valid:", 176),
		FIELD("PCIeDataChannel:", 174, 175),
		FIELD1("DCAEgrQEn:", 173),
		FIELD("DCACPUID:", 168, 172),
		FIELD1("FCThreshOverride:", 167),
		FIELD("WRLength:", 162, 166),
		FIELD1("WRLengthKnown:", 161),
		FIELD1("ReschedulePending:", 160),
		FIELD1("OnChipQueue:", 159),
		FIELD1("FetchSizeMode", 158),
		{ "FetchBurstMin:", 156, 157, 4, 0, 1 },
		{ "FetchBurstMax:", 153, 154, 6, 0, 1 },
		FIELD1("FLMcongMode:", 152),
		FIELD("MaxuPFLCredits:", 144, 151),
		FIELD("FLMcontextID:", 133, 143),
		FIELD1("uPTokenEn:", 132),
		FIELD1("UserModeIO:", 131),
		FIELD("uPFLCredits:", 123, 130),
		FIELD1("uPFLCreditEn:", 122),
		FIELD("FID:", 111, 121),
		FIELD("HostFCMode:", 109, 110),
		FIELD1("HostFCOwner:", 108),
		{ "CIDXFlushThresh:", 105, 107, 0, 0, 1 },
		FIELD("CIDX:", 89, 104),
		FIELD("PIDX:", 73, 88),
		{ "BaseAddress:", 18, 72, 9, 1 },
		FIELD("QueueSize:", 2, 17),
		FIELD1("QueueType:", 1),
		FIELD1("CachePriority:", 0),
		{ NULL }
	};

field_desc_ex_t ingress[] = {
		FIELD1("NoSnoop:", 145),
		FIELD1("RelaxedOrdering:", 144),
		FIELD1("GTSmode:", 143),
		FIELD1("ISCSICoalescing:", 142),
		FIELD1("Valid:", 141),
		FIELD1("TimerPending:", 140),
		FIELD1("DropRSS:", 139),
		FIELD("PCIeChannel:", 137, 138),
		FIELD1("SEInterruptArmed:", 136),
		FIELD1("CongestionMgtEnable:", 135),
		FIELD1("DCAIngQEnable:", 134),
		FIELD("DCACPUID:", 129, 133),
		FIELD1("UpdateScheduling:", 128),
		FIELD("UpdateDelivery:", 126, 127),
		FIELD1("InterruptSent:", 125),
		FIELD("InterruptIDX:", 114, 124),
		FIELD1("InterruptDestination:", 113),
		FIELD1("InterruptArmed:", 112),
		FIELD("RxIntCounter:", 106, 111),
		FIELD("RxIntCounterThreshold:", 104, 105),
		FIELD1("Generation:", 103),
		{ "BaseAddress:", 48, 102, 9, 1 },
		FIELD("PIDX:", 32, 47),
		FIELD("CIDX:", 16, 31),
		{ "QueueSize:", 4, 15, 4, 0 },
		{ "QueueEntrySize:", 2, 3, 4, 0, 1 },
		FIELD1("QueueEntryOverride:", 1),
		FIELD1("CachePriority:", 0),
		{ NULL }
	};

field_desc_ex_t flm[] = {
		FIELD1("NoSnoop:", 79),
		FIELD1("RelaxedOrdering:", 78),
		FIELD1("Valid:", 77),
		FIELD("DCACPUID:", 72, 76),
		FIELD1("DCAFLEn:", 71),
		FIELD("EQid:", 54, 70),
		FIELD("SplitEn:", 52, 53),
		FIELD1("PadEn:", 51),
		FIELD1("PackEn:", 50),
		FIELD1("DBpriority:", 48),
		FIELD("PackOffset:", 16, 47),
		FIELD("CIDX:", 8, 15),
		FIELD("PIDX:", 0, 7),
		{ NULL }
	};

field_desc_ex_t conm[] = {
		FIELD1("CngDBPHdr:", 6),
		FIELD1("CngDBPData:", 5),
		FIELD1("CngIMSG:", 4),
		FIELD("CngChMap:", 0, 3),
		{ NULL }
	};

#undef FIELD1
#undef FIELD

#ifdef __cplusplus
}
#endif

#endif /* __CSIO_T4_H___ */
