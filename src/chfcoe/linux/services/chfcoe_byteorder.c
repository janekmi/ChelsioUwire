/*
 *  Copyright (C) 2015 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#include <linux/kernel.h>

/* Byte order */
unsigned short chfcoe_ntohs(unsigned short v)
{	
	return ntohs(v);
}

unsigned int chfcoe_ntohl(unsigned int v)
{
	return ntohl(v);
}

unsigned short chfcoe_htons(unsigned short v)
{
	return htons(v);
}

unsigned int chfcoe_htonl(unsigned int v)
{
	return htonl(v);
}

unsigned int chfcoe_le32_to_cpu(unsigned int v)
{
	return le32_to_cpu(v);
}

unsigned long long chfcoe_le64_to_cpu(unsigned long long v)
{
	return le64_to_cpu(v);
}

unsigned short chfcoe_cpu_to_be16(unsigned short v)
{
	return cpu_to_be16(v);
}

unsigned int chfcoe_cpu_to_be32(unsigned int v)
{
	return cpu_to_be32(v);
}

unsigned long long chfcoe_cpu_to_be64(unsigned long long v)
{
	return cpu_to_be64(v);
}

unsigned long long chfcoe_be64_to_cpu(unsigned long long v)
{
	return be64_to_cpu(v);
}

unsigned short chfcoe_be16_to_cpu(unsigned short v)
{
	return be16_to_cpu(v);
}

unsigned int chfcoe_be32_to_cpu(unsigned int v)
{
	return be32_to_cpu(v);
}
