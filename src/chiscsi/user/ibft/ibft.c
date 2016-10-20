/*
 *   ibft.c
 *      IBFT table access
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
//#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <netinet/in.h>

#include "ibft.h"

#define ISCSI_NAME_LENGTH_MAX	224
typedef struct chiscsi_context {
	char target_name[ISCSI_NAME_LENGTH_MAX];
	char target_ipaddr[32];
	unsigned int target_port;
	char initiator_name[ISCSI_NAME_LENGTH_MAX];
	char chap_name[ISCSI_NAME_LENGTH_MAX];
	char chap_secret[ISCSI_NAME_LENGTH_MAX];
	char rchap_name[ISCSI_NAME_LENGTH_MAX];
	char rchap_secret[ISCSI_NAME_LENGTH_MAX];
} chiscsi_context;

char *fname = "/dev/mem";
char *ibft_start = NULL;
chiscsi_context context;
char buf[256];
int debug = 1;

/* 
 * output the iBFT info. to a chelsio iscsi config file
 */
static int chiscsi_context_to_config_file(char *outfile)
{
	FILE *fhndl = fopen(outfile, "w");
	if (!fhndl) {
		fprintf(stderr, "ERR! Unable to open %s for write.\n",
			outfile);
		return 1;
	}
	fprintf(fhndl, "initiator:\n");
	fprintf(fhndl, "\tInitiatorName=%s\n", context.initiator_name);
	fprintf(fhndl, "\tTarget=%s@%s:%u\n", context.target_name,
		context.target_ipaddr, context.target_port);
	if (strlen(context.chap_secret)) {
		fprintf(fhndl, "\tAuth_CHAP_Initiator=\"%s\":\"%s\"\n",
			context.chap_name, context.chap_secret);
	}
	if (strlen(context.rchap_secret)) {
		fprintf(fhndl, "\tAuth_CHAP_Target=\"%s\":\"%s\"\n",
			context.rchap_name, context.rchap_secret);
	}
	fclose(fhndl);
	return 0;
}

/* 
 * iBFT standard header checking
 */
#define IBFT_STANDARD_HEADER_FIELD_VERIFY(H,F,V,RC)	\
	if ((H)->F != V) { \
		fprintf(stderr, "ERR! Standard header %s mismatch 0x%x, exp. 0x%x.\n", \
			#F, (H)->F, V); \
		RC = 1; \
	}

#define is_ibft_standard_header_valid(hdr,TYPE,rc)	\
	do { \
		IBFT_STANDARD_HEADER_FIELD_VERIFY(hdr, id, IBFT_ID_##TYPE, rc); \
		IBFT_STANDARD_HEADER_FIELD_VERIFY(hdr, version, IBFT_VERSION_##TYPE, rc); \
		IBFT_STANDARD_HEADER_FIELD_VERIFY(hdr, length, IBFT_LENGTH_##TYPE, rc); \
	}while(0)


/*
 * iBFT Read and Display
 */
static int is_byte_string_all_zero(uint8_t *bytes, int len)
{
	int i;
	for (i = 0; i < len && !bytes[i]; i++)
		;
	return (i == len);
}

/* display integer as unsigned */
#define display_field_integer(prefix,P,F,buf) \
	do { \
		int l = snprintf(buf, 256, "%u", (P)->F); \
		buf[l] = 0; \
		printf("%s_%s=%s\n", prefix,  #F, buf); \
	} while(0)
			
/* string is given by an offset and length */
#define display_field_string(prefix,name,offset,len,buf) \
	do { \
		if (len) { \
			int l = snprintf(buf, 256, "%.*s", len, ibft_start + offset); \
			buf[l] = 0; \
			printf("%s_%s=%s\n", prefix, name, buf); \
		} \
	} while(0)

/* display ip address: ipv4/ipv6 */
#define display_field_ip_address(prefix,P,F,buf) \
	do { \
		uint8_t *ip = (P)->F; \
		int l = 0; \
		if (!ip[0] && !ip[1] && !ip[2] && !ip[3] && \
            	    !ip[4] && !ip[5] && !ip[6] && !ip[7] && \
		    !ip[8] && !ip[9] && \
		    ip[10] == 0xFF && ip[11] == 0xFF) { \
			l = snprintf(buf, 256, "%d.%d.%d.%d", \
				ip[12], ip[13], ip[14], ip[15]); \
		} else { \
			l = snprintf(buf, 256, "%d.%d.%d.%d.%d.%d.%d.%d", \
					ntohs(ip[0]), ntohs(ip[1]), \
					ntohs(ip[2]), ntohs(ip[3]), \
					ntohs(ip[4]), ntohs(ip[5]), \
					ntohs(ip[6]), ntohs(ip[7])); \
		} \
		buf[l] = 0; \
		printf("%s_%s=%s\n", prefix, #F, buf);  \
	} while(0)

/* display lun number */
#define display_field_lun(prefix,P,F,buf) \
	do { \
		int l = snprintf(buf, 256, "%x%x%x%x%x%x%x%x", \
				(P)->F[0], (P)->F[1], (P)->F[2], (P)->F[3],  \
				(P)->F[4], (P)->F[5], (P)->F[6], (P)->F[7]); \
		buf[l] = 0; \
		printf("%s_%s=%s\n", prefix, #F, buf); \
	} while(0)

/* MAC address */
#define display_field_mac(prefix,P,F,buf) \
	do { \
		int l = sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", \
			(P)->F[0], (P)->F[1], (P)->F[2], (P)->F[3], \
			(P)->F[4], (P)->F[5]); \
		buf[l] = 0; \
		printf("%s_%s=%s\n", prefix, #F, buf); \
	} while(0)

/* PCI bus:device:function */
#define display_field_pci_info(prefix,P,F,buf) \
	do { \
		int l = snprintf(buf, 256, "%d:%d:%d", \
				((P)->F & 0xff00) >> 8, ((P)->F & 0xf8) >> 3, \
				((P)->F & 0x7)); \
		buf[l] = 0; \
		printf("%s_%s=%s\n", prefix, #F, buf); \
	} while(0)
	
	
static void ibft_standard_table_hdr_display(char *prefix, ibft_hdr *hdr)
{
	printf("\n%s BLOCK: %s %s\n", prefix, 
		(hdr->flags & IBFT_BLOCK_FLAG_VALID) ? "VALID" : "",
		(hdr->flags & IBFT_BLOCK_FLAG_FW_BOOT_SEL) ? "BOOT_SEL" : "");
	display_field_integer(prefix, hdr, id, buf);
	display_field_integer(prefix, hdr, version, buf);
	display_field_integer(prefix, hdr, length, buf);
	display_field_integer(prefix, hdr, index, buf);
	display_field_integer(prefix, hdr, flags, buf);
}

static void ibft_nic_display(char *prefix, ibft_nic *nic)
{
	uint8_t	selected = nic->hdr.flags & IBFT_NIC_FLAG_FW_BOOT_SEL;
	if (!debug && !selected)
		return;

	if (debug) ibft_standard_table_hdr_display(prefix, &nic->hdr);

//	if (is_byte_string_all_zero(nic->dhcp, 16)) {
		if (!is_byte_string_all_zero(nic->ip_addr, 16)) 
			display_field_ip_address(prefix, nic, ip_addr, buf);
		display_field_integer(prefix, nic, subnet_mask_prefix, buf);
		display_field_integer(prefix, nic, origin, buf);
		if (!is_byte_string_all_zero(nic->gateway, 16)) 
			display_field_ip_address(prefix, nic, gateway, buf);
		if (!is_byte_string_all_zero(nic->primary_dns, 16)) 
			display_field_ip_address(prefix, nic, primary_dns, buf);
		if (!is_byte_string_all_zero(nic->secondary_dns, 16)) 
			display_field_ip_address(prefix, nic, secondary_dns, buf);
		display_field_integer(prefix, nic, vlan, buf);
		display_field_mac(prefix, nic, mac, buf);
		display_field_pci_info(prefix, nic, pci_info, buf);		

//	} else if (!is_byte_string_all_zero(nic->dhcp, 16)) {
//		display_field_ip_address(prefix, nic, dhcp, buf);
//	}
	display_field_string(prefix, "hostname", nic->hostname_offset,
			     nic->hostname_length, buf);
}

static void ibft_initiator_display(char *prefix, ibft_initiator *ii)
{
	uint8_t	selected = ii->hdr.flags & IBFT_INITIATOR_FLAG_FW_BOOT_SEL;
	if (!debug && !selected)
		return;

	if (debug) ibft_standard_table_hdr_display(prefix, &ii->hdr);
		
	display_field_string(prefix, "name", ii->initiator_name_offset,
			     ii->initiator_name_length, buf);
	if (selected && ii->initiator_name_length) {
		strncpy(context.initiator_name, buf, ISCSI_NAME_LENGTH_MAX);
	}
	if (!is_byte_string_all_zero(ii->isns_server, 16)) 
		display_field_ip_address(prefix, ii, isns_server, buf);
	if (!is_byte_string_all_zero(ii->slp_server, 16)) 
		display_field_ip_address(prefix, ii, slp_server, buf);
	if (!is_byte_string_all_zero(ii->primary_radius_server, 16)) 
		display_field_ip_address(prefix, ii, primary_radius_server, buf);
	if (!is_byte_string_all_zero(ii->secondary_radius_server, 16)) 
		display_field_ip_address(prefix, ii, secondary_radius_server, buf);
}

static void ibft_target_display(char *prefix, ibft_target *it)
{
	uint8_t	selected = it->hdr.flags & IBFT_TARGET_FLAG_FW_BOOT_SEL;
	if (!debug && !selected)
		return;

	if (debug) ibft_standard_table_hdr_display(prefix, &it->hdr);

	display_field_string(prefix, "name", it->target_name_offset,
			     it->target_name_length, buf);
	if (selected && it->target_name_length) {
		strncpy(context.target_name, buf, ISCSI_NAME_LENGTH_MAX);
	}

	if (!is_byte_string_all_zero(it->ip_addr, 16)) {
		display_field_ip_address(prefix, it, ip_addr, buf);
		if (selected) 
			strncpy(context.target_ipaddr, buf, 32);
	}
	display_field_integer(prefix, it, port, buf);
	if (selected) 
		context.target_port = it->port;

	display_field_lun(prefix, it, boot_lun, buf);
	display_field_integer(prefix, it, nic_association, buf);
	display_field_integer(prefix, it, chap_type, buf);

	display_field_string(prefix, "chap_name", it->chap_name_offset,
		     	     it->chap_name_length, buf);
	if (selected && it->chap_name_length)
		strncpy(context.chap_name, buf, ISCSI_NAME_LENGTH_MAX);

	display_field_string(prefix, "chap_secret", it->chap_secret_offset,
			     it->chap_secret_length, buf);
	if (selected && it->chap_secret_length)
		strncpy(context.chap_secret, buf, ISCSI_NAME_LENGTH_MAX);

	display_field_string(prefix, "reverse_chap_name", it->rchap_name_offset,
		     	     it->rchap_name_length, buf);
	if (selected && it->rchap_name_length)
		strncpy(context.rchap_name, buf, ISCSI_NAME_LENGTH_MAX);

	display_field_string(prefix, "reverse_chap_secret",
			     it->rchap_secret_offset, it->rchap_secret_length, buf);
	if (selected && it->rchap_secret_length)
		strncpy(context.rchap_secret, buf, ISCSI_NAME_LENGTH_MAX);
}

static int ibft_display(void)
{
	ibft_control	*control;
	ibft_nic	*nic[2] = {NULL, NULL};
	ibft_target	*target[2] = {NULL, NULL};
	ibft_initiator	*initiator = NULL;
	int		rv = 0;

	control = (ibft_control *)(ibft_start + sizeof(ibft_table_hdr));
	is_ibft_standard_header_valid(&control->hdr, CONTROL, rv);
	if (rv) return rv;

	/* extension NOT supported */

	if (control->initiator_offset) {
		initiator = (ibft_initiator *)(ibft_start + 
						control->initiator_offset);
		is_ibft_standard_header_valid(&initiator->hdr, INITIATOR, rv);
		if (rv) return rv;
	}

	if (control->nic0_offset) {
		nic[0] = (ibft_nic *)(ibft_start + control->nic0_offset);
		is_ibft_standard_header_valid(&(nic[0]->hdr), NIC, rv);
		if (rv) return rv;
	}

	if (control->nic1_offset) {
		nic[1] = (ibft_nic *)(ibft_start + control->nic1_offset);
		is_ibft_standard_header_valid(&(nic[1]->hdr), NIC, rv);
		if (rv) return rv;
	}

	if (control->target0_offset) {
		target[0] = (ibft_target *)(ibft_start + control->target0_offset);
		is_ibft_standard_header_valid(&(target[0]->hdr), TARGET, rv);
		if (rv) return rv;
	}

	if (control->target1_offset) {
		target[1] = (ibft_target *)(ibft_start + control->target1_offset);
		is_ibft_standard_header_valid(&(target[1]->hdr), TARGET, rv);
		if (rv) return rv;
	}

	if (initiator)
		ibft_initiator_display("ISCSI_INITIATOR", initiator);
	if (nic[0])
		ibft_nic_display(debug ? "NIC0" : "ISCSI_INITIATOR_NIC", nic[0]);
	if (nic[1])
		ibft_nic_display(debug ? "NIC1" : "ISCSI_INITIATOR_NIC", nic[1]);
	if (target[0])
		ibft_target_display(debug ? "ISCSI_TARGET0" : "ISCSI_TARGET", target[0]);
	if (target[1])
		ibft_target_display(debug ? "ISCSI_TARGET1" : "ISCSI_TARGET", target[1]);
	
	return 0;
}

static void display_usage(char *cmd)
{
	printf("Usage: %s [-d] [-f <filename>]\n	\
		-d		-- debug mode, dump the content to stdout\n \
		-b		-- boot according to the ibft\n \
		-f <filename>	-- write chelsio config format\n",
		cmd);
}

int main (int argc, char **argv)
{
	unsigned int	offset = 512 * 1024; /* 512K */
	unsigned int	length = 512 * 1024; /* 512K */
	char	*outfile = NULL;
	char	*ibft_mem = NULL;
	int	fd, option, i, boot = 0;
	int 	rv = 0;

	while ( (option = getopt(argc, argv, "f:hd")) != -1) {
		switch (option) {
			case 'b':
				boot = 1;
				break;
			case 'f':
				outfile = optarg;	
				break;
			case 'd':
				debug = 1;
				break;
			case 'h':
				display_usage(argv[0]);
				exit(1);
			default:
				fprintf(stderr, "Unknown option %c.\n", option);
				display_usage(argv[0]);
				exit(1);
		}
	}

	fd = open(fname, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Could not open %s: %s (%d)\n",
			fname, strerror(errno), errno);
		exit(1);
	} else {
		struct stat fstat;
		if (stat(fname, &fstat)!=0) {
			fprintf(stderr, "Could not stat file %s: %s (%d)\n",
				fname, strerror(errno), errno);
			exit(1);
		}
		if (fstat.st_size > 0) {
			offset = 0;
			length = fstat.st_size;
		}
	}
	
	/* iBFT: 
	   search for the table header signature in the system memory 
	   between 512K and 1024K 
	*/
	ibft_mem = mmap(NULL, length, PROT_READ, MAP_PRIVATE, fd, offset);
	if (ibft_mem == MAP_FAILED) {
		fprintf(stderr, "Could not mmap %s: %s (%d)\n",
			fname, strerror(errno), errno);
		exit(1);
	} 
	for (ibft_start = ibft_mem, i = 0; i < length; i++, ibft_start++) {
		ibft_table_hdr	*hdr = (ibft_table_hdr *)ibft_start;
		if (memcmp(ibft_start, IBFT_SIGNATURE, strlen(IBFT_SIGNATURE)))
			continue;
		/* match find, check the table header */	
		if (hdr->revision != IBFT_REVISION) 
			continue;
		/* header checksum */	
		if ((i + hdr->length) <= (offset + length)) {
			int j;
			unsigned char csum;
			for (j = 0, csum = 0; j < hdr->length; j++)
				 csum += ibft_start[j];
			if (csum) {
				fprintf(stderr, "Header checksum not zero 0x%x \n", csum);
				rv = 1;
				goto done;
			}
                }
		break;
	}

	if (i >= length) {
		fprintf(stderr, "%s: could not find signature %s.\n",
			fname, IBFT_SIGNATURE);
		rv = 1;
		goto done;
	}

	memset(&context, 0, sizeof(chiscsi_context));
	rv = ibft_display();

done:
	munmap(ibft_mem, length);
	close(fd);

	if (outfile && !rv)
		rv = chiscsi_context_to_config_file(outfile);
	exit(rv);
}
