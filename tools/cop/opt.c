#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <err.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "offload_req.h"

struct ProgInst {              /* classifier program "instructions" */
    int32_t  offset;
    uint32_t mask;
    uint32_t value;
    int32_t  next[2];
};

static const char *progname;

static void __attribute__((noreturn)) usage(FILE *fp)
{
    fprintf(fp, "Usage: %s policy-file\n", progname);
    exit(fp == stderr ? 1 : 0);
}

static int run_classifier(const struct ClassifierFileHeader *h,
			  const unsigned int *progs,
			  const struct OffloadReq *req)
{
    if (h->output_everything >= 0)
	return h->output_everything;

    const struct ProgInst *prog_start = (const struct ProgInst *)progs;
    const uint32_t *r = (const uint32_t *)req;
    int pos = 0;

    do {
	const struct ProgInst *curr = prog_start + pos;
	uint32_t data = r[curr->offset] & curr->mask;
	pos = data == curr->value ? curr->next[1] : curr->next[0];
    } while (pos > 0);

    return -pos;
}

static int run_opt_classifier(const struct ClassifierFileHeader *h,
			      const unsigned int *progs,
			      const struct OffloadReq *req)
{
    if (h->output_everything >= 0)
	return h->output_everything;

    const uint32_t *r = (const uint32_t *)req;
    const uint32_t *pr = &progs[h->prog_size * 5], *pp;

    while (1) {
	int off = pr[0] & 0xffff;
	uint32_t data = r[off] & pr[3];
	
	for (off = pr[0] >> 16, pp = pr + 4; off; off--, pp++)
	    if (*pp == data) {
		off = pr[2];
		goto gotit;
	    }
	off = pr[1];
gotit:
	if (off <= 0)
	    return -off;
	pr += off;
    }
}

static void do_test(const struct ClassifierFileHeader *h,
		    const unsigned int *progs)
{
    struct OffloadReq req;
    char sip[128], dip[128];
    int match, opt_match;
    unsigned int sport, dport, vlan, tos, otype, mark;
    struct OffloadSettings *settings, *os;

    settings = (void *)&progs[h->prog_size * 5 + h->opt_prog_size];

    memset(&req, 0, sizeof(req));
    printf("\nenter sip, dip, sport, dport, vlan, tos, open type, mark\n");
    while (scanf("%s %s %u %u %u %u %u %u", sip, dip, &sport, &dport, &vlan,
		 &tos, &otype, &mark) == 8) {
	struct in_addr addr;

	inet_aton(sip, &addr);
	req.sip[0] = addr.s_addr;
	inet_aton(dip, &addr);
	req.dip[0] = addr.s_addr;
	req.sport = htons(sport);
	req.dport = htons(dport);
	req.ipvers_opentype = (otype << 4) | 4;
	req.tos = tos;
	req.vlan = htons(vlan);
	req.mark = mark;

	match = run_classifier(h, progs, &req);
	opt_match = run_opt_classifier(h, progs, &req);
	os = &settings[match];
	printf("  match %d, opt match %d\n", match, opt_match);
	printf("  offload %u, ddp %d, coalesce %d, cong_algo %d, queue %d, "
	       "class %d, tstamp %d, sack %d\n\n",
		os->offload, os->ddp, os->rx_coalesce, os->cong_algo,
		os->bind_q, os->sched_class, os->tstamp, os->sack);
    }
}

static int validate(const struct ClassifierFileHeader *h,
		    const unsigned int *progs)
{
    /*
     * We validate the following:
     * - Program sizes match what's in the header
     * - Branch targets are within the program
     * - Outputs are valid
     */
    if (h->output_everything >= 0 && h->output_everything > h->nrules)
	errx(1, "illegal output_everything %d in header",
	     h->output_everything);

    const struct ProgInst *prog_start = (const struct ProgInst *)progs;
    const struct ProgInst *pi = prog_start;
    int i, inst;

    for (i = 0; i < h->prog_size; i++, pi++) {
	if (pi->offset < 0 || pi->offset >= sizeof(struct OffloadReq) / 4)
	    errx(1, "illegal offset %d at instruction %zd", pi->offset,
		 pi - prog_start);
	if (pi->next[0] < 0 && -pi->next[0] > h->nrules)
	    errx(1, "illegal output %d at instruction %zd", -pi->next[0],
		 pi - prog_start);
	if (pi->next[1] < 0 && -pi->next[1] > h->nrules)
	    errx(1, "illegal output %d at instruction %zd", -pi->next[1],
		 pi - prog_start);
	if (pi->next[0] > 0 && pi->next[0] >= h->prog_size)
	    errx(1, "illegal branch target %d at instruction %zd", pi->next[0],
		 pi - prog_start);
	if (pi->next[1] > 0 && pi->next[1] >= h->prog_size)
	    errx(1, "illegal branch target %d at instruction %zd", pi->next[1],
		 pi - prog_start);
    }

    const uint32_t *opt_prog_start = &progs[h->prog_size * 5];
    const uint32_t *p = opt_prog_start;

    for (inst = i = 0; i < h->opt_prog_size; inst++) {
	unsigned int off = *p & 0xffff, nvals = *p >> 16;

	if (off >= sizeof(struct OffloadReq) / 4)
	    errx(1, "illegal offset %u at opt instruction %d", off, inst);
	if ((int32_t)p[1] < 0 && -p[1] > h->nrules)
	    errx(1, "illegal output %d at opt instruction %d", -p[1], inst);
	if ((int32_t)p[2] < 0 && -p[2] > h->nrules)
	    errx(1, "illegal output %d at opt instruction %d", -p[2], inst);
	if ((int32_t)p[1] > 0 && p[1] >= h->opt_prog_size)
	    errx(1, "illegal branch target %d at opt instruction %d", p[1],
		 inst);
	if ((int32_t)p[2] > 0 && p[2] >= h->opt_prog_size)
	    errx(1, "illegal branch target %d at opt instruction %d", p[2],
		 inst);
	p += 4 + nvals;
	i += 4 + nvals;
	if (i > h->opt_prog_size)
	    errx(1, "too many values %u for opt instruction %d", nvals, inst);
    }

    return 0;
}

int main(int argc, char *argv[])
{
    progname = argv[0];
    if (argc != 2)
	usage(stderr);

    int fd = open(argv[1], O_RDONLY);
    if (fd < 0)
	err(1, "%s", argv[1]);

    struct ClassifierFileHeader h;
    if (read(fd, &h, sizeof(h)) != sizeof(h)) {
	if (errno)
	    err(1, "%s", argv[1]);
	else
	    errx(1, "incomplete header found in %s", argv[1]);
    }

    if (h.output_everything < 0 && h.prog_size + h.opt_prog_size == 0)
	errx(1, "no programs found in %s", argv[1]);

    unsigned int prog_size = h.prog_size * sizeof(struct ProgInst) +
			     h.opt_prog_size * sizeof(int) +
			     (h.nrules + 1) * sizeof(struct OffloadSettings);
    unsigned int *progs = malloc(prog_size);
    if (!progs)
	err(1, "insufficient memory to load classifier programs");

    if (prog_size && read(fd, progs, prog_size) != prog_size) {
	if (errno)
	    err(1, "%s", argv[1]);
	else
	    errx(1, "%s is too short", argv[1]);
    }

    close(fd);

    if (validate(&h, progs) < 0)
	errx(1, "corrupted classifier programs");

    printf("%s:\n  version %u\n  program length %zu bytes\n  "
	   "alternate program length %zu bytes\n", argv[1], h.vers,
	   h.prog_size * sizeof(struct ProgInst),
	   h.opt_prog_size * sizeof(int));

    do_test(&h, progs);
    free(progs);
    return 0;
}

/* vim: set ts=8 sw=4: */
