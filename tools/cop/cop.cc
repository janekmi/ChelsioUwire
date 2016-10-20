#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "error.h"
#include "ipfilter.h"
#include "offload_req.h"

#ifdef USE_STD_VECTOR
# include <vector>
# define Vector std::vector
#else
# include "vector.cc"
#endif

static int debug;
static const char *progname;

static bool line_continues(const char *line, size_t len)
{
    return len > 1 && line[len - 1] == '\n' && line[len - 2] == '\\';
}

static void __attribute__((noreturn)) usage(FILE *fp)
{
    fprintf(fp, "Usage: %s [-dht] [-o <outfile>] [policy-file]\n",
	    progname);
    exit(fp == stderr ? 1 : 0);
}

static void do_test(const IPFilter &c)
{
    struct OffloadReq req;
    char sip[128], dip[128];
    unsigned int sport, dport, vlan, tos, otype, mark;

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

	if (debug) {
	    const uint32_t *p = (const uint32_t *)&req;
	    for (unsigned int i = 0; i < sizeof(req) / 4; i++)
		printf("%2u %08x\n", i, htonl(p[i]));
	}

	printf("  match %d, optimized match %d\n\n", c.match(req),
	       c.optimized_match(req));
    }
}

int main(int argc, char *argv[])
{
    int c, test_mode = 0;
    char *line = NULL, *p;
    const char *out_name = NULL;
    size_t len = 0;
    ssize_t read;
    bool continuation = false;
    stringvec lines;
    IPFilter classifier;
    ErrorHandler eh;

    progname = argv[0];

    while ((c = getopt(argc, argv, "dhto:")) != -1)
	switch (c) {
	case 'd': debug++; break;
	case 'h': usage(stdout); break;
	case 'o': out_name = optarg; break;
	case 't': test_mode++; break;
	default: usage(stderr);
	}

    FILE *fp = argc <= optind ? stdin : fopen(argv[optind], "r");
    if (fp == NULL)
	err(1, "%s", argv[optind]);

    while ((read = getline(&line, &len, fp)) != -1) {
	for (p = line; isspace(*p); p++)
	    ;
	if (!*p || *p == '#')        // skip comments and blank lines
	    continue;

	bool cont = line_continues(line, read);
	if (cont) {
	    line[read - 2] = 0;
	    read -= 2;
	} else if (read > 0 && line[read - 1] == '\n') {
	    line[read - 1] = 0;
	    read--;
	}

	if (continuation)
	    lines[lines.size() - 1] += line;
	else
	    lines.push_back(line);
	continuation = cont;
    }
    if (line)
	free(line);

    if (debug) {
	printf("policy rules read:\n");
	for (stringvec::size_type i = 0; i < lines.size(); i++)
	    printf("  rule %zu: %s\n", i, lines[i].data());
	putchar('\n');
    }

    if (classifier.configure(lines, &eh) != 0)
	exit(1);

    if (debug) {
	classifier.dump_program(stdout);
	classifier.dump_integer_program(stdout);
	classifier.dump_offload_settings(stdout);
    }

    if (out_name && classifier.save(out_name) < 0)
	err(1, "%s", out_name);

    if (test_mode)
	do_test(classifier);

    return 0;
}

/* vim: set ts=8 sw=4: */
