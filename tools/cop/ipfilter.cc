/*
 * ipfilter.{cc,h} -- IP-packet filter with tcpdumplike syntax
 * Eddie Kohler
 *
 * Copyright (c) 2000-2007 Mazu Networks, Inc.
 * Copyright (c) 2004-2007 Regents of the University of California
 * Copyright (c) 2007-2009 Dimitris Michailidis
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.
 */

#include <fcntl.h>
#include <assert.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include "ipfilter.h"

#define ACTION_SEP "=>"

struct Entry {
    const char *name;
    uint32_t value;
};

static const Entry type_entries[] = {
    { "aopen", IPFilter::TYPE_AOPEN },
    { "dest", IPFilter::TYPE_SYNTAX },
    { "dscp", IPFilter::FIELD_DSCP },
    { "dst", IPFilter::TYPE_SYNTAX },
    { "host", IPFilter::TYPE_HOST },	//Its Ipv4 or Ipv6 address
    { "listen", IPFilter::TYPE_LISTEN },
    { "mark", IPFilter::TYPE_MARK },
    { "net", IPFilter::TYPE_NET },	//Its a network mask
    { "not", IPFilter::TYPE_SYNTAX },
    { "popen", IPFilter::TYPE_POPEN },
    { "port", IPFilter::TYPE_PORT },
    { "src", IPFilter::TYPE_SYNTAX },
    { "tos", IPFilter::FIELD_TOS },
    { "vers", IPFilter::FIELD_VERSION },
    { "vlan", IPFilter::FIELD_VLAN },
    { 0, 0 }
};

static bool cp_integer(const std::string &s, int *valp)
{
    char *p;

    *valp = strtoul(s.data(), &p, 0);
    return *p == 0 && s[0];
}

static bool cp_integer(const std::string &s, uint32_t *valp)
{
    char *p;

    *valp = strtoul(s.data(), &p, 0);
    return *p == 0 && s[0];
}

static bool cp_integer(const std::string &s, int16_t *valp)
{
    char *p;
    unsigned long v;

    *valp = v = strtoul(s.data(), &p, 0);
    return *p == 0 && s[0] && (v & ~0xffffUL) == 0;
}

static bool cp_cong_algo(const std::string &s, int8_t *valp)
{
    if (s == "reno")
	*valp = 0;
    else if (s == "tahoe")
	*valp = 1;
    else if (s == "newreno")
	*valp = 2;
    else if (s == "highspeed")
	*valp = 3;
    else
	return false;
    return true;
}

static int ip_address_portion(const char *s, uint8_t *addr)
{
    int d, part;

    for (d = 0; d < 4 && isdigit(*s); d++) {
	for (part = 0; isdigit(*s) && part <= 255; s++)
	    part = part * 10 + *s - '0';
	if (part > 255)
	    return 0;
	addr[d] = part;

	if (*s == '.')
	    s++;
    }

    memset(addr + d, 0, 4 - d);
    return *s == 0 ? d : 0;
}

static bool cp_ip_address(const std::string &str, uint8_t *addr,
			  int af_allowed, int *af)
{
    const char *s = str.c_str();
    bool v6 = strchr(s, ':') != NULL;

    if (v6) {
       	if (af_allowed == AF_INET)
	    return false;
	if (inet_pton(AF_INET6, s, addr) <= 0)
	    return false;
	if (af)
	    *af = AF_INET6;
    } else {
	if (af_allowed == AF_INET6)
	    return false;
	if (ip_address_portion(s, addr) != 4)
	    return false;
	if (af)
	    *af = AF_INET;
    }
    return true;
}

/*
 * cp_ip_mask is similar to cp_ip_address except it ensures the value read is
 * indeed a mask rather than an arbitrary address.  It also does not support
 * AF_UNSPEC since a mask should match the corresponding address's family.
 */
static bool cp_ip_mask(const std::string &str, uint8_t *mask, int af)
{
    if (!cp_ip_address(str, mask, af, NULL))
	return false;

    int addr_len = af == AF_INET ? 4 : 16;
    while (addr_len--) {
	uint8_t c = ~*mask++;
	if (c & (c + 1))
	    return false;
    }
    return true;
}

static bool cp_ip_prefix(const std::string &str, uint8_t *return_value,
			 uint8_t *return_mask, bool allow_bare_address,
			 int af_allowed, int *af)
{
    int addr_bytes;
    int prefix_bits;
    std::string ip_part, mask_part;
    std::string::size_type slash = str.rfind('/');

    if (slash == std::string::npos && allow_bare_address)
	ip_part = str;
    else if (slash != std::string::npos && slash < str.length() - 1) {
	ip_part = str.substr(0, slash);
	mask_part = str.substr(slash + 1);
    } else
	return false;

    bool v6 = ip_part.find(':') != std::string::npos;
    if ((v6 && af_allowed == AF_INET) || (!v6 && af_allowed == AF_INET6))
	return false;

    int addr_len = v6 ? 16 : 4;

    // read IP address part
    if (v6) {
	if (inet_pton(AF_INET6, ip_part.c_str(), return_value) <= 0)
	    return false;
	addr_bytes = 16;
    } else {
	addr_bytes = ip_address_portion(ip_part.c_str(), return_value);
	if (addr_bytes == 0)
	    return false;
    }

    if (af)
	*af = v6 ? AF_INET6 : AF_INET;

    // check mask
    if (allow_bare_address && !mask_part.length() && addr_bytes == addr_len) {
	memset(return_mask, 255, addr_len);
	return true;
    }

    if (!cp_integer(mask_part, &prefix_bits) || prefix_bits < 0 ||
	prefix_bits > addr_len * 8 || addr_bytes < (prefix_bits + 7) / 8)
	return false;

    // set mask bits
    memset(return_mask, 0, addr_len);
    memset(return_mask, 0xff, prefix_bits / 8);
    if (prefix_bits % 8)
	return_mask[prefix_bits / 8] = 0xff << (8 - prefix_bits % 8);

    return true;
}

static inline int ffs_msb(uint32_t x)
{
    return x ? __builtin_clz(x) + 1 : 0;
}

int IPFilter::lookup(const std::string &word, int type, uint32_t &data) const
{
    if (!isalpha(word[0])) // all potential translations start with a letter
	return -1;

    // type queries always win if they occur
    if (type == 0 || type == TYPE_TYPE)
	for (const Entry *p = type_entries; p->name; p++)
	    if (word == p->name) {
		data = p->value;
		return data == TYPE_SYNTAX ? -1 : TYPE_TYPE;
	    }

    if (type == 0 || type == TYPE_PORT) {
	/*
	 * Note that some glibcs are buggy and will match not only service
	 * names but random words in the /etc/services comments.  At least
	 * the isalpha above doesn't let them match numbers and operators.
	 */
	struct servent *serv = getservbyname(word.c_str(), "tcp");
	if (serv) {
	    data = ntohs(serv->s_port);
	    return TYPE_PORT;
	}
    }
    return -1;
}

void IPFilter::Primitive::clear()
{
    _type = _srcdst = 0;
    _data = 0;
    _op = OP_EQ;
    _op_negated = false;
}

void IPFilter::Primitive::set_type(int type, ErrorHandler *errh)
{
    if (_type)
	errh->error("type specified twice");
    _type = type;
}

void IPFilter::Primitive::set_srcdst(int srcdst, ErrorHandler *errh)
{
    if (_srcdst)
	errh->error("'src' or 'dst' specified twice");
    _srcdst = srcdst;
}

int IPFilter::Primitive::set_mask(uint32_t full_mask, int shift,
				  uint32_t provided_mask, ErrorHandler *errh)
{
    uint32_t data = _u.u;
    uint32_t this_mask = provided_mask ? provided_mask : full_mask;

    if ((this_mask & full_mask) != this_mask)
	return errh->error("mask 0x%X out of range (0-0x%X)", provided_mask,
			   full_mask);

    if (_op == OP_GT || _op == OP_LT) {
	// Check for comparisons that are always true or false.
	if ((_op == OP_LT && (data == 0 || data > this_mask))
	    || (_op == OP_GT && data >= this_mask)) {
	    bool will_be = (_op == OP_LT && data > this_mask ?
			    !_op_negated : _op_negated);
	    errh->warning("relation '%s %u' is always %s (range 0-%u)",
			  unparse_op(), data, will_be ? "true" : "false",
			  this_mask);
	    _u.u = _mask.u = 0;
	    _op_negated = !will_be;
	    _op = OP_EQ;
	    return 0;
	}

	// value < X == !(value > (X - 1))
	if (_op == OP_LT) {
	    _u.u--;
	    _op_negated = !_op_negated;
	    _op = OP_GT;
	}

	_u.u = (_u.u << shift) | ((1 << shift) - 1);
	_mask.u = (this_mask << shift) | ((1 << shift) - 1);
	// Want (_u.u & _mask.u) == _u.u.
	// So change 'tcp[0] & 5 > 2' into the equivalent 'tcp[0] & 5 > 1':
	// find the highest bit in _u that is not set in _mask,
	// and turn on all lower bits.
	if ((_u.u & _mask.u) != _u.u) {
	    uint32_t full_mask_u = (full_mask << shift) | ((1 << shift) - 1);
	    uint32_t missing_bits = (_u.u & _mask.u) ^ (_u.u & full_mask_u);
	    uint32_t add_mask = 0xFFFFFFFFU >> ffs_msb(missing_bits);
	    _u.u = (_u.u | add_mask) & _mask.u;
	}
	return 0;
    }

    if (data > full_mask)
	return errh->error("value %u out of range (0-%u)", data, full_mask);

    _u.u = data << shift;
    _mask.u = this_mask << shift;
    return 0;
}

std::string IPFilter::Primitive::unparse_type(int srcdst, int type)
{
    int len = 0;
    char buf[512];
    const char *p = NULL;

    switch (srcdst) {
	case SD_SRC: p = "src "; break;
	case SD_DST: p = "dst "; break;
	case SD_OR:  p = "src or dst "; break;
	case SD_AND: p = "src and dst "; break;
    }
    if (p)
	len = sprintf(buf, "%s", p);

    p = NULL;
    switch (type) {
	case TYPE_NONE: p = "<none>"; break;
	case TYPE_HOST: p = "host"; break;
	case TYPE_PORT: p = "port"; break;
	case TYPE_NET: p = "net"; break;
	case TYPE_LISTEN: p = "listen"; break;
	case TYPE_AOPEN: p = "active open"; break;
	case TYPE_POPEN: p = "passive open"; break;
	case TYPE_MARK: p = "mark"; break;
	default:
	    if (type & TYPE_FIELD) {
		switch (type) {
		    case FIELD_VERSION: p = "vers"; break;
		    case FIELD_TOS: p = "tos"; break;
		    case FIELD_DSCP: p = "dscp"; break;
		    case FIELD_VLAN: p = "vlan"; break;
		}
	    } else
		sprintf(buf + len, "<unknown type %d>", type);
	    break;
    }

    if (p)
	sprintf(buf + len, "%s", p);

    return std::string(buf);
}

std::string IPFilter::Primitive::unparse_type() const
{
    return unparse_type(_srcdst, _type);
}

const char * IPFilter::Primitive::unparse_op() const
{
    if (_op == OP_GT)
	return _op_negated ? "<=" : ">";
    if (_op == OP_LT)
	return _op_negated ? ">=" : "<";
    return _op_negated ? "!=" : "=";
}

void IPFilter::Primitive::simple_negate()
{
    assert(negation_is_simple());
    _op_negated = !_op_negated;
}

/*
 * Returns whether an expression primitive has integer type
 */
bool IPFilter::Primitive::is_int_type() const
{
    return (_type & TYPE_FIELD) || _type == TYPE_MARK || _type == TYPE_PORT;
}

int IPFilter::Primitive::check(const Primitive &p, uint32_t provided_mask,
			       ErrorHandler *errh)
{
    // if _type is erroneous, return -1 right away
    if (_type < 0)
	return -1;

    // set _type if it was not specified
    if (!_type) {
retry:
	switch (_data) {
	case TYPE_HOST:
	case TYPE_NET:
	case TYPE_PORT:
	    _type = _data;
	    if (!_srcdst)
		_srcdst = p._srcdst;
	    break;

	case TYPE_INT:
	    if (!p.is_int_type())
		return errh->error("missing type for '%d'", _u.i);
	    _data = p._type;
	    goto retry;

	case TYPE_NONE:
	    return errh->error("partial directive");

	default:
	    if (_data & TYPE_FIELD)
		_type = _data;
	    else
		return errh->error("unknown type '%s'",
				   unparse_type(0, _data).c_str());
	    break;
	}
    }

    // check that _data and _type agree
    switch (_type) {
    case TYPE_HOST:
	if (_data != TYPE_HOST)
	    return errh->error("IP address missing in 'host' directive");
	if (_op != OP_EQ)
	    return errh->error("can't use relational operators with 'host'");
	if (provided_mask)
	    return errh->error("can't use masks with 'host', use 'net' instead");
	memset(_mask.c, 0xff, sizeof(_mask.c));
	break;

    case TYPE_NET:
	if (_data != TYPE_NET)
	    return errh->error("IP prefix missing in 'net' directive");
	if (_op != OP_EQ)
	    return errh->error("can't use relational operators with 'net'");
	if (provided_mask)
	    return errh->error("can't use & masks with 'net'");
	_type = TYPE_HOST;
	// _mask already set
	break;

    case TYPE_PORT:
	if (_data == TYPE_INT)
	    _data = TYPE_PORT;
	if (_data != TYPE_PORT)
	    return errh->error("port number missing in 'port' directive");
	if (set_mask(0xFFFF, 0, provided_mask, errh) < 0)
	    return -1;
	break;

    case TYPE_MARK:
	if (_data == TYPE_INT)
	    _data = TYPE_MARK;
	else if (_data != TYPE_MARK)
	    return errh->error("mark value missing in 'mark' directive");
	if (set_mask(0xFFFFFFFFU, 0, provided_mask, errh) < 0)
	    return -1;
	break;

    case TYPE_LISTEN:
	if (_data != TYPE_NONE)
	    return errh->error("'listen' directive takes no data");
	if (provided_mask)
	    return errh->error("can't use masks with 'listen'");
	_mask.u = 3;
	_u.u = OPEN_TYPE_LISTEN;
	break;

    case TYPE_AOPEN:
	if (_data != TYPE_NONE)
	    return errh->error("'aopen' directive takes no data");
	if (provided_mask)
	    return errh->error("can't use masks with 'aopen'");
	_mask.u = 3;
	_u.u = OPEN_TYPE_ACTIVE;
	break;

    case TYPE_POPEN:
	if (_data != TYPE_NONE)
	    return errh->error("'popen' directive takes no data");
	if (provided_mask)
	    return errh->error("can't use masks with 'popen'");
	_mask.u = 3;
	_u.u = OPEN_TYPE_PASSIVE;
	break;

    default:
	if (_type & TYPE_FIELD) {
	    if (_data == TYPE_INT)
		_data = _type;
	    else if (_data != _type)
		return errh->error("value missing in '%s' directive",
				   unparse_type().c_str());

	    int nbits = ((_type & FIELD_LENGTH_MASK) >> FIELD_LENGTH_SHIFT) + 1;
	    uint32_t mask = (nbits == 32 ? 0xFFFFFFFFU : (1 << nbits) - 1);
	    if (set_mask(mask, 0, provided_mask, errh) < 0)
		return -1;
	}
	break;
    }

    // fix _srcdst
    if (_type == TYPE_HOST || _type == TYPE_PORT) {
	if (_srcdst == 0)
	    _srcdst = SD_OR;
    } else if (_srcdst) {
	_srcdst = 0;
	errh->warning("'src' or 'dst' is meaningless with '%s'",
		      unparse_type().c_str());
    }

    return 0;
}

/*
 * Field explanation:
 *
 * offset: offset of the value we'll compare against in 32-bit units
 * swapped: true if the value in the primitive is in the same byte order as the
 *          value it will be compared against
 */
void IPFilter::Primitive::add_comparison_exprs(Classifier *c, Vector<int> &tree,
	int offset, int shift, bool swapped, bool op_negate, int op_shift) const
{
    assert(_op == IPFilter::OP_EQ || _op == IPFilter::OP_GT);

    uint32_t mask = _mask.u;
    uint32_t u = _u.u & mask;
     if (op_shift != 0) {
	u = ((uint32_t *)(&_u))[op_shift];
	mask = ((uint32_t *)(&_mask))[op_shift];
	u = u & mask;
    }
    if (swapped) {
	mask = ntohl(mask);
	u = ntohl(u);
    }

    if (_op == IPFilter::OP_EQ) {
	c->add_expr(tree, offset, htonl(u << shift), htonl(mask << shift));
	if (_op_negated && op_negate)
	    c->negate_expr_subtree(tree);
	return;
    }

    // To implement a greater-than test for "input&MASK > U":
    // Check the top bit of U&MASK.
    // If the top bit is 0, then:
    //    Find TOPMASK, the top bits of MASK s.t. U&TOPMASK == 0.
    //    If "input&TOPMASK == 0", continue testing with lower bits of
    //    U and MASK; combine with OR.
    //    Otherwise, succeed.
    // If the top bit is 1, then:
    //    Find TOPMASK, the top bits of MASK s.t. (U+1)&TOPMASK == TOPMASK.
    //    If "input&TOPMASK == TOPMASK", continue testing with lower bits of
    //    U and MASK; combine with AND.
    //    Otherwise, fail.
    // Stop testing when U >= MASK.

    int high_bit_record = 0;
    int count = 0;

    while (u < mask) {
	int high_bit = (u > (mask >> 1));
	int first_different_bit = 33 - ffs_msb(high_bit ? ~(u+1) & mask : u);
	uint32_t upper_mask;
	if (first_different_bit == 33)
	    upper_mask = mask;
	else
	    upper_mask = mask & ~((1 << first_different_bit) - 1);
	uint32_t upper_u = (high_bit ? 0xFFFFFFFF & upper_mask : 0);

	c->start_expr_subtree(tree);
	c->add_expr(tree, offset, htonl(upper_u << shift),
		    htonl(upper_mask << shift));
	if (!high_bit)
	    c->negate_expr_subtree(tree);
	high_bit_record = (high_bit_record << 1) | high_bit;
	count++;

	mask &= ~upper_mask;
	u &= mask;
    }

    while (count > 0) {
	c->finish_expr_subtree(tree, (high_bit_record & 1) ? Classifier::C_AND :
							     Classifier::C_OR);
	high_bit_record >>= 1;
	count--;
    }

    if (_op_negated && op_negate)
	c->negate_expr_subtree(tree);
}

void IPFilter::Primitive::add_exprs(Classifier *c, Vector<int> &tree) const
{
    c->start_expr_subtree(tree);

    // handle other types
    switch (_type) {
    case TYPE_HOST:
        if (_v6 == 1) {
		c->start_expr_subtree(tree);
		if (_srcdst == SD_SRC || _srcdst == SD_AND || _srcdst == SD_OR) {
		    add_comparison_exprs(c, tree, SIP_WORD, SIP_OFFSET, true, false, 0);
		    add_comparison_exprs(c, tree, SIPV6_1_WORD, SIPV6_1_OFFSET, true, false, 1);
		    add_comparison_exprs(c, tree, SIPV6_2_WORD, SIPV6_2_OFFSET, true, false, 2);
		    add_comparison_exprs(c, tree, SIPV6_3_WORD, SIPV6_3_OFFSET, true, false, 3);
		} else
		if (_srcdst == SD_DST || _srcdst == SD_AND || _srcdst == SD_OR) {
		    add_comparison_exprs(c, tree, DIP_WORD, DIP_OFFSET, true, false, 0);
		    add_comparison_exprs(c, tree, DIPV6_1_WORD, DIPV6_1_OFFSET, true, false, 1);
		    add_comparison_exprs(c, tree, DIPV6_2_WORD, DIPV6_2_OFFSET, true, false, 2);
		    add_comparison_exprs(c, tree, DIPV6_3_WORD, DIPV6_3_OFFSET, true, false, 3);
		}
		c->finish_expr_subtree(tree, (_srcdst == SD_OR ? C_OR : C_AND));
		if (_op_negated)
		    c->negate_expr_subtree(tree);

	}
	else {
		c->start_expr_subtree(tree);
		if (_srcdst == SD_SRC || _srcdst == SD_AND || _srcdst == SD_OR)
		    add_comparison_exprs(c, tree, SIP_WORD, SIP_OFFSET, true, false, 0);
		if (_srcdst == SD_DST || _srcdst == SD_AND || _srcdst == SD_OR)
		    add_comparison_exprs(c, tree, DIP_WORD, DIP_OFFSET, true, false, 0);
		c->finish_expr_subtree(tree, (_srcdst == SD_OR ? C_OR : C_AND));
		if (_op_negated)
		    c->negate_expr_subtree(tree);
	}
	break;

    case TYPE_PORT:
	c->start_expr_subtree(tree);
	if (_srcdst == SD_SRC || _srcdst == SD_AND || _srcdst == SD_OR)
	    add_comparison_exprs(c, tree, SPORT_WORD, SPORT_OFFSET, false,
				 false, 0);
	if (_srcdst == SD_DST || _srcdst == SD_AND || _srcdst == SD_OR)
	    add_comparison_exprs(c, tree, DPORT_WORD, DPORT_OFFSET, false,
				 false, 0);
	c->finish_expr_subtree(tree, (_srcdst == SD_OR ? C_OR : C_AND));
	if (_op_negated)
	    c->negate_expr_subtree(tree);
	break;

    case TYPE_LISTEN:
    case TYPE_AOPEN:
    case TYPE_POPEN:
	c->add_expr(tree, OPENTYPE_WORD, htonl(_u.u << OPENTYPE_OFFSET),
		    htonl(_mask.u << OPENTYPE_OFFSET));
	break;

    case TYPE_MARK:
	add_comparison_exprs(c, tree, MARK_WORD, MARK_OFFSET, true, true, 0);
	break;

    default:
	if (_type & TYPE_FIELD) {
	    int offset = (_type & FIELD_OFFSET_MASK) >> FIELD_OFFSET_SHIFT;
	    int len = ((_type & FIELD_LENGTH_MASK) >> FIELD_LENGTH_SHIFT) + 1;
	    int word_offset = (offset >> 5), bit_offset = offset & 0x1F;

	    add_comparison_exprs(c, tree, word_offset, 32 - (bit_offset + len),
				 false, true, 0);
	} else
	    assert(0);
	break;
    }

    c->finish_expr_subtree(tree);
}

/*
 * Returns true if a character is part of a word
 */
static bool is_word_char(const char c)
{
    return isalnum(c) || c == '-' || c == '.' || c == '/' || c == '@' ||
	   c == '_' || c == ':';
}

static bool is_or(const std::string &word)
{
    return word == "or" || word == "||";
}

static bool is_and(const std::string &word)
{
    return word == "and" || word == "&&";
}

static bool is_not(const std::string &word)
{
    return word == "not" || word == "!";
}

static bool is_dst(const std::string &word)
{
    return word == "dst" || word == "dest";
}

static void tokenize(const std::string &text, Vector<std::string> &words)
{
    const char *s = text.data();
    int len = text.length();
    int pos = 0;

    while (pos < len) {
	while (pos < len && isspace(s[pos]))
	    pos++;
	if (pos >= len)
	    break;

	switch (s[pos]) {
	case '&': case '|':
	    if (pos < len - 1 && s[pos + 1] == s[pos])
		goto two_char;
	    goto one_char;

	case '<': case '>': case '!': case '=':
	    if (pos < len - 1 && s[pos + 1] == '=')
		goto two_char;
	    if (s[pos] == '=' && pos < len - 1 && s[pos + 1] == '>')
		goto two_char;
	    goto one_char;

	case '(': case ')': case ',': case ';': case '?':
one_char:
	    words.push_back(text.substr(pos, 1));
	    pos++;
	    break;
two_char:
	    words.push_back(text.substr(pos, 2));
	    pos += 2;
	    break;

	default:
	    int first = pos;
	    while (pos < len && is_word_char(s[pos]))
		pos++;
	    if (pos == first) // must consume at least a character per iteration
		pos++;
	    words.push_back(text.substr(first, pos - first));
	    break;
	}
    }
}

/*
 * It parse a cop fileter
 * expr ::= orexpr
 *	|   orexpr ? expr : expr
 *	;
 * orexpr ::= orexpr || orexpr
 *	|   orexpr or orexpr
 *	|   term
 *	;
 * term ::= term && term
 *	|   term and term
 *	|   term factor			// juxtaposition = and
 *	|   factor
 * factor ::= ! factor
 *	|   true
 *	|   false
 *	|   quals data
 *	|   quals relop data
 *	|   ( expr )
 *	;
 */

int
IPFilter::parse_expr(const Vector<std::string> &words, int pos,
		     Vector<int> &tree, Primitive &prev_prim,
		     ErrorHandler *errh, int *defaultInc)
{
    start_expr_subtree(tree);

    while (1) {
	pos = parse_orexpr(words, pos, tree, prev_prim, errh, defaultInc);
	if ((vec_size_t)pos >= words.size())
	    break;
	if (words[pos] != "?")
	    break;
	int old_pos = pos + 1;
	pos = parse_expr(words, old_pos, tree, prev_prim, errh, defaultInc);
	if (pos == old_pos)
	    break;
	if ((vec_size_t)pos < words.size() && words[pos] == ":")
	    pos++;
	else {
	    errh->error("':' missing in ternary expression");
	    break;
	}
    }

    finish_expr_subtree(tree, C_TERNARY);
    return pos;
}

int IPFilter::parse_orexpr(const Vector<std::string> &words, int pos,
			   Vector<int> &tree, Primitive &prev_prim,
			   ErrorHandler *errh, int *defaultInc)
{
    start_expr_subtree(tree);

    while (1) {
	pos = parse_term(words, pos, tree, prev_prim, errh, defaultInc);
	if ((vec_size_t)pos >= words.size() || !is_or(words[pos]))
	    break;
	pos++;

    }

    finish_expr_subtree(tree, C_OR);
    return pos;
}

int
IPFilter::parse_term(const Vector<std::string> &words, int pos,
		     Vector<int> &tree, Primitive &prev_prim,
		     ErrorHandler *errh, int *defaultInc)
{
    start_expr_subtree(tree);

    bool blank_ok = false;   // controls whether a term is required
    while (1) {
	int next = parse_factor(words, pos, tree, prev_prim, false, errh, defaultInc);
	if (next == pos)
	    break;
	blank_ok = true;
	if ((vec_size_t)next < words.size() && is_and(words[next])) {
	    blank_ok = false;
	    next++;
	}
	pos = next;
    }

    if (!blank_ok)
	errh->error("missing term");
    finish_expr_subtree(tree);
    return pos;
}

int
IPFilter::parse_factor(const Vector<std::string> &words, int pos,
		       Vector<int> &tree, Primitive &prev_prim,
		       bool negated, ErrorHandler *errh, int *defaultInc)
{
    int nwords = words.size();
    uint32_t provided_mask = 0;

    // return immediately on last word, ")", "||", "or", "?", ":"
    if (pos >= nwords || words[pos] == ")" || is_or(words[pos]) ||
	words[pos] == "?" || words[pos] == ":" || words[pos] == ACTION_SEP)
	return pos;

    // easy cases

    // 'true' and 'false'
    if (words[pos] == "true") {
	add_expr(tree, 0, 0, 0);
	if (negated)
	    negate_expr_subtree(tree);
	return pos + 1;
    }
    if (words[pos] == "false") {
	add_expr(tree, 0, 0, 0);
	if (!negated)
	    negate_expr_subtree(tree);
	return pos + 1;
    }

    // ! factor
    if (is_not(words[pos])) {
	int next = parse_factor(words, pos + 1, tree, prev_prim, !negated,
				errh, defaultInc);
	if (next == pos + 1)
	    errh->error("missing factor after '%s'", words[pos].c_str());
	return next;
    }

    // ( expr )
    if (words[pos] == "(") {
	int next = parse_expr(words, pos + 1, tree, prev_prim, errh, defaultInc);
	if (next == pos + 1)
	    errh->error("missing expression after '('");
	else {
	    if (next >= nwords || words[next] != ")")
		errh->error("missing ')'");
	    else
		next++;
	    if (negated)
		negate_expr_subtree(tree);
	}
	return next;
    }

    // hard case

    // expect [quals [relop]] data
    int first_pos = pos;
    Primitive prim;

    // collect qualifiers
    for (; pos < nwords; pos++) {
	uint32_t wdata;
	const std::string &wd = words[pos];
	int wt = lookup(wd, 0, wdata);

	if (wt == TYPE_TYPE)
	    prim.set_type(wdata, errh);
	else if (wt != -1)
	    break;
	else if (wd == "src") {
	    if (pos < nwords - 2 && is_dst(words[pos + 2])) {
		if (is_and(words[pos + 1])) {
		    prim.set_srcdst(SD_AND, errh);
		    pos += 2;
		} else if (is_or(words[pos + 1])) {
		    prim.set_srcdst(SD_OR, errh);
		    pos += 2;
		} else
		    prim.set_srcdst(SD_SRC, errh);
	    } else
		prim.set_srcdst(SD_SRC, errh);
	} else if (is_dst(wd))
	    prim.set_srcdst(SD_DST, errh);
	else if (is_not(wd))
	    negated = !negated;
	else
	    break;
    }

    // if any qualifiers were found next check for optional mask and relops
    if (pos != first_pos) {
	prev_prim.clear();  // prev_prim is irrelevant if there were qualifiers

	if (pos < nwords && words[pos] == "&") {
	    pos++;
	    if (pos >= nwords || !cp_integer(words[pos], &provided_mask))
		errh->error("missing mask after &");
	    else if (provided_mask == 0)
		errh->error("bitmask of 0 ignored");
	    else
		pos++;
	}

	if (pos < nwords) {
	    const std::string &wd = words[pos++];

	    if (wd == "=" || wd == "==")
		/* nada */;
	    else if (wd == "!=")
		prim._op_negated = true;
	    else if (wd == ">")
		prim._op = OP_GT;
	    else if (wd == "<")
		prim._op = OP_LT;
	    else if (wd == ">=") {
		prim._op = OP_LT;
		prim._op_negated = true;
	    } else if (wd == "<=") {
		prim._op = OP_GT;
		prim._op_negated = true;
	    } else
		pos--;
	}
    }

    // now collect the actual data
    if (pos < nwords) {
	uint32_t wdata;
	const std::string &wd = words[pos];
	int wt = lookup(wd, prim._type, wdata);

	pos++;
	if (wt != -1 && wt != TYPE_TYPE) {
	    prim._data = wt;
	    prim._u.u = wdata;
	} else if (cp_integer(wd, &prim._u.i))
	    prim._data = TYPE_INT;
	else if (cp_ip_address(wd, prim._u.c, AF_INET, NULL)) {
	    prim._v6 = 0;
	    if (pos < nwords - 1 && words[pos] == "mask") {
		if (cp_ip_mask(words[pos + 1], prim._mask.c, AF_INET)) {
		    pos += 2;
		    prim._data = TYPE_NET;
		} else {
		    errh->error("illegal mask %s", words[pos + 1].c_str());
		    return pos;
		}
	    } else if (prim._type == TYPE_NET) {
		memset(prim._mask.c, 255, 16);
		prim._data = TYPE_NET;
	    } else
		prim._data = TYPE_HOST;
	} else if (cp_ip_prefix(wd, prim._u.c, prim._mask.c, false, AF_INET,
				NULL)) {
	    prim._v6 = 0;
	    prim._data = TYPE_NET;
	} else if (cp_ip_address(wd, prim._u.c, AF_INET6, NULL)) {
		prim._data = TYPE_HOST;
		prim._v6 = 1;
		*defaultInc = *defaultInc + 3;
	} else if (cp_ip_prefix(wd, prim._u.c, prim._mask.c, false, AF_INET6,
				NULL)) {
		prim._data = TYPE_NET;
		prim._v6 = 1;
		*defaultInc = *defaultInc + 3;
	}
	else {
	    if (prim._op != OP_EQ || prim._op_negated)
		errh->error("dangling operator near '%s'", wd.c_str());
	    pos--;
	}
    }

    if (pos == first_pos) {
	errh->error("empty term near '%s'", words[pos].c_str());
	return pos;
    }

    // add if it is valid
    if (prim.check(prev_prim, provided_mask, errh) >= 0) {
	prim.add_exprs(this, tree);
	if (negated)
	    negate_expr_subtree(tree);
	prev_prim = prim;
    }

    return pos;
}

int IPFilter::parse_offload_settings(const stringvec &words, int pos,
				     ErrorHandler *errh)
{
    int neg = 0, nwords = words.size();
    OffloadSettings os;

    while (pos < nwords) {
	if (words[pos] == "!" or words[pos] == "not")
	    neg++;
	else if (words[pos] == "offload") {
	    os.offload = (neg + 1) & 1;
	    neg = 0;
	} else if (words[pos] == "ddp") {
	    os.ddp = (neg + 1) & 1;
	    neg = 0;
	} else if (words[pos] == "coalesce") {
	    os.rx_coalesce = (neg + 1) & 1;
	    neg = 0;
	} else if (words[pos] == "sack") {
	    os.sack = (neg + 1) & 1;
	    neg = 0;
	} else if (words[pos] == "timestamp" || words[pos] == "tstamp") {
	    os.tstamp = (neg + 1) & 1;
	    neg = 0;
	} else {
	    if (neg) {
		errh->error("negation can't be used with '%s'",
			    words[pos].c_str());
		neg = 0;
	    } else if (words[pos] == "bind") {
		if (pos + 1 >= nwords)
		    errh->error("missing value for 'bind'");
		else if (words[pos + 1] == "random")
		    os.bind_q = QUEUE_RANDOM;
		else if (words[pos + 1] == "cpu")
		    os.bind_q = QUEUE_CPU;
		else if (!cp_integer(words[pos + 1], &os.bind_q) ||
			 os.bind_q < 0)
		    errh->error("'bind' needs an integer value >= 0, 'cpu', or "
				"'random'");
		pos++;
	    } else if (words[pos] == "cong") {
		if (pos + 1 >= nwords ||
		    !cp_cong_algo(words[pos + 1], &os.cong_algo))
		    errh->error("unknown congestion algorithm %s",
				words[pos + 1].c_str());
		pos++;
	    } else if (words[pos] == "class") {
		if (pos + 1 >= nwords ||
		    !cp_integer(words[pos + 1], &os.sched_class) ||
		    os.sched_class < 0)
		    errh->error("'class' needs an integer value between 0 "
				"and 32767");
		pos++;
	    } else
		return pos;
	}
	pos++;
    }
    if (neg)
	errh->error("incomplete negation at end of rule");
    _settings.push_back(os);
    return pos;
}

static inline bool is_filter_wildcard(const std::string &word)
{
    return word == "any" || word == "all" || word == "-";
}

int IPFilter::configure(stringvec &conf, ErrorHandler *errh)
{
    _output_everything = -1;
    _noutputs = conf.size();
    int defaultInc = 0;
    int lastInc = 0;
    int lastExpInc = 0;

    Vector<int> tree;
    init_expr_subtree(tree);
    errh->snap_errors();

    // [QUALS] [host|net|port] [data]
    // QUALS ::= src | dst | src and dst | src or dst | \empty
    for (vec_size_t argno = 0; argno < conf.size(); argno++) {
	Vector<std::string> words;
	tokenize(conf[argno], words);
	defaultInc = 0;

	if (words.size() == 0) {
	    errh->error("empty pattern %d", argno);
	    continue;
	}

	char pfx[80];
	sprintf(pfx, "rule %zd: ", argno);
	errh->set_prefix(pfx);

	int pos, nwords = words.size();
	int init_pos;
	unsigned int old_errors = errh->nerrors();
	start_expr_subtree(tree);
	lastExpInc = _exprs.size();

	// check for "-"
	if (nwords >= 2 && words[1] == ACTION_SEP &&
	    is_filter_wildcard(words[0])) {
	    add_expr(tree, 0, 0, 0);
	    pos = 1;
	} else {
	    // start with a blank primitive
	    Primitive prev_prim;
	    //Its value is stored in filter exp stored in tree.
	    pos = parse_expr(words, 0, tree, prev_prim, errh, &defaultInc);
	}

	if (errh->nerrors() != old_errors)
	    ;            // don't bother with settings if the filter had errors
	else if (pos < nwords && words[pos] == ACTION_SEP) { 
	    	 init_pos = parse_offload_settings(words, pos + 1, errh);
		 if (lastInc + defaultInc > 0)
			 for( unsigned int i = 0 ; i < (_exprs.size() - lastExpInc - 1) ; i++){	
				parse_offload_settings(words, pos + 1, errh);
			 }
		pos = init_pos;
	    if (pos < nwords)
		errh->error("unexpected '%s'", words[pos].c_str());
	} else
	    errh->error("missing '" ACTION_SEP "' after rule filter");
	
	lastInc = lastInc + defaultInc; 
	finish_expr_subtree(tree, C_AND, -(defaultInc > 0 || lastInc > 0 ?  _exprs.size() - 1 : argno )); 
       
    }

    // add sentinel offload settings
    _settings.push_back(OffloadSettings());
    if (lastInc > 0) _noutputs = _exprs.size();

    finish_expr_subtree(tree, C_OR, -noutputs(), -noutputs());

    errh->set_prefix(0);
    if (errh->any_errors())
	return -1;

    if (lastInc == 0)
	optimize_exprs(errh);
    if (_output_everything < 0) {
	// It helps to do another bubblesort for things like ports.
	bubble_sort_and_exprs();

	// Compress the program into _prog.
	compress_exprs(_prog, false);
    }
    return errh->any_errors() ? -1 : 0;
}

void IPFilter::dump_integer_program(FILE *fp) const
{
    fprintf(fp, "optimized classifier program:\n");

    if (_output_everything >= 0) {
	fprintf(fp, "all->[%d]\n", _output_everything);
	return;
    }

    for (vec_size_t i = 0; i < _prog.size(); ) {
	int nvals = _prog[i] >> 16;

	fprintf(fp, "%4zd  %d #%d  %08x  yes->", i, _prog[i] & 0xffff, nvals,
		htonl(_prog[i+3]));
	if ((int32_t) _prog[i+2] > 0)
	    fprintf(fp, "step %zd  ", _prog[i+2] + i);
	else
	    fprintf(fp, "[%d]     ", -(int32_t)_prog[i+2]);
	if ((int32_t) _prog[i+1] > 0)
	    fprintf(fp, "no->step %zd\n", _prog[i+1] + i);
	else
	    fprintf(fp, "no->[%d]\n", -(int32_t)_prog[i+1]);
	i += 4;

	while (nvals--) {
	    fprintf(fp, "%4zd    %08x\n", i, htonl(_prog[i]));
	    i++;
	}
    }
}

void IPFilter::dump_offload_settings(FILE *fp) const
{
    fprintf(fp, "offload settings:\n");

    for (vec_size_t i = 0; i < _settings.size(); i++) {
	const OffloadSettings &os = _settings[i];

	fprintf(fp, "%4zd: offload %u, ddp %d, coalesce %d, cong_algo %d, "
		"queue %d, class %d, tstamp %d, sack %d\n",
		i, os.offload, os.ddp, os.rx_coalesce, os.cong_algo, os.bind_q,
	       	os.sched_class, os.tstamp, os.sack);
    }
}

/*
 * An offload policy file consists of the following sections:
 * - file header of size sizeof(ClassifierFileHeader)
 * - unoptimized classification program of size header.prog_size * 20, where
 *   20 is the size of a program "instruction" (5 ints)
 * - optimized classification program of size header.opt_prog_size * 4
 * - offload settings of size header.nsettings * sizeof(OffloadSettings)
 */
int IPFilter::save(const char *fname) const
{
    size_t sz;

    int fd = creat(fname, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (fd < 0)
	return -1;

    ClassifierFileHeader h;
    h.vers = 0;
    h.output_everything = _output_everything;
    h.nrules = noutputs();
    h.prog_size = _exprs.size();
    h.opt_prog_size = _prog.size();
    h.nsettings = _settings.size();
    if (write(fd, &h, sizeof(h)) != sizeof(h)) {
fail:	close(fd);
	return -1;
    }

    sz = h.prog_size * 5 * sizeof(int);
    if (sz && write(fd, &_exprs[0], sz) != (ssize_t)sz)
	goto fail;

    sz = _prog.size() * sizeof(int);
    if (sz && write(fd, &_prog[0], sz) != (ssize_t)sz)
	goto fail;

    sz = _settings.size() * sizeof(OffloadSettings);
    if (write(fd, &_settings[0], sz) != (ssize_t)sz)
	goto fail;

    close(fd);
    return 0;
}

int IPFilter::optimized_match(const OffloadReq &req) const
{
    if (_output_everything >= 0)
	return _output_everything;

    const uint32_t *q = (const uint32_t *)&req;
    const uint32_t *pr = &_prog[0], *pp;

    while (1) {
	int off = (int16_t) pr[0];
	uint32_t data = q[off] & pr[3];

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

#ifndef USE_STD_VECTOR
# include "vector.cc"
#endif

// vim: shiftwidth=4
