#ifndef CLICK_IPFILTER_H
#define CLICK_IPFILTER_H

#include "classifier.h"
#include "offload_req.h"

class IPFilter : public Classifier {
public:
    IPFilter() {}
    ~IPFilter() {}

    int configure(stringvec &, ErrorHandler *);
    void dump_integer_program(FILE *fp) const;
    void dump_offload_settings(FILE *fp) const;
    int save(const char *fname) const;

    int optimized_match(const OffloadReq &) const;

    enum {
	TYPE_NONE   = 0,		// data types
	TYPE_TYPE   = 1,
	TYPE_SYNTAX = 2,
	TYPE_INT    = 3,

	TYPE_HOST   = 10,		// expression types
	TYPE_PORT   = 13,
	TYPE_VLAN   = 15,
	TYPE_LISTEN = 16,
	TYPE_AOPEN  = 17,
	TYPE_POPEN  = 18,
	TYPE_MARK   = 19,

	TYPE_NET    = 30,		// shorthands

	TYPE_FIELD  = 0x40000000,
	// bit 31 must be zero
	// bit 30 must be one
	// bits 29-21 represent IP protocol (9 bits); 0 means no protocol
	// bits 20-5 represent field offset into header in bits (16 bits)
	// bits 4-0 represent field length in bits minus one (5 bits)
	FIELD_OFFSET_SHIFT = 5,
	FIELD_OFFSET_MASK  = (0xFFFF << FIELD_OFFSET_SHIFT),
	FIELD_LENGTH_SHIFT = 0,
	FIELD_LENGTH_MASK  = (0x1F << FIELD_LENGTH_SHIFT),
	FIELD_VERSION = (TYPE_FIELD | ((9*32+4) << FIELD_OFFSET_SHIFT) | 3),
	FIELD_TOS     = (TYPE_FIELD | ((9*32+8) << FIELD_OFFSET_SHIFT) | 7),
	FIELD_DSCP    = (TYPE_FIELD | ((9*32+8) << FIELD_OFFSET_SHIFT) | 5),
	FIELD_VLAN    = (TYPE_FIELD | ((9*32+20) << FIELD_OFFSET_SHIFT) | 11),
    };

    enum {
	SD_SRC = 1, SD_DST = 2, SD_AND = 3, SD_OR = 4,

	OP_EQ = 0, OP_GT = 1, OP_LT = 2,
    };

    enum { OPEN_TYPE_LISTEN, OPEN_TYPE_ACTIVE, OPEN_TYPE_PASSIVE };

    struct Primitive {
	int _type;		/* type_entries */
	int _data;		/* type_entries data*/
	int _op;		/* operator OP_EQ, OP_GT, OP_LT */
	bool _op_negated;
	int _srcdst;
	int _v6;

	union {
	    uint32_t u;
	    int32_t i;
	    uint8_t c[16];
	} _u, _mask;

	Primitive() { clear(); }

	void clear();
	void set_type(int, ErrorHandler *);
	void set_srcdst(int, ErrorHandler *);

	int set_mask(uint32_t full_mask, int shift, uint32_t provided_mask,
		     ErrorHandler *);
	int check(const Primitive &, uint32_t provided_mask, ErrorHandler *);
	void add_exprs(Classifier *, Vector<int> &) const;

	bool negation_is_simple() const;
	void simple_negate();

	bool is_int_type() const;

	std::string unparse_type() const;
	const char *unparse_op() const;
	static std::string unparse_type(int srcdst, int type);

    private:
	void add_comparison_exprs(Classifier *, Vector<int> &tree, int offset,
		int shift, bool swapped, bool op_negate, int op_shift) const;
    };

private:
    Vector<uint32_t> _prog;
    Vector<OffloadSettings> _settings;

    int lookup(const std::string &word, int type, uint32_t &data) const;

    int parse_expr(const Vector<std::string> &, int, Vector<int> &, Primitive &,
		   ErrorHandler *, int *);
    int parse_orexpr(const Vector<std::string> &, int, Vector<int> &,
		     Primitive &, ErrorHandler *, int*);
    int parse_term(const Vector<std::string> &, int, Vector<int> &, Primitive &,
		   ErrorHandler *, int*);
    int parse_factor(const Vector<std::string> &, int, Vector<int> &,
		     Primitive &, bool negated, ErrorHandler *, int*);
    int parse_offload_settings(const stringvec &, int, ErrorHandler *);
};

inline bool IPFilter::Primitive::negation_is_simple() const
{
    return _type == TYPE_HOST || (_type & TYPE_FIELD);
}
#endif

/* vim: set ts=8 sw=4: */
