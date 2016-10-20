#ifndef CLICK_CLASSIFIER_H
#define CLICK_CLASSIFIER_H

#include <stdint.h>
#include <string>
#include "error.h"

#ifdef USE_STD_VECTOR
# include <vector>
# define Vector std::vector
#else
# include "vector.h"
#endif

typedef Vector<std::string> stringvec;
typedef stringvec::size_type vec_size_t;

struct OffloadReq;

class Classifier {
public:

  class Expr;
  
  Classifier();
  virtual ~Classifier();
  
  // creating Exprs
  enum { NEVER = -2147483647, FAILURE, SUCCESS };
  void add_expr(Vector<int> &, const Expr &);
  void add_expr(Vector<int> &, int offset, uint32_t value, uint32_t mask);
  void init_expr_subtree(Vector<int> &);
  void start_expr_subtree(Vector<int> &);
  void negate_expr_subtree(Vector<int> &);
  enum Combiner { C_AND, C_OR, C_TERNARY };
  void finish_expr_subtree(Vector<int> &, Combiner = C_AND, int success = SUCCESS, int failure = FAILURE);
  std::string program_string(void);
  void dump_program(FILE *);
  
  int noutputs() const { return _noutputs; }

  int match(const OffloadReq &) const;
  
  struct Expr {
    int offset;
    union {
      unsigned char c[4];
      uint32_t u;
    } mask;
    union {
      unsigned char c[4];
      uint32_t u;
    } value;
    int32_t j[2];
    int32_t yes() const			{ return j[1]; }
    int32_t no() const			{ return j[0]; }
    int32_t &yes()			{ return j[1]; }
    int32_t &no()			{ return j[0]; }
    bool implies(const Expr &) const;
    bool implies_not(const Expr &) const;
    bool not_implies(const Expr &) const;
    bool not_implies_not(const Expr &) const;
    bool compatible(const Expr &) const;
    bool flippable() const;
    void flip();
    std::string s() const;
  };

 protected:

  Vector<Expr> _exprs;
  int _output_everything;
  int _noutputs;

  void redirect_expr_subtree(int first, int next, int success, int failure);
  
  void combine_compatible_states();
  bool remove_unused_states();
  void unaligned_optimize();
  void count_inbranches(Vector<int> &) const;
  void bubble_sort_and_exprs(int sort_stopper = 0x7FFFFFFF);
  void optimize_exprs(ErrorHandler *, int sort_stopper = 0x7FFFFFFF);
  void compress_exprs(Vector<uint32_t> &prog, bool perform_binary_search = true,
		      unsigned int bin_search_threshold = 7) const;
  
 private:

  class DominatorOptimizer { public:

    DominatorOptimizer(Classifier *c);

    static int brno(int state, bool br)		{ return (state << 1) + br; }
    static int stateno(int brno)		{ return brno >> 1; }
    static bool br(int brno)			{ return brno & 1; }

    bool br_implies(int brno, int state) const;
    bool br_implies_not(int brno, int state) const;

    void run(int);
    void print();

   private:

    Classifier *_c;
    Vector<int> _dom;
    Vector<int> _dom_start;
    Vector<int> _domlist_start;

    enum { MAX_DOMLIST = 4 };
    
    Classifier::Expr &expr(int state) const;
    int nexprs() const;

    static void intersect_lists(const Vector<int> &, const Vector<int> &, const Vector<int> &, int pos1, int pos2, Vector<int> &);
    static int last_common_state_in_lists(const Vector<int> &, const Vector<int> &, const Vector<int> &);
    void find_predecessors(int state, Vector<int> &) const;
    int dom_shift_branch(int brno, int to_state, int dom, int dom_end, Vector<int> *collector);
    void shift_branch(int brno);
    void calculate_dom(int state);
    
  };

  friend class DominatorOptimizer;
};

#endif
