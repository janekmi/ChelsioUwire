/*
 * classifier.{cc,h} -- element is a generic classifier
 * Eddie Kohler
 *
 * Copyright (c) 1999-2000 Massachusetts Institute of Technology
 * Copyright (c) 2000 Mazu Networks, Inc.
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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "classifier.h"

//
// CLASSIFIER::EXPR OPERATIONS
//

bool
Classifier::Expr::implies(const Expr &e) const
  /* Returns true iff a packet that matches `*this' must match `e'. */
{
  if (!e.mask.u)
    return true;
  else if (e.offset != offset)
    return false;
  uint32_t both_mask = mask.u & e.mask.u;
  return both_mask == e.mask.u
    && (value.u & both_mask) == e.value.u;
}

bool
Classifier::Expr::not_implies(const Expr &e) const
  /* Returns true iff a packet that DOES NOT match `*this' must match `e'. */
  /* This happens when (1) 'e' matches everything, or (2) 'e' and '*this'
     both match against the same single bit, and they have different values. */
{
  if (!e.mask.u)
    return true;
  else if (e.offset != offset || (mask.u & (mask.u - 1)) != 0
	   || mask.u != e.mask.u || value.u == e.value.u)
    return false;
  else
    return true;
}

bool
Classifier::Expr::implies_not(const Expr &e) const
  /* Returns true iff a packet that matches `*this' CANNOT match `e'. */
{
  if (!e.mask.u || e.offset != offset)
    return false;
  uint32_t both_mask = mask.u & e.mask.u;
  return both_mask == e.mask.u
    && (value.u & both_mask) != (e.value.u & both_mask);
}

bool
Classifier::Expr::not_implies_not(const Expr &e) const
  /* Returns true iff a packet that DOES NOT match `*this' CANNOT match `e'. */
{
  if (!mask.u)
    return true;
  else if (e.offset != offset)
    return false;
  uint32_t both_mask = mask.u & e.mask.u;
  return both_mask == mask.u
    && (value.u & both_mask) == (e.value.u & both_mask);
}

bool
Classifier::Expr::compatible(const Expr &e) const
{
  if (!mask.u || !e.mask.u)
    return true;
  else if (e.offset != offset)
    return false;
  uint32_t both_mask = mask.u & e.mask.u;
  return (value.u & both_mask) == (e.value.u & both_mask);
}

bool
Classifier::Expr::flippable() const
{
  if (!mask.u)
    return false;
  else
    return ((mask.u & (mask.u - 1)) == 0);
}

void
Classifier::Expr::flip()
{
  assert(flippable());
  value.u ^= mask.u;
  int tmp = j[0];
  j[0] = j[1];
  j[1] = tmp;
}

std::string
Classifier::Expr::s() const
{
  std::string s;
  char buf[20];
  int offset = this->offset;

  sprintf(buf, "%3d/", offset);
  s = buf;
  for (int i = 0; i < 4; i++)
    sprintf(buf + 2*i, "%02x", value.c[i]);
  sprintf(buf + 8, "%%");
  for (int i = 0; i < 4; i++)
    sprintf(buf + 9 + 2*i, "%02x", mask.c[i]);
  s += buf;

  s += "  yes->";
  if (yes() <= 0)
      sprintf(buf, "[%d]   ", -yes());
  else
      sprintf(buf, "step %d", yes());
  s += buf;

  s += "  no->";
  if (no() <= 0)
      sprintf(buf, "[%d]", -no());
  else
      sprintf(buf, "step %d", no());
  s += buf;
 
  return s;
}

//
// CLASSIFIER ITSELF
//

Classifier::Classifier()
    : _output_everything(-1)
{
}

Classifier::~Classifier()
{
}

//
// COMPILATION
//

// DOMINATOR OPTIMIZER

/* Optimize Classifier decision trees by removing useless branches. If we have
   a path like:

   0: x>=5?  ---Y-->  1: y==2?  ---Y-->  2: x>=6?  ---Y-->  3: ...
       \
        --N-->...

   and every path to #1 leads from #0, then we can move #1's "Y" branch to
   point at state #3, since we know that the test at state #2 will always
   succeed.

   There's an obvious exponential-time algorithm to check this. Namely, given
   a state, enumerate all paths that could lead you to that state; then check
   the test against all tests on those paths. This terminates -- the
   classifier structure is a DAG -- but clearly in exptime.

   We reduce the algorithm to polynomial time by storing a bounded number of
   paths per state. For every state S, we maintain a set of up to
   MAX_DOMLIST==4 path subsets D1...D4, so *every* path to state S is a
   superset of at least one Di. (There is no requirement that S contains Di as
   a contiguous subpath. Rather, Di might leave out edges.) We can then shift
   edges as follows. Given an edge S.x-->T, check whether T is resolved (to
   the same answer) by every one of the path subsets D1...D4 corresponding to
   S. If so, then the edge S.x-->T is redundant; shift it to destination
   corresponding to the answer to T. (In the example above, we shift #1.Y to
   point to #3, since that is the destination of the #2.Y edge.)

   _dom holds all the Di sets for all states.
   _dom_start[k] says where, in _dom, a given Di begins.
   _domlist_start[S] says where, in _dom_start, the list of dominator sets
   for state S begins.
*/


Classifier::DominatorOptimizer::DominatorOptimizer(Classifier *c)
  : _c(c)
{
  _dom_start.push_back(0);
  _domlist_start.push_back(0);
}

inline Classifier::Expr &
Classifier::DominatorOptimizer::expr(int state) const
{
  return _c->_exprs[state];
}

inline int
Classifier::DominatorOptimizer::nexprs() const
{
  return _c->_exprs.size();
}

inline bool
Classifier::DominatorOptimizer::br_implies(int brno, int state) const
{
  assert(state > 0);
  if (br(brno))
    return expr(stateno(brno)).implies(expr(state));
  else
    return expr(stateno(brno)).not_implies(expr(state));
}

inline bool
Classifier::DominatorOptimizer::br_implies_not(int brno, int state) const
{
  assert(state > 0);
  if (br(brno))
    return expr(stateno(brno)).implies_not(expr(state));
  else
    return expr(stateno(brno)).not_implies_not(expr(state));
}

void
Classifier::DominatorOptimizer::find_predecessors(int state, Vector<int> &v) const
{
  for (int i = 0; i < state; i++) {
    Expr &e = expr(i);
    if (e.yes() == state)
      v.push_back(brno(i, true));
    if (e.no() == state)
      v.push_back(brno(i, false));
  }
}

void
Classifier::DominatorOptimizer::print()
{
  std::string s = _c->program_string();
  fprintf(stderr, "%s\n", s.c_str());
  for (Vector<int>::size_type i = 0; i < _domlist_start.size() - 1; i++) {
    if (_domlist_start[i] == _domlist_start[i+1])
      fprintf(stderr, "S-%zd   NO DOMINATORS\n", i);
    else {
      fprintf(stderr, "S-%zd : ", i);
      for (int j = _domlist_start[i]; j < _domlist_start[i+1]; j++) {
	if (j > _domlist_start[i])
	  fprintf(stderr, "    : ");
	for (int k = _dom_start[j]; k < _dom_start[j+1]; k++)
	  fprintf(stderr, " %d.%c", stateno(_dom[k]), br(_dom[k]) ? 'Y' : 'N');
	fprintf(stderr, "\n");
      }
    }
  }
}

void
Classifier::DominatorOptimizer::calculate_dom(int state)
{
  assert((int)_domlist_start.size() == state + 1);
  assert((int)_dom_start.size() - 1 == _domlist_start.back());
  assert((int)_dom.size() == _dom_start.back());
  
  // find predecessors
  Vector<int> predecessors;
  find_predecessors(state, predecessors);
  
  // if no predecessors, kill this expr
  if (predecessors.size() == 0) {
    if (state > 0)
	expr(state).j[0] = expr(state).j[1] = -_c->noutputs();
    else {
	assert(state == 0);
	_dom.push_back(brno(state, false));
	_dom_start.push_back(_dom.size());
    }
    _domlist_start.push_back(_dom_start.size() - 1);
    return;
  }

  // collect dominator lists from predecessors
  Vector<int> pdom, pdom_end;
  for (int i = 0; i < (int)predecessors.size(); i++) {
    int p = predecessors[i], s = stateno(p);
    
    // if both branches point at same place, remove predecessor state from
    // tree
    if (i > 0 && stateno(predecessors[i-1]) == s) {
      assert(i == (int)predecessors.size() - 1 || stateno(predecessors[i+1]) != s);
      assert(pdom_end.back() > pdom.back());
      assert(stateno(_dom[pdom_end.back() - 1]) == s);
      pdom_end.back()--;
      continue;
    }

    // append all dom lists to pdom and pdom_end; modify dom array to end with
    // branch 'p'
    for (int j = _domlist_start[s]; j < _domlist_start[s+1]; j++) {
      pdom.push_back(_dom_start[j]);
      pdom_end.push_back(_dom_start[j+1]);
      assert(stateno(_dom[pdom_end.back() - 1]) == s);
      _dom[pdom_end.back() - 1] = p;
    }
  }

  // We now have pdom and pdom_end arrays pointing at predecessors'
  // dominators.

  // If we have too many arrays, combine some of them.
  int pdom_pos = 0;
  if (pdom.size() > MAX_DOMLIST) {
    intersect_lists(_dom, pdom, pdom_end, 0, pdom.size(), _dom);
    _dom.push_back(brno(state, false));
    _dom_start.push_back(_dom.size());
    pdom_pos = pdom.size();	// skip loop
  }

  // Our dominators equal predecessors' dominators.
  for (vec_size_t p = pdom_pos; p < pdom.size(); p++) {
    for (int i = pdom[p]; i < pdom_end[p]; i++) {
      int x = _dom[i];
      _dom.push_back(x);
    }
    _dom.push_back(brno(state, false));
    _dom_start.push_back(_dom.size());
  }

  _domlist_start.push_back(_dom_start.size() - 1);
}


void
Classifier::DominatorOptimizer::intersect_lists(const Vector<int> &in, const Vector<int> &start, const Vector<int> &end, int pos1, int pos2, Vector<int> &out)
  /* Define subvectors V1...Vk as in[start[i] ... end[i]-1] for each pos1 <= i
     < pos2. This code places an intersection of V1...Vk in 'out'. */
{
  assert(pos1 <= pos2 && pos2 <= (int)start.size() && pos2 <= (int)end.size());
  if (pos1 == pos2)
    return;
  else if (pos2 - pos1 == 1) {
    for (int i = start[pos1]; i < end[pos1]; i++)
      out.push_back(in[i]);
  } else {
    Vector<int> pos(start);
    
    // Be careful about lists that end with something <= 0.
    int x = -1;			// 'x' describes the intersection path.
    
    while (1) {
      int p = pos1, k = 0;
      // Search for an 'x' that is on all of V1...Vk. We step through V1...Vk
      // in parallel, using the 'pos' array (initialized to 'start'). On
      // reaching the end of any of the arrays, exit.
      while (k < pos2 - pos1) {
	while (pos[p] < end[p] && in[pos[p]] < x)
	  pos[p]++;
	if (pos[p] >= end[p])
	  goto done;
	// Stepped past 'x'; current value is a new candidate
	if (in[pos[p]] > x)
	  x = in[pos[p]], k = 0;
	p++;
	if (p == pos2)
	  p = pos1;
	k++;
      }
      // Went through all of V1...Vk without changing x, so it's on all lists
      // (0 will definitely be the first such); add it to 'out' and step
      // through again
      out.push_back(x);
      x++;
    }
   done: ;
  }
}

int
Classifier::DominatorOptimizer::dom_shift_branch(int brno, int to_state, int dom, int dom_end, Vector<int> *collector)
{
  // shift the branch from `brno' to `to_state' as far down as you can, using
  // information from `brno's dominators
  assert(dom_end > dom && stateno(_dom[dom_end - 1]) == stateno(brno));
  _dom[dom_end - 1] = brno;
  if (collector)
    collector->push_back(to_state);

  while (to_state > 0) {
    for (int j = dom_end - 1; j >= dom; j--)
      if (br_implies(_dom[j], to_state)) {
	  to_state = expr(to_state).yes();
	  goto found;
      } else if (br_implies_not(_dom[j], to_state)) {
	  to_state = expr(to_state).no();
	  goto found;
      }
    // not found
    break;
   found:
    if (collector)
      collector->push_back(to_state);
  }

  return to_state;
}

int
Classifier::DominatorOptimizer::last_common_state_in_lists(const Vector<int> &in, const Vector<int> &start, const Vector<int> &end)
{
  assert(start.size() == end.size() && start.size() > 1);
  if (in[end[0] - 1] <= 0) {
    int s = in[end[0] - 1];
    for (int j = 1; j < (int)start.size(); j++)
      if (in[end[j] - 1] != s)
	goto not_end;
    return s;
  }
 not_end:
  Vector<int> intersection;
  intersect_lists(in, start, end, 0, start.size(), intersection);
  return intersection.back();
}

void
Classifier::DominatorOptimizer::shift_branch(int brno)
{
  // shift a branch by examining its dominators
  
  int s = stateno(brno);
  int32_t &to_state = expr(s).j[br(brno)];
  if (to_state <= 0)
    return;

  if (_domlist_start[s] + 1 == _domlist_start[s+1]) {
    // single domlist; faster algorithm
    int d = _domlist_start[s];
    to_state = dom_shift_branch(brno, to_state, _dom_start[d], _dom_start[d+1], 0);
  } else {
    Vector<int> vals, start, end;
    for (int d = _domlist_start[s]; d < _domlist_start[s+1]; d++) {
      start.push_back(vals.size());
      (void) dom_shift_branch(brno, to_state, _dom_start[d], _dom_start[d+1], &vals);
      end.push_back(vals.size());
    }
    to_state = last_common_state_in_lists(vals, start, end);
  }
}

void
Classifier::DominatorOptimizer::run(int state)
{
  assert((int)_domlist_start.size() == state + 1);
  calculate_dom(state);
  shift_branch(brno(state, true));
  shift_branch(brno(state, false));
}


// OPTIMIZATION

bool
Classifier::remove_unused_states()
{
  // Remove uninteresting exprs
  int first = 0;
  for (int i = 0; _output_everything < 0 && i < (int)_exprs.size(); i++) {
    Expr &e = _exprs[i];
    int next = e.yes();
    if (e.yes() == e.no() || e.mask.u == 0) {
      if (i == first && next <= 0)
	_output_everything = e.yes();
      else {
	for (int j = 0; j < i; j++)
	    for (int k = 0; k < 2; k++)
		if (_exprs[j].j[k] == i)
		    _exprs[j].j[k] = next;
	if (i == 0)
	    first = next;
      }
    }
  }
  if (_output_everything < 0 && first > 0)
    _exprs[0] = _exprs[first];

  // Remove unreachable states
  for (int i = 1; i < (int)_exprs.size(); i++) {
    for (int j = 0; j < i; j++)	// all branches are forward
      if (_exprs[j].yes() == i || _exprs[j].no() == i)
	goto done;
    // if we get here, the state is unused
    for (int j = i+1; j < (int)_exprs.size(); j++)
      _exprs[j-1] = _exprs[j];
    _exprs.pop_back();
    for (int j = 0; j < (int)_exprs.size(); j++)
	for (int k = 0; k < 2; k++)
	    if (_exprs[j].j[k] >= i)
		_exprs[j].j[k]--;
    i--;			// shifted downward, so must reconsider `i'
   done: ;
  }

  // Get rid of bad branches
  Vector<int> failure_states(_exprs.size(), FAILURE);
  bool changed = false;
  for (int i = _exprs.size() - 1; i >= 0; i--) {
    Expr &e = _exprs[i];
    for (int k = 0; k < 2; k++)
	if (e.j[k] > 0 && failure_states[e.j[k]] != FAILURE) {
	    e.j[k] = failure_states[e.j[k]];
	    changed = true;
	}
    if (e.yes() == FAILURE)
      failure_states[i] = e.no();
    else if (e.no() == FAILURE)
      failure_states[i] = e.yes();
  }
  return changed;
}

void
Classifier::combine_compatible_states()
{
  for (int i = 0; i < (int)_exprs.size(); i++) {
    Expr &e = _exprs[i];
    if (e.no() > 0 && _exprs[e.no()].compatible(e) && e.flippable())
      e.flip();
    if (e.yes() <= 0)
      continue;
    Expr &ee = _exprs[e.yes()];
    if (e.no() == ee.yes() && ee.flippable())
      ee.flip();
    if (e.no() == ee.no() && ee.compatible(e)) {
      e.yes() = ee.yes();
      if (!e.mask.u)		// but probably ee.mask.u is always != 0...
	e.offset = ee.offset;
      e.value.u = (e.value.u & e.mask.u) | (ee.value.u & ee.mask.u);
      e.mask.u |= ee.mask.u;
      i--;
    }
  }
}

void
Classifier::count_inbranches(Vector<int> &inbranch) const
{
    inbranch.assign(_exprs.size(), -1);
    for (int i = 0; i < (int)_exprs.size(); i++) {
	const Expr &e = _exprs[i];
	for (int k = 0; k < 2; k++)
	    if (e.j[k] > 0)
		inbranch[e.j[k]] = (inbranch[e.j[k]] >= 0 ? 0 : i);
    }
}

void
Classifier::bubble_sort_and_exprs(int sort_stopper)
{
    Vector<int> inbranch;
    count_inbranches(inbranch);
    
    // do bubblesort
    for (int i = 0; i < (int)_exprs.size(); i++) {
	Expr &e1 = _exprs[i];
	for (int k = 0; k < 2; k++)
	    if (e1.j[k] > 0) {
		int j = e1.j[k];
		Expr &e2 = _exprs[j];
		if (e1.j[!k] == e2.j[!k]
		    && (e1.offset > e2.offset
			|| (e1.offset == e2.offset && e1.mask.u > e2.mask.u))
		    && e1.offset < sort_stopper && inbranch[j] > 0) {
		    Expr temp(e2);
		    e2 = e1;
		    e2.j[k] = temp.j[k];
		    e1 = temp;
		    e1.j[k] = j;
		    // step backwards to continue the sort
		    i = (inbranch[i] > 0 ? inbranch[i] - 1 : i - 1);
		    break;
		}
	    }
    }
}

void
Classifier::optimize_exprs(ErrorHandler *errh, int sort_stopper)
{
  // sort 'and' expressions
  bubble_sort_and_exprs(sort_stopper);
  
  //{ String sxx = program_string(this, 0); click_chatter("%s", sxx.c_str()); }

  // optimize using dominators
  {
    DominatorOptimizer dom(this);
    for (vec_size_t i = 0; i < _exprs.size(); i++)
      dom.run(i);
    //dom.print();
    combine_compatible_states();
    (void) remove_unused_states();
  }

  //{ String sxx = program_string(this, 0); click_chatter("%s", sxx.c_str()); }
  
  // Check for case where all patterns have conflicts: _exprs will be empty
  // but _output_everything will still be < 0. We require that, when _exprs
  // is empty, _output_everything is >= 0.
  if (_exprs.size() == 0 && _output_everything < 0)
    _output_everything = noutputs();
  else if (_output_everything >= 0)
    _exprs.clear();

  // Warn on patterns that can't match anything
  Vector<int> used_patterns(noutputs() + 1, 0);
  if (_output_everything >= 0)
    used_patterns[_output_everything] = 1;
  else
    for (vec_size_t i = 0; i < _exprs.size(); i++)
	for (int k = 0; k < 2; k++)
	    if (_exprs[i].j[k] <= 0)
		used_patterns[-_exprs[i].j[k]] = 1;
  for (int i = 0; i < noutputs(); i++)
    if (!used_patterns[i])
      errh->warning("pattern %d matches no packets", i);
}

//
// CONFIGURATION
//

void
Classifier::init_expr_subtree(Vector<int> &tree)
{
  assert(!tree.size());
  tree.push_back(0);
}

void
Classifier::add_expr(Vector<int> &tree, const Expr &e)
{
    if (_exprs.size() < 0x7FFF) {
	_exprs.push_back(e);
	Expr &ee = _exprs.back();
	ee.yes() = SUCCESS;
	ee.no() = FAILURE;
	int level = tree[0];
	tree.push_back(level);
    }
}

void
Classifier::add_expr(Vector<int> &tree, int offset, uint32_t value, uint32_t mask)
{
  Expr e;
  e.offset = offset;
  e.value.u = value & mask;
  e.mask.u = mask;
  add_expr(tree, e);
}

void
Classifier::start_expr_subtree(Vector<int> &tree)
{
  tree[0]++;
}

void
Classifier::redirect_expr_subtree(int first, int last, int success, int failure)
{
  for (int i = first; i < last; i++) {
    Expr &e = _exprs[i];
    if (e.yes() == SUCCESS)
	e.yes() = success;
    else if (e.yes() == FAILURE)
	e.yes() = failure;
    if (e.no() == SUCCESS)
	e.no() = success;
    else if (e.no() == FAILURE)
	e.no() = failure;
  }
}

void
Classifier::finish_expr_subtree(Vector<int> &tree, Combiner combiner,
				int success, int failure)
{
  int level = tree[0];

  // 'subtrees' contains pointers to trees at level 'level'
  Vector<int> subtrees;
  {
    // move backward to parent subtree
    int ptr = _exprs.size();
    while (ptr > 0 && (tree[ptr] < 0 || tree[ptr] >= level))
      ptr--;
    // collect child subtrees
    for (ptr++; ptr <= (int)_exprs.size(); ptr++)
      if (tree[ptr] == level)
	subtrees.push_back(ptr - 1);
  }

  if (subtrees.size()) {

    // combine subtrees

    // first mark all subtrees as next higher level
    tree[subtrees[0] + 1] = level - 1;
    for (int e = subtrees[0] + 2; e <= (int)_exprs.size(); e++)
      tree[e] = -1;

    // loop over expressions
    int t;
    for (t = 0; t < (int)subtrees.size() - 1; t++) {
      int first = subtrees[t];
      int next = subtrees[t+1];

      if (combiner == C_AND)
	redirect_expr_subtree(first, next, next, failure);
      else if (combiner == C_OR)
	redirect_expr_subtree(first, next, success, next);
      else if (combiner == C_TERNARY) {
	if (t < (int)subtrees.size() - 2) {
	  int next2 = subtrees[t+2];
	  redirect_expr_subtree(first, next, next, next2);
	  redirect_expr_subtree(next, next2, success, failure);
	  t++;
	} else			// like C_AND
	  redirect_expr_subtree(first, next, next, failure);
      } else
	redirect_expr_subtree(first, next, success, failure);
    }

    if (t < (int)subtrees.size()) {
      assert(t == (int)subtrees.size() - 1);
      redirect_expr_subtree(subtrees[t], _exprs.size(), success, failure);
    }
  }

  tree[0]--;
}

void
Classifier::negate_expr_subtree(Vector<int> &tree)
{
  // swap 'SUCCESS' and 'FAILURE' within the last subtree
  int level = tree[0];
  int first = _exprs.size() - 1;
  while (first >= 0 && tree[first+1] != level)
    first--;

  for (vec_size_t i = first; i < _exprs.size(); i++) {
    Expr &e = _exprs[i];
    if (e.yes() == FAILURE)
	e.yes() = SUCCESS;
    else if (e.yes() == SUCCESS)
	e.yes() = FAILURE;
    if (e.no() == FAILURE)
	e.no() = SUCCESS;
    else if (e.no() == SUCCESS)
	e.no() = FAILURE;
  }
}

void
Classifier::compress_exprs(Vector<uint32_t> &prog, bool perform_binary_search,
			   unsigned min_binary_search) const
{
    // Compress the program into "prog."

    // The compressed program groups related Exprs together and sorts large
    // sequences of common primitives ("port 80 or port 90 or port 92 or ..."),
    // allowing the use of binary search.

    // The compressed program is a sequence of tests.  Each test consists of
    // five or more 32-bit words, as follows.
    //
    // +--------+--------+--------+--------+--------+-------
    // |nval|off|   no   |   yes  |  mask  |  value | value...
    // +--------+--------+--------+--------+--------+-------
    // nval (16 bits)  - number of values in the test
    // off (16 bits)   - offset of word into the data packet
    // no (32 bits)    - jump if test fails
    // yes (32 bits)   - jump if test succeeds
    // mask (32 bits)  - masked with packet data before comparing with values
    // value (32 bits) - comparison data (nval values).  The values are sorted
    //                   in numerical order if 'nval >= MIN_BINARY_SEARCH.'
    //
    // The test succeeds if the 32 bits of packet data starting at 'off,'
    // bitwise anded with 'mask,' equal any one of the 'value's.  If a 'jump'
    // value is <= 0, it is the negative of the relevant IPFilter output port.
    // A positive 'jump' value equals the number of 32-bit words to move the
    // instruction pointer.

    assert(prog.size() == 0);

    Vector<int> wanted(_exprs.size() + 1, 0);
    wanted[0] = 1;
    for (vec_size_t i = 0; i < _exprs.size(); i++) {
	const Expr *ex = &_exprs[i];

	if (wanted[i])
	    for (int j = 0; j < 2; j++)
		if (ex->j[j] > 0)
		    wanted[ex->j[j]]++;
    }

    Vector<int> offsets;
    for (vec_size_t i = 0; i < _exprs.size(); i++) {
	int off = prog.size();
	offsets.push_back(off);
	if (wanted[i] == 0)
	    continue;
	assert(_exprs[i].offset >= 0);
	prog.push_back(_exprs[i].offset + 0x10000);
	prog.push_back(_exprs[i].no());
	prog.push_back(_exprs[i].yes());
	prog.push_back(_exprs[i].mask.u);
	prog.push_back(_exprs[i].value.u);
	int no;
	while ((no = (int32_t) prog[off+1]) > 0 && wanted[no] == 1
		&& _exprs[no].yes() == _exprs[i].yes()
		&& _exprs[no].offset == _exprs[i].offset
		&& _exprs[no].mask.u == _exprs[i].mask.u) {
	    prog[off] += 0x10000;
	    prog[off+1] = _exprs[no].no();
	    prog.push_back(_exprs[no].value.u);
	    wanted[no]--;
	}
#if NOT_YET
	if (perform_binary_search && (prog[off] >> 16) >= min_binary_search)
	    click_qsort(&prog[off+4], prog[off] >> 16);
#endif
    }
    offsets.push_back(prog.size());

    for (vec_size_t i = 0; i < _exprs.size(); i++)
	if ((vec_size_t)offsets[i] < prog.size() && offsets[i] < offsets[i+1]) {
	    int off = offsets[i];
	    if ((int32_t) prog[off+1] > 0)
		prog[off+1] = offsets[prog[off+1]] - off;
	    if ((int32_t) prog[off+2] > 0)
		prog[off+2] = offsets[prog[off+2]] - off;
	}
}

std::string Classifier::program_string(void)
{
    std::string s("");
    char buf[256];

    for (vec_size_t i = 0; i < _exprs.size(); i++) {
	sprintf(buf, "%4zd  ", i);
	s += buf;
	s += _exprs[i].s();
	s += '\n';
    }
    if (_exprs.size() == 0) {
	sprintf(buf, "all->[%d]\n", _output_everything);
	s += buf;
    }
    return s;
}

void Classifier::dump_program(FILE *out)
{
    fprintf(out, "classifier program:\n%s", program_string().c_str());
}

int Classifier::match(const OffloadReq &req) const
{
    if (_output_everything >= 0)
	return _output_everything;

    const uint32_t *p = (const uint32_t *)&req;
    const Expr *ex = &_exprs[0];	// avoid bounds checking
    int pos = 0;

    do {
	const Expr *curr = &ex[pos];
	uint32_t data = p[curr->offset] & curr->mask.u;
	pos = curr->j[data == curr->value.u];
    } while (pos > 0);

    return -pos;
}

#ifndef USE_STD_VECTOR
# include "vector.cc"
#endif
