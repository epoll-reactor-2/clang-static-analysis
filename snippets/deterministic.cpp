#include <stdlib.h>

extern size_t get_size_external(void);

int _is_evaluable() {
  return 1 + 2;
}

int _is_evaluable_branch_same() {
  if (1)
    return 10;
  else
    return 10;
}

int _is_evaluable_branch_different() {
  if (1)
    return 1;
  else
    return 2;
}

int _is_not_evaluable() {
  return rand();
}

void deterministic_chain(void) {
  size_t s = 8;
  s += 3 * 4;
  s = (s << 2) / 2;
  s ^= 2u;
  s += sizeof(double);
  s = (s & 0x7F) | 0x30;
  for (int i = 0; i < 5; ++i)
      s += 7;
  s += (1 ? 15 : 99);
  void *buf = malloc(s);
  // CHECK: deterministic.cpp:[[#@LINE-1]]:{{[0-9]+}}:  malloc  Constant
}

void test_malloc_origins(int n) {
  /*────────────────────────────
    Case 0: Evaluable functions.
   *───────────────────────────*/
  char *c1 = (char *) malloc(_is_evaluable());
  char *c2 = (char *) malloc(_is_not_evaluable());
  char *c3 = (char *) malloc(_is_evaluable_branch_same()); // 10
  char *c4 = (char *) malloc(_is_evaluable_branch_different());
  c3[0] = 'a';
  c3[9] = 'b';
  c3[10] = 'c';
  c3[100000] = 'd';

  /*────────────────────────────
    Case 1 – compile‑time constant.
    EXPECT: Constant
   *───────────────────────────*/
  void *p1 = malloc(64);
  // CHECK: deterministic.cpp:[[#@LINE-1]]:{{[0-9]+}}:  malloc  Constant

  /*────────────────────────────
    Case 2 – arithmetic on constants.
    EXPECT: Deterministic
   *───────────────────────────*/
  void *p2 = malloc(32 + 16);
  // CHECK: deterministic.cpp:[[#@LINE-1]]:{{[0-9]+}}:  malloc  Deterministic

  /*────────────────────────────
    Case 3 – single variable, constant initializer.
    EXPECT: Deterministic
   *───────────────────────────*/
  size_t s3 = 128;
  void *p3 = malloc(s3);
  // CHECK: deterministic.cpp:[[#@LINE-1]]:{{[0-9]+}}:  malloc  Deterministic

  /*────────────────────────────
    Case 4 – caller‑supplied parameter (n).
    EXPECT: NonDeterministic
   *───────────────────────────*/
  void *p4 = malloc(n);
  // CHECK: deterministic.cpp:[[#@LINE-1]]:{{[0-9]+}}:  malloc  NonDeterministic

  /*────────────────────────────
    Case 5 – deterministic loop accumulation.
    EXPECT: Deterministic
   *───────────────────────────*/
  {
    size_t total = 0;
    for (int i = 0; i < 8; ++i)
      total += 10;                         // always 80
    void *p5 = malloc(total);
    // CHECK: deterministic.cpp:[[#@LINE-1]]:{{[0-9]+}}:  malloc  Deterministic
  }

  /*────────────────────────────
    Case 6 – value seeded by rand().
    EXPECT: NonDeterministic
   *───────────────────────────*/
  {
    size_t sz = rand();                    // nondeterministic
    sz += 4;                               // still nondeterministic
    void *p6 = malloc(sz);
    // CHECK: deterministic.cpp:[[#@LINE-1]]:{{[0-9]+}}:  malloc  NonDeterministic
  }

  /*────────────────────────────
    Case 7 – branch merges constant & nondet.
    EXPECT: Conflicting
   *───────────────────────────*/
  {
    size_t s7;
    if (n > 0)
      s7 = 256;                            // constant
    else
      s7 = rand();                         // nondeterministic
    void *p7 = malloc(s7);
    // CHECK: deterministic.cpp:[[#@LINE-1]]:{{[0-9]+}}:  malloc  Conflicting
  }

  /*────────────────────────────
    Case 8 – ternary choosing between constants.
    EXPECT: Deterministic
   *───────────────────────────*/
  {
    size_t s8 = (n > 10) ? 100 : 200;
    void *p8 = malloc(s8);
    // CHECK: deterministic.cpp:[[#@LINE-1]]:{{[0-9]+}}:  malloc  Deterministic
  }

  /*────────────────────────────
    Case 9 – sizeof expression.
    EXPECT: Deterministic
   *───────────────────────────*/
  {
    void *p9 = malloc(sizeof(int) * 4);
    // CHECK: deterministic.cpp:[[#@LINE-1]]:{{[0-9]+}}:  malloc  Deterministic
  }

  /*────────────────────────────
    Case 10 – external function result.
    EXPECT: NonDeterministic
   *───────────────────────────*/
  {
    char *p10 = (char *) malloc(get_size_external());
    p10[0] = 'a';
    p10[1000] = 'b';
    // CHECK: deterministic.cpp:[[#@LINE-1]]:{{[0-9]+}}:  malloc  NonDeterministic
  }

  /*────────────────────────────
    Case 11 – explicit cast of constant.
    EXPECT: Constant
   *───────────────────────────*/
  {
    void *p11 = malloc((size_t)512);
    // CHECK: deterministic.cpp:[[#@LINE-1]]:{{[0-9]+}}:  malloc  Constant
  }

  /*────────────────────────────
    Case 12 – deterministic loop + optional nondet branch.
    EXPECT: Conflicting
   *───────────────────────────*/
  {
    size_t s12 = 0;
    for (int i = 0; i < 5; ++i)
      s12 += 20;                           // deterministic 100
    if (n & 1)
      s12 += rand();                       // may add nondet component
    void *p12 = malloc(s12);
    // CHECK: deterministic.cpp:[[#@LINE-1]]:{{[0-9]+}}:  malloc  Conflicting
  }
  
  /*────────────────────────────
    Case 12 – deterministic loop + optional nondet branch.
    EXPECT: Conflicting
   *───────────────────────────*/

  char *p12 = (char *) malloc(10);
  p12[0] = 'a';
  p12[1 + 2] = 'a';
  p12[10 + 20] = 'a';
  p12[100] = 'b';
}
