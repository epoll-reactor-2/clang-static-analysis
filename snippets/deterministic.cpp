#include <stdlib.h>

extern size_t get_size_external(void);

int _is_evaluable() {
  return 1 + 2;
}

int _is_evaluable_branch_same() {
  if (1)
    return 1;
  else
    return 1;
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

void test_malloc_origins(int n) {
  /*────────────────────────────
    Case 0: Evaluable functions.
   *───────────────────────────*/
  malloc(_is_evaluable());
  malloc(_is_not_evaluable());
  malloc(_is_evaluable_branch_same());
  malloc(_is_evaluable_branch_different());

  /*────────────────────────────
    Case 1 – compile‑time constant.
    EXPECT: Constant
   *───────────────────────────*/
  void *p1 = malloc(64);
  // CHECK: size-origin.c:[[#@LINE-1]]:{{[0-9]+}}:  malloc  Constant

  /*────────────────────────────
    Case 2 – arithmetic on constants.
    EXPECT: Deterministic
   *───────────────────────────*/
  void *p2 = malloc(32 + 16);
  // CHECK: size-origin.c:[[#@LINE-1]]:{{[0-9]+}}:  malloc  Deterministic

  /*────────────────────────────
    Case 3 – single variable, constant initializer.
    EXPECT: Deterministic
   *───────────────────────────*/
  size_t s3 = 128;
  void *p3 = malloc(s3);
  // CHECK: size-origin.c:[[#@LINE-1]]:{{[0-9]+}}:  malloc  Deterministic

  /*────────────────────────────
    Case 4 – caller‑supplied parameter (n).
    EXPECT: NonDeterministic
   *───────────────────────────*/
  void *p4 = malloc(n);
  // CHECK: size-origin.c:[[#@LINE-1]]:{{[0-9]+}}:  malloc  NonDeterministic

  /*────────────────────────────
    Case 5 – deterministic loop accumulation.
    EXPECT: Deterministic
   *───────────────────────────*/
  {
    size_t total = 0;
    for (int i = 0; i < 8; ++i)
      total += 10;                         // always 80
    void *p5 = malloc(total);
    // CHECK: size-origin.c:[[#@LINE-1]]:{{[0-9]+}}:  malloc  Deterministic
  }

  /*────────────────────────────
    Case 6 – value seeded by rand().
    EXPECT: NonDeterministic
   *───────────────────────────*/
  {
    size_t sz = rand();                    // nondeterministic
    sz += 4;                               // still nondeterministic
    void *p6 = malloc(sz);
    // CHECK: size-origin.c:[[#@LINE-1]]:{{[0-9]+}}:  malloc  NonDeterministic
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
    // CHECK: size-origin.c:[[#@LINE-1]]:{{[0-9]+}}:  malloc  Conflicting
  }

  /*────────────────────────────
    Case 8 – ternary choosing between constants.
    EXPECT: Deterministic
   *───────────────────────────*/
  {
    size_t s8 = (n > 10) ? 100 : 200;
    void *p8 = malloc(s8);
    // CHECK: size-origin.c:[[#@LINE-1]]:{{[0-9]+}}:  malloc  Deterministic
  }

  /*────────────────────────────
    Case 9 – sizeof expression.
    EXPECT: Deterministic
   *───────────────────────────*/
  {
    void *p9 = malloc(sizeof(int) * 4);
    // CHECK: size-origin.c:[[#@LINE-1]]:{{[0-9]+}}:  malloc  Deterministic
  }

  /*────────────────────────────
    Case 10 – external function result.
    EXPECT: NonDeterministic
   *───────────────────────────*/
  {
    void *p10 = malloc(get_size_external());
    // CHECK: size-origin.c:[[#@LINE-1]]:{{[0-9]+}}:  malloc  NonDeterministic
  }

  /*────────────────────────────
    Case 11 – explicit cast of constant.
    EXPECT: Constant
   *───────────────────────────*/
  {
    void *p11 = malloc((size_t)512);
    // CHECK: size-origin.c:[[#@LINE-1]]:{{[0-9]+}}:  malloc  Constant
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
    // CHECK: size-origin.c:[[#@LINE-1]]:{{[0-9]+}}:  malloc  Conflicting
  }
}
