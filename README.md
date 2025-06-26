This projects shows how to setup and use
* Recursive AST visitors
* AST matchers
* Dataflow analysis API with its lattice concept

This pass creates a data structure named lattice, which is populated while DataflowAnalysis
goes over the code. Analyzer able to make judgements based on a lattice state, which contains
information about const-evaluable property of the malloc() argument.

In fact, this is a partial -Wunsafe-buffer-usage implementation.

Example result:

```c
   1    char *p12 = (char *) malloc(10);
   2    p12[0] = 'a';
   3    p12[1 + 2] = 'a';
   4    p12[10 + 20] = 'a';
   5    p12[100] = 'b';
```

```
/.../code.cpp:4:10: warning: Out of range! 30 vs 10
  181 |   p12[10 + 20] = 'a';
      |          ^
Array access[100] to variable `p12`
/.../code.cpp:5:7: warning: Out of range! 100 vs 10
  182 |   p12[100] = 'b';
      |          ^
```
