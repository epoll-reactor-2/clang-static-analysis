for f in unknown-*.cpp; do
  echo "Compiling with GCC -fanalyzer"
  g++ -fsanitize=address -fanalyzer -O0 $f
  echo ""
  echo "Compiling with Clang --analyze "
  clang++ -fsanitize=address --analyze -O0 $f
  echo ""
  echo "Boom..."
  VAR=1 ./a.out
done
