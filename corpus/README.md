# Seed corpus

Raw DNS packets used to seed the fuzzers and as quick manual test inputs.

- `valid/` — well-formed packets the airlock accepts and the C++ parses fine.
- `malformed/` — packets the airlock rejects. `label_overread.bin` and
  `pointer_wild.bin` are the two that crash the raw C++ parser under ASan.

Seed a cargo-fuzz run with them:

```bash
cp corpus/valid/*.bin corpus/malformed/*.bin fuzz/corpus/raw_parser/   # after `cargo fuzz run` creates the dir
```

Feed one to the raw parser by hand (ASan build):

```bash
g++ -std=c++17 -fsanitize=address -g -Icpp/include \
    cpp/src/dns_parser.cpp cpp/src/fuzz_one.cpp -o /tmp/fuzz_one
/tmp/fuzz_one < corpus/malformed/label_overread.bin   # ASan crash
/tmp/fuzz_one < corpus/valid/example_com.bin          # clean
```
