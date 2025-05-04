# pf
A library I quickly threw together to add some benchmarking code I commonly use.
It has 2 things:
1. An interface for accessing TSC and using it to measure time durations.
2. An interface for using perf that can track P and/or E cores.

This is not production quality. There are probably resource leaks and/or subtle bugs.
This is a simple library for quickly throwing benchmarks together on my machine.
