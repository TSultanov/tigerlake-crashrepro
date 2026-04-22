We observe a weird crash of some program on Intel i5-1135G7 which we suspect might be related to several AVX512 instructions, but we don't know which. Crashdumps usually point to random vmovdqu64 instructions which ought to be executing completely valid operations. The most interesting part that sometimes the entire Linux system crashes, sometimes only the application.

Goal is to produce a program which will try to fuzz the AVX512 instructions execution on that CPU and try to recreate the crash behaviour.

Produce a C program with inline assembly which will attempt to do the fuzzing. Target Linux. This machine runs ARM64 macOS, so consider provisions for cross-compilation.