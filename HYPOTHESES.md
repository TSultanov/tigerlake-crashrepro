# Hypotheses for reproducing the i5-1135G7 vmovdqu64 crash

The fuzzer (`crashrepro`) already exercises a broad set of AVX-512 stressors: instruction class × operand shape × mask pattern × alignment × page-straddle × shared-dst × async signal pressure × frequency-license churn (passive/scalar/avx2/train profiles). The bug hasn't reproduced yet. The original symptoms are:

- Faults cited as `vmovdqu64` at random RIPs, on what should be valid operands.
- **Sometimes takes the whole Linux host down** — that's the strongest signal. Architecturally-faulting user instructions don't crash the kernel; an MCE, a kernel XSAVE/XRSTOR bug, or a hardware errata in the save-restore path does.

This document enumerates hypotheses that were initially missing from the
fuzzer, ranks them, and notes the concrete knob each now uses when
implemented.

Existing coverage inventory (for reference): see [src/fuzz.c](src/fuzz.c), [src/insns.c](src/insns.c), [src/power.c](src/power.c), [src/main.c](src/main.c). Already covered: frequency-license churn, dst aliasing, page straddle, masked zero/merge, async signal injection, nested / alt-stack / RT signal save-restore, shared-dst contention, gather/scatter, compress/expand, dirty-upper entry, TLB shootdown noise, gather/scatter partial-fault recovery, SMT sibling antagonists, and fork-churn. The newly added knobs are default-on and can be disabled explicitly.

## Hypothesis classes

Each entry: **[Hypothesis] → why it matches the symptoms → concrete fuzzer knob**.

### Tier 1: best fit for "crashes the whole host"

A whole-host crash means either (a) kernel-side state corruption around AVX-512 XSAVE/XRSTOR, (b) hardware MCE / bad microcode path, or (c) a TLB / memory-management race where user AVX-512 execution contends with a kernel operation. The biggest gaps here are:

1. **[Implemented] Dirty upper-ZMM entry** — bursts can now enter with live upper-YMM state via the default-on `--dirty-upper=<on|off>` warmup, which uses VEX-encoded AVX2 ops touching `ymm0..ymm15` immediately before the AVX-512 dispatch and omits `vzeroupper`. Pairs with the existing `--churn-profile=avx2`.

2. **[Implemented] Nested / alt-stack / RT signal save-restore** — interrupt pressure now defaults to `--interrupt-variant=nested`. Workers verify `sigaltstack()` setup during thread init, the primary `SIGUSR1` handler self-targets a realtime signal from the `SIGRTMIN..SIGRTMAX` range, and the realtime handler briefly re-enters masked AVX-512 on the worker alt stack.

3. **[Implemented] TLB-shootdown-under-burst** — the default-on `--tlb-noise=<on|off>` helper thread now cycles `mprotect(PROT_NONE)` ↔ `mprotect(PROT_READ|PROT_WRITE)` plus `madvise(MADV_DONTNEED)` on a scratch page separate from A/B/dst while workers execute AVX-512.

4. **[Implemented] Gather/scatter partial-fault recovery** — the default-on `--gather-scatter-partial-fault=<on|off>` path now uses raw signed gather/scatter offsets on a subset of `vpgatherdd` / `vpscatterdd` iterations so some active lanes stay valid and one active lane lands in a guard page. These iterations reuse the existing expected-fault recovery path and skip oracle comparison.

5. **[Implemented] SMT sibling license antagonist** — the default-on `--smt-antagonist=<on|off>` mode now discovers sibling pairs from `/sys/devices/system/cpu/cpu*/topology/thread_siblings_list`, auto-pins each worker to one logical CPU, and runs an AVX2-only antagonist thread on the sibling. The default worker count changes to one worker per sibling pair while this mode is enabled.

### Tier 2: plausible, good follow-ups if Tier 1 doesn't reproduce

6. **Non-temporal + masked-store interleave** — `vmovntdq` / `vmovntdqa` against write-combining buffers, followed by masked `vmovdqu64` to overlapping lines. Currently we only do normal temporal stores. → New instruction class + `--nt=on` knob.

7. **Cache-line-split masked stores** — page-straddle is sampled at 1/8; *cache-line* straddle (64-byte-boundary-within-page) with a non-trivial mask is not explicitly forced. → Add a shape variant `clsplit` that biases offsets to {56..63} mod 64.

8. **K-mask register-file pressure** — current masks use k1–k7 one at a time. Force a dependent chain using all of k1–k7 simultaneously (with `kmovq`/`kunpckbw`/`korq`) to provoke rename/spill paths in the mask register file. → New "mask-chain" churn kernel in [src/power.c](src/power.c).

9. **Embedded broadcast & rounding/SAE** — no `{1toN}` broadcast decode path tested; no `{rn-sae}` / `{sae}`. Broadcast takes a different load-path in the FE. → Extend [src/insns.c](src/insns.c) shapes with `bcast64`, `bcast32`. SAE only applies to FP; pair with next item.

10. **FP / FMA with denormals + MXCSR state** — current instruction mix is integer-only. FMA + denormal inputs + DAZ/FTZ toggled exercises microcode assists and is a separate retirement path. → Add `vfmadd132pd`, toggle MXCSR DAZ/FTZ each iteration, feed denormal/NaN/±0 mixed inputs.

11. **[Implemented] fork() mid-burst** — the default-on `--fork-churn=<on|off>` path occasionally forks after a hot AVX-512 iteration; the child runs one `vmovdqu64` probe and exits immediately.

12. **PEBS / perf_event NMI pressure** — open a high-rate sampling perf event on the worker and let NMI-like interrupts save/restore ZMM. This is the real-world analogue of our SIGUSR1 stressor but at a different kernel path. → `--perf-pressure=on`, requires `CAP_PERFMON` or perf paranoid level.

### Tier 3: long shots, cheap to add

13. **UC / WC memory-type mappings for scratch regions** — via `/dev/mem` or a small kernel module; mostly non-portable, skip unless Tier 1/2 all fail.
14. **THP + AVX-512 alignment** — `madvise(MADV_HUGEPAGE)` on A/B/dst; may change page-straddle semantics at 2 MiB boundaries.
15. **AVX-VNNI / VAES / GFNI / VPCLMULQDQ coverage** — feature bits are detected but unused; add one class each.
16. **Longer temporal mask patterns** — keep the same mask across N iterations rather than resampling, to expose mask-history-dependent bugs.
17. **Deliberate split-lock atomics near AVX-512** — `lock add` on a cache-line-straddling address interleaved with `vmovdqu64`.
18. **ptrace attach mid-burst** — a sidecar process attaches, single-steps one instruction, detaches.

## Ranking and recommended next step

All Tier 1 whole-host hypotheses are now represented in-tree: **#1**, **#2**, **#3**, **#4**, and **#5** are implemented, with **#11** added from Tier 2 as an XSAVE/COW follow-up. The remaining gaps are the Tier 2 and Tier 3 follow-ups, which are more likely to surface silent miscompare than a host-down event.

Recommended next concrete step: add **#8** K-mask register-file pressure or **#10** FP / FMA with denormals + MXCSR state, since the main whole-host signal, memory-management, sibling-contention, and XSAVE inheritance stressors are now in place.
