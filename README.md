# crashrepro

AVX-512 crash-reproduction fuzzer for Intel i5-1135G7 (Tiger Lake).

See [TASK.md](TASK.md) for the original problem statement. In short: a
real workload crashes with faults on seemingly-valid `vmovdqu64`
instructions, and sometimes takes the whole Linux host down with it —
strongly suggesting a CPU-level (Tiger Lake) issue around AVX-512,
likely at the frequency/voltage license boundary. This tool deliberately
exercises many AVX-512 shapes concurrently with forced frequency
transitions, captures what was executing when a signal lands, and writes
a per-thread durable state file every iteration so we can recover the
last-known state after a whole-machine crash + reboot.

## Build

Requires [zig](https://ziglang.org/) (for its `zig cc` cross compiler).
On macOS: `brew install zig`.

```
./build.sh
file crashrepro   # ELF 64-bit LSB executable, x86-64, statically linked
```

The binary is a static musl x86_64 Linux executable — copy it to the
target machine, no glibc version matching required.

## Usage

```
./crashrepro --help
```

Common runs:

```
# Smoke test, one thread, no churn, oracle-check only:
./crashrepro --threads=1 --iters=10000 --churn=off

# Full-throttle fuzzing on the target (default):
./crashrepro --logdir=/var/tmp/cr

# Deterministic replay of one class using a seed we saw crash before:
./crashrepro --seed=0xDEADBEEFCAFEBABE --threads=1 \
             --classes=vmovdqu64 --churn=off --iters=1000000

# Isolate overlap-only operand layouts while chasing a move crash:
./crashrepro --threads=1 --classes=vmovdqu64 \
             --shapes=dst_overlaps_a,a_overlaps_dst --churn=off

# After a whole-system crash, reboot and inspect last-known state:
./crashrepro --replay=/var/tmp/cr
```

Flags of note:

- `--seed=<u64>` — base RNG seed; each thread uses `seed ^ (tid * golden)`
  so a crash can be reproduced exactly.
- `--threads=<N>` — default: online CPU count.
- `--iters=<N>` — per-thread iteration count; 0 (default) runs until
  SIGINT / SIGTERM.
- `--classes=<csv>` — restrict to named classes; `--list-classes` prints
  them.
- `--shapes=<csv>` — restrict to named operand layouts such as
   `distinct`, `dst_eq_a`, or `dst_overlaps_a`; `--list-shapes` prints
   them. Shapes that are impossible for a selected instruction class are
   skipped.
- `--verify=on|off` — compare against a scalar oracle (default: on).
- `--churn=on|off` — interleave AVX-512 frequency/voltage bursts
   using a mix of throughput-heavy, dependency-heavy, and memory-heavy
   burst profiles (default: on).
- `--pin` — pin thread *i* to core *i*.
- `--verbose` — echo every logged iteration to stderr (very chatty;
  without it the logger still emits a ~1/sec per-thread heartbeat so
  you can see activity live).

## What it does

For each iteration, per thread:

1. Picks an instruction class, operand shape (distinct, aliased, or
   partially overlapping where legal), a mask register (`k1`..`k7`),
   alignment offset (with 1/8 probability biased toward page-straddling),
   mask pattern (mix of edge cases and random), and zero-vs-merge
   masking.
2. Writes the iteration descriptor to a per-thread mmap'd state file
   and `msync`s it — this is what survives a kernel panic.
3. Runs the AVX-512 inline-asm executor against three guard-paged
   scratch regions (A, B, dst).
4. If verification is on, re-runs the operation in a scalar oracle
   (built with `__attribute__((target("no-avx")))` so the compiler
   cannot cheat) and `memcmp`s the result — silent miscomputation
   shows up here.
5. Bumps iteration counter; ~1/256 of the time, fires an AVX-512
   burst-then-gap cycle that forces a frequency/voltage transition. The
   burst profile is varied between independent ALU pressure, dependent
   chains, and unaligned `vmovdqu64`-heavy load/store traffic.

On SIGSEGV / SIGILL / SIGBUS / SIGFPE / SIGTRAP: an async-signal-safe
handler writes signal info, full integer register file, the thread's
last 64 iteration descriptors, and a best-effort 64-byte hex dump
around RIP, to `${logdir}/crash.t<tid>.log`.

## Repro recipe

1. Smoke-test on any AVX-512 Linux host with `--churn=off --threads=1
   --iters=10000`. Zero mismatches, zero signals — proves the fuzzer
   is sound.
2. Run on the target i5-1135G7:
   `./crashrepro --logdir=/var/tmp/cr` and leave it.
3. Wait for a crash.
4. Collect `/var/tmp/cr/*`, plus `dmesg -T` and (if the whole host
   went down) `/var/log/kern.log` from before the reboot.
5. Read `state.t*.bin` via `--replay=/var/tmp/cr` to see what was
   executing per thread at the moment of death.
6. Plug the failing thread's seed + iteration into a single-threaded
   deterministic replay:
   `--seed=<s> --threads=1 --iters=<n+1> --classes=<that class>
    --churn=off`
   to bisect down to a minimal repro.

## Instruction classes covered

Run `./crashrepro --list-classes` for the current list. Current
coverage emphasises moves (the reported crash site) and includes
integer add/xor/shift/multiply, ternary logic (vpternlogq imm8=0xCA),
and the unary popcnt/lzcnt ops — with both zero-mask and merge-mask
variants of each. Expanding this is straightforward: add an entry to
`insn_specs[]` in [src/insns.c](src/insns.c) plus a scalar oracle in
[src/insns_oracle.c](src/insns_oracle.c).
