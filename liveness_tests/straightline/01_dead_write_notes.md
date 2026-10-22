# Test 1: Dead write (straight-line)

## Program
r6 = 42
r0 = 0
exit

## Expected (dataflow equations)
r6 is written once, never read -> should be dead everywhere after insn 0.
r0 is used by exit -> should be live before insn 2.

## Verifier result
Live regs before insn 0: (none)
Live regs before insn 1: (none) -- r6 correctly not marked live
Live regs before insn 2: r0 -- correctly marked live before exit

## Verdict
MATCH -- verifier liveness tracking agrees with expected dataflow result.
No bug found in this case.
