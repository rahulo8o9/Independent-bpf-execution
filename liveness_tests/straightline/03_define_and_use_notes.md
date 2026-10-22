# Test 3: Define and use (straight-line)

## Program
r6 = 42
r0 = r6
exit

## Expected (dataflow equations)
r6 is read at insn 1 -- must be live before insn 1.
r0 is read at insn 2 (exit) -- must be live before insn 2.

## Verifier result
Live regs before insn 0: (none)
Live regs before insn 1: r6 -- correctly live (read by r0 = r6)
Live regs before insn 2: r0 -- correctly live before exit

## Verdict
MATCH -- verifier correctly propagates liveness backward from the use.
No bug found in this case.
