# Test 2: Overwrite before use (straight-line)

## Program
r6 = 42
r6 = 99
r0 = 0
exit

## Expected (dataflow equations)
First write to r6 (insn 0) is a dead store -- immediately killed by
second write (insn 1) before any read. r6 should not be live anywhere.
r0 should be live only before exit.

## Verifier result
Live regs before insn 0: (none)
Live regs before insn 1: (none) -- correctly ignores the dead first write
Live regs before insn 2: (none)
Live regs before insn 3: r0 -- correctly live before exit

## Verdict
MATCH -- verifier correctly treats insn 0's write as dead.
No bug found in this case.
