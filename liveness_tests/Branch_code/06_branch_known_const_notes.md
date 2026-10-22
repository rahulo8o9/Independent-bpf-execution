# Test 6: Branch with known constant condition

## Program
r6 = 1
r7 = 2
if r7 > 0 goto +1
r6 = 99
r0 = r6
exit

## Expected liveness (backward, JOIN over successors)
before 5: r0
before 4: r6
before 3: none
before 2: r6, r7
before 1: r6
before 0: none

## Runtime
r0 = 1 (branch always taken, r6 = 99 skipped)

## Observation
Path walk skipped insn 3 because r7 = 2 is a known constant, but the
"Live regs before insn" block still lists insn 3. The liveness pass is a
static scan of the whole CFG and does not depend on pruning.


