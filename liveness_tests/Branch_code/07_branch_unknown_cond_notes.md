# Test 7: Branch with unknown condition

## Program
r6 = 1
r7 = skb->len
if r7 > 100 goto +1
r6 = 99
r0 = r6
exit

## Expected liveness
before 5: r0
before 4: r6
before 3: none
before 2: r6, r7
before 1: r1, r6
before 0: r1

## Runtime
r0 = 99 (len is 64, so the branch is not taken and r6 = 99 runs)

## Observation
Both paths were walked (fall-through and "from 2 to 4"). The liveness
block is identical to test 6, where the branch was pruned, so the
liveness pass is independent of path exploration.
