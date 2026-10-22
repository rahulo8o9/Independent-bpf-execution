# Test 5: Arithmetic chain (straight-line)

## Program
r6 = 10
r6 += 5
r6 *= 2
r0 = r6
exit

## Hand-computed expected value
(10 + 5) * 2 = 30

## Expected liveness
r6 must be live before insns 1, 2, 3 (each reads the prior value of r6).
r0 live before exit.

## Verifier result (load-time)
Symbolic trace: R6=10 -> R6=15 -> R6=30 -> R0=30 (matches hand computation)
Liveness: r6 live before insns 1,2,3 -- matches expected.

## Runtime result
r0 (retval) = 30 -- matches hand computation exactly.

## Verdict
MATCH -- both load-time symbolic trace and runtime execution agree with
the hand-computed expected value. No bug found in this case.
Demonstrates combined load-time + run-time cross-check methodology.
