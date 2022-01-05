# tsha256

tsha256 is a register only implementation of the Secure Hash Algorithm 2
(SHA256).

It was originally intended to be integrated into the Linux kernel to replace
the modified TRESOR sha256 implementation.  The t comes from TRESOR which
which the design was inspired from.

This implementation is a Work In Progress (WIP).  The part that is missing is
maybe is to control of the CPU scheduler or preemption to prevent the possiblity
of peeking at the registers by other running tasks.

It should not be built and run in user space but only in kernel space.

## Completion

It was decided to put the project on hold indefinitely.

It is on hold for larger key sizes due to technical issues with not enough
register space until a new CPU can be obtained.

The other reason for the hold is the
[cryptoanalysis attack issues](https://en.wikipedia.org/wiki/SHA-2#Comparison_of_SHA_functions)
with SHA-2.

Only the reference implementation for SHA512/256 was complete but the assembly
and hybrid versions are on indefinite hold because of the insufficient register
issue.

The implementations needs to be tested for larger messages.  It is not sure
if the 64 byte sequence for the size is correct.

Implementing the .c reference version took about a day to complete.

The sha256 assembly version took about 11 days to complete.

## License

MIT
