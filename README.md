[![dependency status](https://deps.rs/repo/github/jedisct1/rust-libhydrogen/status.svg)](https://deps.rs/repo/github/jedisct1/rust-libhydrogen)

![libhydrogen for rust](https://raw.github.com/jedisct1/libhydrogen/master/logo.png)
====================

The [Hydrogen](https://github.com/jedisct1/libhydrogen) library is a small, easy-to-use, hard-to-misuse cryptographic library.

Features:
- Consistent high-level API, inspired by libsodium. Instead of low-level primitives, it exposes simple functions to solve common problems that cryptography can solve.
- 100% built using just two cryptographic building blocks: the [Curve25519](https://cr.yp.to/ecdh.html) elliptic curve, and the [Gimli](https://gimli.cr.yp.to/) permutation.
- Small and easy to audit. Implemented as one tiny file for every set of operation, and adding a single `.c` file to your project is all it takes to use libhydrogen in your project.
- The whole code is released under a single, very liberal license (ISC).
- Zero dynamic memory allocations and low stack requirements (median: 32 bytes, max: 128 bytes). This makes it usable in constrained environments such as microcontrollers.
- Portable. Supports Linux, *BSD, MacOS, Windows, and the Arduino IDE out of the box.
- Can generate cryptographically-secure random numbers, even on Arduino boards.
- Attempts to mitigate the implications of accidental misuse, even on systems with an unreliable PRG and/or no clock.

This crate implement high-level Rust bindings.

# Documentation

* [Rust API documentation](https://docs.rs/libhydrogen)
* [Original libhydrogen documentation](https://github.com/jedisct1/libhydrogen/wiki)
