# dllinject

A slimmed down version of [global-inject-demo](https://github.com/m417z/global-inject-demo) with only the DLL injection part, wrapped in a Rust library.

Allows injecting a DLL into a target process:

- 64-bit -> 64-bit
- 32-bit -> 32-bit
- 64-bit -> 32-bit
- 32-bit -> 64-bit (using Heaven's Gate)
