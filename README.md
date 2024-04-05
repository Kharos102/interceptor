# interceptor

Sample library and client to demonstrate two methods of hooking targets on x86 and x86-64 platforms (inline and pointer swapping).

The library is platform agnostic for x86 and x86-64 architectures (requires an allocator).

To run the sample, navigate into `client_sample` and run for x86 or x86-64 (note: the client is a Windows example, but the library is platform agnostic).

E.g. `cargo run` when on an x64 host, or `cargo run --target=i686-pc-windows-msvc` for x86.
