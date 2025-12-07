# Tradecraft Garden but in rust

*Note: All credits for techniques, original C code and modularisation using spec files go to Rapahel Mudge. I have only taken this work to showcase how Crystal Palace can be used in Rust. This project uses the original Tradecraft Garden as tests for low level techniques I have used in crystal-sdk* 

"[The Tradecraft Garden](https://tradecraftgarden.org/tradecraft.html) is a collection of position-independent capability loaders with background information on each". This project showcases how to write and use [position dependent code objects (PICOs)](https://tradecraftgarden.org/docs.html#picos) in rust through the use of:

 - [Crystal Palace](https://tradecraftgarden.org/crystalpalace.html): "Linker and linker script language specialised to the needs of writing position-independent DLL and COFF loaders"
 - [crystal-bindings](https://github.com/laachy/crystal-bindings): Crate to dynamically generate *-sys style rust bindings from c headers, specifically to allow usage of crystal palace style libraries created in c in our rust PICOs
 - [crystal-sdk](https://github.com/laachy/crystal-sdk): Crate to enable usage of crystal palace linking features and ergonomic PICO development in rust

I have provided all of the original Tradecraft Garden as a means to give context to how **c to rust** PICOs translate in their writing conventions and also so that **c and rust** PICOs can be tested and linked with each other as a form of proof that this project can help expand the ecosystem which is position independent tradecraft in contrast to creating its own. For more information and a better learning experience I urge you to check out the original [Tradecraft Garden](https://tradecraftgarden.org/index.html) and the [blog](aff-wg.org) that explains new updates and design choices for the linker.

## Contents
- [Garden Quick Find](#garden-quick-find)
- [Usage / Guide](#usage)
- [Additional Notes and Development Disclaimers](#notes)
- [TODO and Issues](#todo-and-issues)

## Garden Quick Find
- [Simple Loader 1](./src/loader1) Simple DLL loader
- [Simple Loader 2 (COFF)](./src/loader2) Simple DLL loader that frees itself with an embedded COFF
- [Simple Loader 3 (Resource Masking)](./src/loader3) Simple DLL loader that accesses masked resources
- [Simple Loader 4 (Pointer Patching)](./src/loader4) Simple DLL loader that bootstraps with patched-in pointers
- [Simple Loader 5 (Execution Guardrails)](./src/loader5) Simple loader stage that implements execution guardrails
- [Simple Loader 6 (Hooking)](./src/loader6) Simple DLL loader that uses IAT hooks to change loaded DLL's behavior
    - [XOR Hooks](./src/loader6/modules/xorhooks) module to XOR mask a DLL when a hooked function is called
    - [Stack Cutting](./src/loader6/modules/stackcutting) Push sensitive Win32 API calls through a stack-cutting call proxy
- [Simple Loader 7 (COFF Capability)](./src/loader7) Simple OBJ loader
- [Simple Loader 8 (Mixed COFF and DLL)](./src/loader8) Simple OBJ and DLL loader (supporting both)
- [Simple PIC](./src/simple_pic) Simple PIC Services Module
- [Page Streaming](./src/page_streaming) Use guard pages and Vectored Exception Handlers to "stream" DLL pages as needed


## Usage
### Rust nightly toolchain (Windows GNU)

This project requires the Rust **nightly** toolchain for the GNU ABI on Windows  
(target triple: `x86_64-pc-windows-gnu`). The only reason **nightly** is needed is for the -Zno-link compiler flag for a better object compilation project structure.
1. **Install Rust and rustup**

   If you don’t have Rust yet, install it via rustup from the official site:  
   https://rustup.rs/

2. **Install the nightly toolchain for `x86_64-pc-windows-gnu`**

   ```powershell
   rustup toolchain install nightly-x86_64-pc-windows-gnu
### Compilation:

Loaders are located within `src` and contain a **Makefile** that compiles individual objects into `bin/"language"` of that loaders directory.
Included is a root **Makefile** `(src/Makefile)` that compiles **EVERYTHING** you need. 

```powershell
   cd src ; make
```

### Linking:

 1. **Download the linker**
	```powershell
	https://tradecraftgarden.org/crystalpalace.html
 	```
 2.  **Link**
		
		Spec files are included in each loaders root directory, by default they link all rust objects. This can be changed easily inside the .spec file

		Linking commands are the same as shown in the original tutorials. In each loaders **README.md** there are sample linking commands assuming `cwd = bin`

		Demo DLLs and Objects are found in `src/demo`. These can be used for linking and testing.

### Execution:

1. Take the **shellcode executer** `run.exe` from `src/demo`


2. **Execute on Windows host**
	```powershell
	run.exe out.bin
 	```
## Notes

- [Size] While Rust is usually known for larger binary sizes compared to C, I have noticed that the object and final shellcode sizes have been smaller using Rust in this project. Without much thought or research into it, I believe this is because of the tail call optimisations present. You can test the sizes for your self, I think one of the best tests is loader 7, or alternatively comparing objects.
- [Rust LTO](CallWalk.java) While originally I wanted to keep the source code of Crystal Palace untouched, I came to the conclusion that it is in my best interests to do some minimal modifications. Vanilla Crystal Palace does not touch JMP instructions. I have fixed this for optimisations so that final binaries are smaller and more complex capabilities can be linked. You can find this at `CallWalk.java`

# TODO and issues

 1. The only thing not working ATM is proxy.rs within stackcutting. Some kind of issue with stack frames, access exception on the second call.
 2. Fixing JMPs (tail call optimisation) within the linker. This is the best approach as TCO is worth keeping. Current issues are related to merging PICOs that use functions referenced on JMPs (xorhook_setup.rs), also hook placement (stackcut)
 3. Globals within stackcut are weird, I hacked around it by linking to .cplink but its better to use .bss. Not really sure what the exact issue is as it works fine on other loaders, will need to test more thoroughly with unitialised data that is merged.
 4. x86 (32bit) support and examples
 5. Other TODOs in crystal-sdk
