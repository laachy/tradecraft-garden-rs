# Tradecraft Garden but in rust

"[The Tradecraft Garden](https://tradecraftgarden.org/tradecraft.html) is a collection of position-independent capability loaders with background information on each". This project showcases how to write and use [position dependent code objects (PICOs)](https://tradecraftgarden.org/docs.html#picos) in rust through the use of:

 - [Crystal Palace](https://tradecraftgarden.org/crystalpalace.html): "Linker and linker script language specialised to the needs of writing position-independent DLL and COFF loaders"
 - [crystal-bindings](https://github.com/laachy/crystal-bindings): Crate to dynamically generate *-sys style rust bindings from c headers, specifically to allow usage of crystal palace style libraries created in c in our rust PICOs
 - [crystal-sdk](https://github.com/laachy/crystal-sdk): Crate to enable usage of crystal palace linking features and ergonomic PICO development in rust

I have provided all of the original Tradecraft Garden as a means to give context to how **c to rust** PICOs translate in their writing conventions and also so that **c and rust** PICOs can be tested and linked with each other as a form of proof that this project can help expand the ecosystem which is position independent tradecraft in contrast to creating its own. For more information and a better learning experience I urge you to check out the original [Tradecraft Garden](https://tradecraftgarden.org/index.html) and the [blog](aff-wg.org) that explains new updates and design choices for the linker.

One thing to also add is that I have noticed rust object files and end binaries to be smaller than its c counterparts. (You can compare for yourself)


# Usage
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

  ```powershell
   cd src/loader1 ; make
```

### Linking:

 1. **Download the linker**
	
	Download the linker from https://tradecraftgarden.org/crystalpalace.html
 2.  **Link**
		
		Spec files are included in each loaders root directory, by default they link all rust objects. This can be changed easily inside the .spec file

		Linking commands are the same as shown in the original tutorials. Demo DLLs and Objects are found in `src/demo`. These can be used for linking and testing.

# TODO and issues

 1. The only loader/capability that doesn't work is loader6/stackcutting, it wont link with rust objects (specific issue with stackcut.rs globals), ive noticed crashing using .rs services module and im sure theres more issues. This will require a more in depth look into the crystal palace source code that I will do at a later date.
 2. Optimise crystal palace directive does not work due to rust/llvm tail call optimisations where direct function symbols are not refrenced. This causes the linker to view them as unused where in reality their addresses are jumped to. To fix this would either need to disable tail call optimisations (at the callsite or globally for every function), provide a patch to the linker, or jmp, function symbol ??? (is that even possible, an idea anyway)
 3. Other TODOs in crystal-sdk
