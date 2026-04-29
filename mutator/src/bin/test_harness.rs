use std::error::Error;
use std::os::raw::c_void;
use std::ptr;

// Emulate AFL++ types and signatures
type MutatorInit = unsafe extern "C" fn(*mut c_void, u32) -> *mut c_void;
type MutatorFuzz = unsafe extern "C" fn(*mut c_void, *mut u8, usize, *mut *mut u8, *mut u8, usize, usize) -> usize;
type MutatorDeinit = unsafe extern "C" fn(*mut c_void);

fn main() -> Result<(), Box<dyn Error>> {
    unsafe {
        let lib = libloading::Library::new("./target/release/libmutator.so")?;

        let init: libloading::Symbol<MutatorInit> = lib.get(b"afl_custom_init")?;
        let fuzz: libloading::Symbol<MutatorFuzz> = lib.get(b"afl_custom_fuzz")?;
        let deinit: libloading::Symbol<MutatorDeinit> = lib.get(b"afl_custom_deinit")?;

        std::env::set_var("TREESCANNER_HINTS", "hints.json");

        let state = init(ptr::null_mut(), 42);
        if state.is_null() {
            return Err("afl_custom_init returned null state".into());
        }

        let mut input = vec![10, 20, 30, 40];
        let mut out_buf: *mut u8 = ptr::null_mut();
        
        println!("Initial input: {:?}", input);

        for i in 0..10 {
            let new_size = fuzz(
                state,
                input.as_mut_ptr(),
                input.len(),
                &mut out_buf,
                ptr::null_mut(),
                0,
                100
            );
            
            let mutated = std::slice::from_raw_parts(out_buf, new_size);
            println!("Mutation {}: {:?}", i, mutated);
        }

        deinit(state);
    }
    Ok(())
}
