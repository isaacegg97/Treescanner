use common::{HintKind, StructuralMap};
use rand::{Rng, thread_rng};
use std::fs;
use std::os::raw::c_void;
use std::slice;

pub struct MutatorState {
    map: StructuralMap,
    buf: Vec<u8>,
}

#[no_mangle]
pub unsafe extern "C" fn afl_custom_init(_afl: *mut c_void, _seed: u32) -> *mut MutatorState {
    let hints_path = match std::env::var("TREESCANNER_HINTS") {
        Ok(path) => path,
        Err(_) => "hints.json".to_string(),
    };
    let map = if let Ok(content) = fs::read_to_string(&hints_path) {
        match serde_json::from_str(&content) {
            Ok(parsed) => parsed,
            Err(_) => StructuralMap { hints: Vec::new() },
        }
    } else {
        StructuralMap { hints: Vec::new() }
    };

    println!("TreeScanner: Loaded {} hints from {}", map.hints.len(), hints_path);

    Box::into_raw(Box::new(MutatorState {
        map,
        buf: Vec::with_capacity(4096),
    }))
}

#[no_mangle]
pub unsafe extern "C" fn afl_custom_fuzz(
    data: *mut MutatorState,
    buf: *mut u8,
    buf_size: usize,
    out_buf: *mut *mut u8,
    _add_buf: *mut u8,
    _add_buf_size: usize,
    max_size: usize,
) -> usize {
    let state = &mut *data;
    let input = slice::from_raw_parts(buf, buf_size);
    
    state.buf.clear();
    state.buf.extend_from_slice(input);

    let mut rng = thread_rng();

    if !state.map.hints.is_empty() {
        if let Some(hint) = state.map.hints.get(rng.gen_range(0..state.map.hints.len())) {
            if let Some(offset) = hint.offset {
                if offset < state.buf.len() {
                    match hint.kind {
                        HintKind::LengthField => {
                            let mut_type = rng.gen_range(0..4);
                            match mut_type {
                                0 => state.buf[offset] = 0,
                                1 => state.buf[offset] = 0xFF,
                                2 => state.buf[offset] = state.buf[offset].wrapping_add(1),
                                3 => state.buf[offset] = state.buf[offset].wrapping_sub(1),
                                _ => {}
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    if state.buf.len() > max_size {
        state.buf.truncate(max_size);
    }

    *out_buf = state.buf.as_mut_ptr();
    state.buf.len()
}

#[no_mangle]
pub unsafe extern "C" fn afl_custom_deinit(data: *mut MutatorState) {
    if !data.is_null() {
        drop(Box::from_raw(data));
    }
}
