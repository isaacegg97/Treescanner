use common::{HintKind, Severity, StructuralMap};
use rand::{Rng, thread_rng};
use std::collections::HashMap;
use std::fs;
use std::os::raw::c_void;
use std::slice;

pub struct MutatorState {
    map: StructuralMap,
    buf: Vec<u8>,
    severity_weights: HashMap<String, f32>,
}

fn weight_for(sev: &Severity) -> f32 {
    match sev {
        Severity::Low => 1.0,
        Severity::Medium => 2.0,
        Severity::High => 3.0,
        Severity::Critical => 4.0,
    }
}

fn apply_length_mutations(buf: &mut [u8], offset: usize) {
    let mut rng = thread_rng();
    match rng.gen_range(0..6) {0 => buf[offset]=0,1 => buf[offset]=0xFF,2=>buf[offset]=buf[offset].wrapping_add(1),3=>buf[offset]=buf[offset].wrapping_sub(1),4=>buf[offset]=(buf.len() as u8).wrapping_add(10),_=>buf[offset]=128}
}
fn apply_boundary_bypass_mutations(buf: &mut [u8], offset: usize) { let mut rng=thread_rng(); match rng.gen_range(0..4){0=>buf[offset]=buf[offset].wrapping_add(1),1=>buf[offset]=255,2=>buf[offset]=0x80,_=>buf[offset]=buf[offset].wrapping_sub(1)} }
fn apply_index_overflow_mutations(buf: &mut [u8], offset: usize) { let mut rng=thread_rng(); match rng.gen_range(0..3){0=>buf[offset]=255,1=>buf[offset]=128,_=>buf[offset]=buf.len() as u8} }
fn apply_vulnerability_fuzz(buf: &mut [u8], offset: usize) { buf[offset]=thread_rng().r#gen::<u8>(); }

#[no_mangle]
pub unsafe extern "C" fn afl_custom_init(_afl: *mut c_void, _seed: u32) -> *mut MutatorState {
    let hints_path = std::env::var("TREESCANNER_HINTS").unwrap_or_else(|_| "hints.json".to_string());
    let map = fs::read_to_string(&hints_path).ok().and_then(|c| serde_json::from_str(&c).ok()).unwrap_or(StructuralMap{hints:vec![]});
    let mut severity_weights = HashMap::new();
    for h in &map.hints { severity_weights.insert(h.label.clone(), weight_for(&h.severity)); }
    Box::into_raw(Box::new(MutatorState { map, buf: Vec::with_capacity(4096), severity_weights }))
}

#[no_mangle]
pub unsafe extern "C" fn afl_custom_fuzz(data: *mut MutatorState, buf: *mut u8, buf_size: usize, out_buf: *mut *mut u8, _add_buf: *mut u8, _add_buf_size: usize, max_size: usize) -> usize {
    let state = &mut *data;
    let input = slice::from_raw_parts(buf, buf_size);
    state.buf.clear();
    state.buf.extend_from_slice(input);
    if !state.map.hints.is_empty() {
        let total: f32 = state.map.hints.iter().map(|h| *state.severity_weights.get(&h.label).unwrap_or(&1.0)).sum();
        let mut pick = thread_rng().gen_range(0.0..total.max(1.0));
        for hint in &state.map.hints {
            pick -= *state.severity_weights.get(&hint.label).unwrap_or(&1.0);
            if pick <= 0.0 {
                if let Some(offset) = hint.offset.filter(|o| *o < state.buf.len()) {
                    match hint.kind {
                        HintKind::LengthField => apply_length_mutations(&mut state.buf, offset),
                        HintKind::BoundaryCheck => apply_boundary_bypass_mutations(&mut state.buf, offset),
                        HintKind::ArrayIndex => apply_index_overflow_mutations(&mut state.buf, offset),
                        HintKind::Vulnerability => apply_vulnerability_fuzz(&mut state.buf, offset),
                    }
                }
                break;
            }
        }
    }
    if state.buf.len() > max_size { state.buf.truncate(max_size); }
    *out_buf = state.buf.as_mut_ptr();
    state.buf.len()
}

#[no_mangle]
pub unsafe extern "C" fn afl_custom_deinit(data: *mut MutatorState) { if !data.is_null() { drop(Box::from_raw(data)); } }
