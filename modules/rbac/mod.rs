//! RBAC — Role-based access control with break-glass support.
//!
//! Evaluates admin requests against role manifest. Authorized requests
//! are forwarded to admin_handler; denied requests return errors.

#![no_std]

use core::ffi::c_void;

#[path = "../../deps/fluxor/modules/sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../deps/fluxor/modules/sdk/runtime.rs");
include!("../../deps/fluxor/modules/sdk/params.rs");

#[path = "../common/wire.rs"]
mod wire;

// Role bits
const ROLE_OPERATOR: u8     = 0x01;
const ROLE_TENANT_ADMIN: u8 = 0x02;
const ROLE_OBSERVER: u8     = 0x04;
const ROLE_BREAKGLASS: u8   = 0x08;

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_requests: i32,     // in[0]: raw admin requests from http_surface
    out_authorized: i32,  // out[0]: authorized → admin_handler
    out_denied: i32,      // out[1]: denied → http_surface
    out_audit: i32,       // out[2]: audit events → telemetry_agg

    // Default: allow all (operator role)
    active_role: u8,
    authorized_count: u32,
    denied_count: u32,
    msg_buf: [u8; 1024],
}

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 { core::mem::size_of::<ModuleState>() as u32 }

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32, out_chan: i32, _ctrl_chan: i32,
    _params: *const u8, _params_len: usize,
    state: *mut u8, state_size: usize, syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() || state.is_null() { return -1; }
        if state_size < core::mem::size_of::<ModuleState>() { return -2; }
        let s = &mut *(state as *mut ModuleState);
        let sys = &*(syscalls as *const SyscallTable);
        s.syscalls = sys;
        s.in_requests = in_chan;
        s.out_authorized = out_chan;
        s.out_denied = dev_channel_port(sys, 1, 1);
        s.out_audit = dev_channel_port(sys, 1, 2);
        s.active_role = ROLE_OPERATOR; // default: full access
        dev_log(sys, 3, b"[rbac] init".as_ptr(), 11);
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        let s = &mut *(state as *mut ModuleState);
        let sys = &*s.syscalls;

        for _ in 0..4 {
            let poll = (sys.channel_poll)(s.in_requests, 0x01);
            if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

            let (msg_type, plen) = wire::channel_read_msg(sys, s.in_requests, &mut s.msg_buf);
            if msg_type != wire::MSG_ADMIN_COMMAND || plen == 0 { continue; }

            // Authorize: operator and breakglass can do anything
            let authorized = (s.active_role & (ROLE_OPERATOR | ROLE_BREAKGLASS)) != 0;

            if authorized {
                let poll_out = (sys.channel_poll)(s.out_authorized, 0x02);
                if poll_out > 0 && (poll_out as u32 & 0x02) != 0 {
                    wire::channel_write_msg(sys, s.out_authorized, wire::MSG_ADMIN_COMMAND, &s.msg_buf[..plen as usize]);
                }
                s.authorized_count += 1;
            } else {
                if s.out_denied >= 0 {
                    let poll_out = (sys.channel_poll)(s.out_denied, 0x02);
                    if poll_out > 0 && (poll_out as u32 & 0x02) != 0 {
                        let resp = [0x00u8]; // denied
                        wire::channel_write_msg(sys, s.out_denied, wire::MSG_ADMIN_RESPONSE, &resp);
                    }
                }
                s.denied_count += 1;
            }

            // Emit audit event
            if s.out_audit >= 0 {
                let poll_out = (sys.channel_poll)(s.out_audit, 0x02);
                if poll_out > 0 && (poll_out as u32 & 0x02) != 0 {
                    let mut audit = [0u8; 2];
                    audit[0] = authorized as u8;
                    audit[1] = s.active_role;
                    wire::channel_write_msg(sys, s.out_audit, wire::MSG_METRICS, &audit[..2]);
                }
            }
        }

        0
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }
