#[macro_use]
extern crate gmod;

use std::{fs, io, ptr, slice};

use gmod::lua::State;

#[derive(Clone, Debug)]
struct Map {
    start: usize,
    end: usize,
    perms: String,
    path: Option<String>,
}

fn parse_maps() -> io::Result<Vec<Map>> {
    let text = fs::read_to_string("/proc/self/maps")?;
    let mut out = Vec::new();

    for line in text.lines() {
        let mut p = line.split_whitespace();

        let Some(range) = p.next() else { continue };
        let Some(perms) = p.next() else { continue };

        let _offset = p.next();
        let _dev = p.next();
        let _inode = p.next();

        let path = p.next().map(|s| s.to_string());

        let Some((a, b)) = range.split_once('-') else { continue };
        let Ok(start) = usize::from_str_radix(a, 16) else { continue };
        let Ok(end) = usize::from_str_radix(b, 16) else { continue };

        out.push(Map {
            start,
            end,
            perms: perms.to_string(),
            path,
        });
    }

    Ok(out)
}

fn is_exec(perms: &str) -> bool {
    perms.as_bytes().get(2) == Some(&b'x')
}

fn is_candidate(path: &str) -> bool {
    let file = std::path::Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(path);

    if file.contains("passlogpatch") {
        return false;
    }

    #[cfg(target_pointer_width = "64")]
    {
        file == "engine.so"
    }

    #[cfg(target_pointer_width = "32")]
    {
        file == "engine_srv.so"
    }
}

fn prot_from_perms(perms: &str) -> i32 {
    let b = perms.as_bytes();
    let mut prot = 0;

    if b.get(0) == Some(&b'r') {
        prot |= libc::PROT_READ;
    }
    if b.get(1) == Some(&b'w') {
        prot |= libc::PROT_WRITE;
    }
    if b.get(2) == Some(&b'x') {
        prot |= libc::PROT_EXEC;
    }

    prot
}

fn page_size() -> usize {
    unsafe {
        let n = libc::sysconf(libc::_SC_PAGESIZE);
        if n <= 0 {
            4096
        } else {
            n as usize
        }
    }
}

unsafe fn mprotect_range(addr: usize, len: usize, prot: i32) -> io::Result<()> {
    let page = page_size();
    let start = addr & !(page - 1);
    let end = (addr + len + page - 1) & !(page - 1);
    let size = end - start;

    let rc = libc::mprotect(start as *mut libc::c_void, size, prot);
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

unsafe fn write_nop5(addr: usize, old_perms: &str) -> io::Result<()> {
    let old_prot = prot_from_perms(old_perms);
    let new_prot = old_prot | libc::PROT_WRITE;

    mprotect_range(addr, 5, new_prot)?;

    for i in 0..5 {
        ptr::write_volatile((addr + i) as *mut u8, 0x90);
    }

    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);

    mprotect_range(addr, 5, old_prot)?;

    Ok(())
}

fn match_pat(buf: &[u8], off: usize, pat: &[Option<u8>]) -> bool {
    if off + pat.len() > buf.len() {
        return false;
    }

    for (i, x) in pat.iter().enumerate() {
        if let Some(byte) = x {
            if buf[off + i] != *byte {
                return false;
            }
        }
    }

    true
}

#[cfg(target_pointer_width = "64")]
const PATTERN: &[Option<u8>] = &[
    Some(0x31), Some(0xF6),                         // xor esi, esi
    Some(0x4C), Some(0x89), Some(0xE7),             // mov rdi, r12
    Some(0xE8), None, None, None, None,             // call netadr_s::ToString
    Some(0x48), Some(0x8D), Some(0x3D), None, None, None, None, // lea rdi, fmt
    Some(0x48), Some(0x89), Some(0xC6),             // mov rsi, rax
    Some(0x31), Some(0xC0),                         // xor eax, eax
    Some(0xE8), None, None, None, None,             // call ConMsg
    Some(0x48), Some(0x8B), Some(0x03),             // mov rax, [rbx]
    Some(0x4C), Some(0x89), Some(0xF9),             // mov rcx, r15
    Some(0x44), Some(0x89), Some(0xF2),             // mov edx, r14d
    Some(0x4C), Some(0x89), Some(0xE6),             // mov rsi, r12
    Some(0x48), Some(0x89), Some(0xDF),             // mov rdi, rbx
    Some(0xFF), Some(0x90), Some(0x80), Some(0x01), Some(0x00), Some(0x00), // call [rax+180h]
];

#[cfg(target_pointer_width = "64")]
const CALL_OFFSET: usize = 22;

#[cfg(target_pointer_width = "32")]
const PATTERN: &[Option<u8>] = &[
    Some(0xC7), Some(0x44), Some(0x24), Some(0x04), Some(0x00), Some(0x00), Some(0x00), Some(0x00),
    // mov dword ptr [esp+4], 0

    Some(0x8D), Some(0xB5), None, None, None, None,
    // lea esi, [ebp+var_xxx]

    Some(0x89), Some(0x3C), Some(0x24),
    // mov [esp], edi

    Some(0xE8), None, None, None, None,
    // call netadr_s::ToString

    Some(0xC7), Some(0x04), Some(0x24), None, None, None, None,
    // mov dword ptr [esp], offset "%s: password failed"

    Some(0x89), Some(0x44), Some(0x24), Some(0x04),
    // mov [esp+4], eax

    Some(0xE8), None, None, None, None,
    // call ConMsg

    Some(0x8B), Some(0x03),
    // mov eax, [ebx]

    Some(0x89), Some(0x74), Some(0x24), Some(0x0C),
    // mov [esp+0Ch], esi
];

#[cfg(target_pointer_width = "32")]
const CALL_OFFSET: usize = 33;

unsafe fn patch_once() -> Result<String, String> {
    let maps = parse_maps().map_err(|e| e.to_string())?;
    let mut patched = 0usize;
    let mut scanned = 0usize;

    for m in maps {
        if !is_exec(&m.perms) {
            continue;
        }

        let Some(path) = m.path.as_deref() else {
            continue;
        };

        if !is_candidate(path) {
            continue;
        }

        scanned += 1;

        let len = m.end.saturating_sub(m.start);
        if len < PATTERN.len() {
            continue;
        }

        let bytes = slice::from_raw_parts(m.start as *const u8, len);

        for off in 0..=(bytes.len() - PATTERN.len()) {
            if !match_pat(bytes, off, PATTERN) {
                continue;
            }

            let call_addr = m.start + off + CALL_OFFSET;

            if ptr::read_volatile(call_addr as *const u8) != 0xE8 {
                continue;
            }

            write_nop5(call_addr, &m.perms)
                .map_err(|e| format!("patch failed at 0x{call_addr:x}: {e}"))?;

            patched += 1;
        }
    }

    if patched == 0 {
        Err(format!("pattern not found, scanned_exec_mappings={scanned}"))
    } else {
        Ok(format!("patched={patched}, scanned_exec_mappings={scanned}"))
    }
}

#[lua_function]
unsafe fn patch(lua: State) -> i32 {
    match patch_once() {
        Ok(msg) => {
            lua.push_boolean(true);
            lua.push_string(&msg);
            2
        }
        Err(err) => {
            lua.push_boolean(false);
            lua.push_string(&err);
            2
        }
    }
}

#[gmod13_open]
unsafe fn gmod13_open(lua: State) -> i32 {
    let result = patch_once();

    match &result {
        Ok(msg) => println!("[passlogpatch] {msg}"),
        Err(err) => println!("[passlogpatch] failed: {err}"),
    }

    lua_stack_guard!(lua => {
        lua.new_table();

        lua.push_string(env!("CARGO_PKG_VERSION"));
        lua.set_field(-2, lua_string!("VERSION"));

        lua.push_function(patch);
        lua.set_field(-2, lua_string!("patch"));

        match result {
            Ok(msg) => {
                lua.push_boolean(true);
                lua.set_field(-2, lua_string!("loaded"));

                lua.push_string(&msg);
                lua.set_field(-2, lua_string!("message"));
            }
            Err(err) => {
                lua.push_boolean(false);
                lua.set_field(-2, lua_string!("loaded"));

                lua.push_string(&err);
                lua.set_field(-2, lua_string!("message"));
            }
        }

        lua.set_global(lua_string!("passlogpatch"));
    });

    0
}