use core::{
    convert::Infallible,
    future::Future,
    mem,
    ops::Range,
    pin::Pin,
    ptr, result, str,
    task::{Context, Poll},
};
use std::{
    fs::{self, File},
    io::{self, BufWriter, Error, Read, Write},
    os::{
        fd::{FromRawFd, OwnedFd},
        unix::{ffi::OsStrExt, fs::FileExt},
    },
    sync::Arc,
};

use argh::FromArgs;
use iced_x86::{Decoder, DecoderOptions, FastFormatter, OpKind, Register as IcedRegister};
use libc::{MAP_FAILED, MAP_SHARED, PROT_READ, PROT_WRITE};
use tokio::io::unix::AsyncFd;

mod bindings;
mod error;

type Result<T, E = error::Error> = result::Result<T, E>;

#[derive(FromArgs)]
#[argh(description = "Find out what (accesses,writes) this address.")]
struct Args {
    #[argh(option, short = 'p', description = "pid")]
    pid: i32,
    #[argh(
        option,
        from_str_fn(validate_bp_addr),
        long = "addr",
        description = "addr: hex format"
    )]
    bp_addr: u64,
    #[argh(
        option,
        from_str_fn(validate_bp_type),
        long = "type",
        description = "type: (access,write)"
    )]
    bp_type: u32,
    #[argh(
        option,
        from_str_fn(validate_bp_len),
        long = "length",
        description = "length: (1,2,4,8)"
    )]
    bp_len: u32,
}

fn validate_bp_addr(value: &str) -> Result<u64, String> {
    u64::from_str_radix(value.trim_start_matches("0x"), 16).map_err(|e| e.to_string())
}

fn validate_bp_type(value: &str) -> Result<u32, String> {
    let bp_type = match value {
        "access" | "3" => bindings::HW_BREAKPOINT_RW,
        "write" | "2" => bindings::HW_BREAKPOINT_W,
        _ => return Err("watchpoint mode must be one of (access,write)".into()),
    };
    Ok(bp_type)
}

fn validate_bp_len(value: &str) -> Result<u32, String> {
    let bp_len = match value {
        "1" => bindings::HW_BREAKPOINT_LEN_1,
        "2" => bindings::HW_BREAKPOINT_LEN_2,
        "4" => bindings::HW_BREAKPOINT_LEN_4,
        "8" => bindings::HW_BREAKPOINT_LEN_8,
        _ => return Err("watchpoint length must be one of (1,2,4,8)".into()),
    };
    Ok(bp_len)
}

struct ParseMaps<'a>(str::Lines<'a>);

impl<'a> ParseMaps<'a> {
    fn new(contents: &'a str) -> Self {
        Self(contents.lines())
    }
}

impl Iterator for ParseMaps<'_> {
    type Item = Range<u64>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let line = self.0.next()?;
        let mut split = line.splitn(6, ' ');
        let mut range_split = split.next()?.split('-');
        let start = u64::from_str_radix(range_split.next()?, 16).ok()?;
        let end = u64::from_str_radix(range_split.next()?, 16).ok()?;
        Some(Range { start, end })
    }
}

#[must_use = "futures do nothing unless you `.await` or poll them"]
struct SelectAll<Fut> {
    inner: Vec<Fut>,
}

impl<Fut: Unpin> Unpin for SelectAll<Fut> {}

fn select_all<I>(iter: I) -> SelectAll<I::Item>
where
    I: IntoIterator,
    I::Item: Future + Unpin,
{
    let ret = SelectAll {
        inner: iter.into_iter().collect(),
    };
    assert!(!ret.inner.is_empty());
    assert_future::<(<I::Item as Future>::Output, usize, Vec<I::Item>), _>(ret)
}

impl<Fut: Future + Unpin> Future for SelectAll<Fut> {
    type Output = (Fut::Output, usize, Vec<Fut>);

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let item =
            self.inner
                .iter_mut()
                .enumerate()
                .find_map(|(i, f)| match Pin::new(f).poll(cx) {
                    Poll::Pending => None,
                    Poll::Ready(e) => Some((i, e)),
                });
        match item {
            Some((idx, res)) => {
                #[allow(clippy::let_underscore_future)]
                let _ = self.inner.swap_remove(idx);
                let rest = mem::take(&mut self.inner);
                Poll::Ready((res, idx, rest))
            }
            None => Poll::Pending,
        }
    }
}

fn assert_future<T, F>(future: F) -> F
where
    F: Future<Output = T>,
{
    future
}

#[allow(non_snake_case)]
mod Register {
    pub const NAMES: [&str; regs_count()] = [
        "AX", "BX", "CX", "DX", "SI", "DI", "BP", "SP", "IP", "R8", "R9", "R10", "R11", "R12",
        "R13", "R14", "R15",
    ];

    pub const IP: usize = 8;

    pub(super) const SAMPLE_REGS_USER: u64 = 0b1111_1111_0000_0001_1111_1111;

    #[inline]
    pub(super) const fn regs_count() -> usize {
        SAMPLE_REGS_USER.count_ones() as usize
    }
}

#[inline]
const fn iced_register_to_perf_id(reg: IcedRegister) -> Option<usize> {
    let id = match reg {
        // General Register
        IcedRegister::RAX | IcedRegister::EAX | IcedRegister::AX | IcedRegister::AH => 0,
        IcedRegister::RBX | IcedRegister::EBX | IcedRegister::BX | IcedRegister::BH => 1,
        IcedRegister::RCX | IcedRegister::ECX | IcedRegister::CX | IcedRegister::CH => 2,
        IcedRegister::RDX | IcedRegister::EDX | IcedRegister::DX | IcedRegister::DH => 3,
        IcedRegister::RSI | IcedRegister::ESI | IcedRegister::SI => 4,
        IcedRegister::RDI | IcedRegister::EDI | IcedRegister::DI => 5,
        IcedRegister::RBP | IcedRegister::EBP | IcedRegister::BP => 6,
        IcedRegister::RSP | IcedRegister::ESP | IcedRegister::SP => 7,
        IcedRegister::R8 | IcedRegister::R8D | IcedRegister::R8W => 9,
        IcedRegister::R9 | IcedRegister::R9D | IcedRegister::R9W => 10,
        IcedRegister::R10 | IcedRegister::R10D | IcedRegister::R10W => 11,
        IcedRegister::R11 | IcedRegister::R11D | IcedRegister::R11W => 12,
        IcedRegister::R12 | IcedRegister::R12D | IcedRegister::R12W => 13,
        IcedRegister::R13 | IcedRegister::R13D | IcedRegister::R13W => 14,
        IcedRegister::R14 | IcedRegister::R14D | IcedRegister::R14W => 15,
        IcedRegister::R15 | IcedRegister::R15D | IcedRegister::R15W => 16,
        // Special Registers
        IcedRegister::RIP | IcedRegister::EIP => 8,
        // Disasm has no FLAGS
        // Segment Registers
        // Disasm OpKind::Memory has no CS, SS, DS, ES, FS, GS
        // TODO Other Registers ?
        _ => return None,
    };
    Some(id)
}

struct PerfMap {
    mmap_addr: u64,
    fd: AsyncFd<OwnedFd>,
}

struct SampleData {
    pid: u32,
    tid: u32,
    regs: [u64; Register::regs_count()],
}

impl PerfMap {
    fn new(pid: i32, bp_addr: u64, bp_type: u32, bp_len: u32) -> Result<Self, Error> {
        let mut attrs = bindings::perf_event_attr::new();

        attrs.set_precise_ip(2);
        attrs.size = size_of::<bindings::perf_event_attr>() as u32;
        attrs.type_ = bindings::PERF_TYPE_BREAKPOINT;
        attrs.__bindgen_anon_1.sample_period = 1;
        attrs.__bindgen_anon_2.wakeup_events = 1;
        attrs.bp_type = bp_type;
        attrs.__bindgen_anon_3.bp_addr = bp_addr;
        attrs.__bindgen_anon_4.bp_len = bp_len as u64;
        attrs.sample_type = bindings::PERF_SAMPLE_REGS_USER | bindings::PERF_SAMPLE_TID;
        attrs.sample_regs_user = Register::SAMPLE_REGS_USER;

        let raw_fd = unsafe {
            bindings::perf_event_open(
                &mut attrs,
                pid,
                -1,
                -1,
                (bindings::PERF_FLAG_FD_CLOEXEC) as u64,
            )
        };
        if raw_fd < 0 {
            return Err(Error::last_os_error());
        }

        let ret = unsafe {
            libc::mmap(
                ptr::null_mut(),
                0x2000,
                PROT_READ | PROT_WRITE,
                MAP_SHARED,
                raw_fd,
                0,
            )
        };
        if ret == MAP_FAILED {
            return Err(Error::last_os_error());
        }

        Ok(Self {
            mmap_addr: ret as u64,
            fd: AsyncFd::new(unsafe { OwnedFd::from_raw_fd(raw_fd) })?,
        })
    }

    async fn try_events<F>(&self, f: F) -> Result<Infallible, Error>
    where
        F: Fn(SampleData) -> Result<(), Error>,
    {
        let mmap_page_metadata =
            unsafe { &mut *(self.mmap_addr as *mut bindings::perf_event_mmap_page) };
        let data_addr = self.mmap_addr + mmap_page_metadata.data_offset;
        let data_size = mmap_page_metadata.data_size;
        let mut read_data_size = 0u64;
        loop {
            let mut guard = self.fd.readable().await?;
            while mmap_page_metadata.data_head != read_data_size {
                let get_addr = |offset| data_addr + ((read_data_size + offset) % data_size);
                let data_header = unsafe { &*(get_addr(0) as *const bindings::perf_event_header) };
                let mut offset = size_of::<bindings::perf_event_header>() as u64;
                if data_header.type_ == bindings::PERF_RECORD_SAMPLE {
                    let pid = unsafe { *(get_addr(offset) as *const u32) };
                    offset += 4;
                    let tid = unsafe { *(get_addr(offset) as *const u32) };
                    offset += 12;
                    let mut regs = [0u64; Register::regs_count()];
                    regs.iter_mut().for_each(|reg| {
                        *reg = unsafe { *(get_addr(offset) as *const u64) };
                        offset += 8;
                    });
                    f(SampleData { pid, tid, regs })?;
                }
                read_data_size += data_header.size as u64;
                mmap_page_metadata.data_tail = read_data_size;
            }
            guard.clear_ready();
        }
    }
}

struct Process {
    mem: File,
    range: Vec<Range<u64>>,
    bitness: u32,
}

impl Process {
    fn open(pid: i32) -> Result<Self> {
        let bitness = get_bitness(pid)?;
        let mem = File::open(format!("/proc/{pid}/mem"))?;
        let contents = fs::read_to_string(format!("/proc/{pid}/maps"))?;
        let range = ParseMaps::new(&contents).collect::<Vec<_>>();
        Ok(Self {
            mem,
            range,
            bitness,
        })
    }
}

fn get_bitness(pid: i32) -> Result<u32> {
    let mut buf = [0; 16];
    fs::read_link(format!("/proc/{pid}/exe"))
        .and_then(File::open)
        .and_then(|mut f| f.read_exact(&mut buf))?;
    match buf[4] {
        1 => Ok(32),
        2 => Ok(64),
        _ => Err("Unknown ELF file format".into()),
    }
}

fn get_perf_maps(pid: i32, bp_addr: u64, bp_type: u32, bp_len: u32) -> Result<Vec<PerfMap>> {
    fs::read_dir(format!("/proc/{pid}/task"))?
        .map(|dir| {
            let id = str::from_utf8(dir?.file_name().as_bytes())?.parse()?;
            let map = PerfMap::new(id, bp_addr, bp_type, bp_len)?;
            Ok(map)
        })
        .collect()
}

fn main() {
    let args: Args = argh::from_env();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .unwrap();
    if let Err(err) = rt.block_on(async_main(args)) {
        eprintln!("Error: {err}")
    }
}

async fn async_main(args: Args) -> Result<()> {
    let Args {
        pid,
        bp_addr,
        bp_type,
        bp_len,
    } = args;

    let proc = Process::open(pid).map(Arc::new)?;
    let maps = get_perf_maps(pid, bp_addr, bp_type, bp_len)?;

    select_all(maps.into_iter().map(|perf| {
        let proc = proc.clone();
        tokio::spawn(async move {
            let f = |data| handle_event(data, &proc);
            perf.try_events(f).await
        })
    }))
    .await
    .0??;

    Ok(())
}

fn handle_event(data: SampleData, proc: &Process) -> Result<(), Error> {
    let SampleData { pid, tid, regs } = data;
    let &Process {
        ref mem,
        ref range,
        bitness,
    } = proc;

    let ip = regs[Register::IP];

    let addr = range
        .iter()
        .find(|x| x.contains(&ip))
        .map(|r| r.start.max(ip.saturating_sub(512)))
        .ok_or_else(|| Error::other("Unknown memory range"))?;

    let mut bytes = [0_u8; 1024];

    let size = mem.read_at(&mut bytes, addr)?;
    let mut decoder = Decoder::new(bitness, &bytes[..size], DecoderOptions::NONE);
    decoder.set_ip(addr);

    let instructions = decoder.into_iter().collect::<Vec<_>>();

    if let Some(k1) = instructions.iter().position(|v| v.next_ip() == ip) {
        let mut output = String::with_capacity(0x2000);
        let mut formatter = FastFormatter::new();
        let mut stdout = BufWriter::new(io::stdout());

        writeln!(stdout, "[Pid: {pid}   Tid: {tid}]")?;

        let range = k1.saturating_sub(5)..(k1 + 5).min(instructions.len());
        for k2 in range {
            let v = &instructions[k2];
            write!(
                stdout,
                "{} {:016X} ",
                if k1 == k2 { "->" } else { "  " },
                v.ip()
            )?;

            let idx = (v.ip() - addr) as usize;
            let instr_bytes = &bytes[idx..idx + v.len()];
            for b in instr_bytes.iter() {
                write!(stdout, "{b:02X}")?;
            }

            for _ in instr_bytes.len()..10 {
                write!(stdout, "  ")?;
            }

            output.clear();
            formatter.format(v, &mut output);
            writeln!(stdout, " {output}")?;
        }

        writeln!(stdout)?;

        let instr = instructions[k1];
        let count = instr.op_count();
        for count in 0..count {
            if instr.op_kind(count) == OpKind::Memory {
                let reg = instr.memory_base();
                match iced_register_to_perf_id(reg).and_then(|id| regs.get(id)) {
                    Some(addr) => {
                        writeln!(
                            stdout,
                            "The value of the pointer needed to find this address is probably: \
                             {addr:X}",
                        )?;
                    }
                    None => {
                        writeln!(stdout, "Unable to guess address")?;
                    }
                }
            }
        }

        writeln!(stdout)?;

        for (k, v) in regs.iter().enumerate() {
            let name = Register::NAMES[k];
            write!(stdout, "{name:>5}: {v:016X} ")?;
            if (k + 1) % 4 == 0 {
                writeln!(stdout)?;
            }
        }

        writeln!(stdout)?;

        stdout.flush()?;
    }

    Ok(())
}
