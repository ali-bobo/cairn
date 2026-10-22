//! TCP/UDP table enumeration with owning PID (raw WinAPI -> plain rows), IPv4 and IPv6.
//!
//! Four tables are read independently (tcp4, tcp6, udp4, udp6). A failure on one table is
//! recorded in [`NetTables::errors`] and the others are still returned (graceful degrade,
//! golden rule 8). The OS buffer is parsed by hand from its documented byte layout
//! ([`parse_tcp4`] and friends) rather than by casting it to the `windows` structs, so the
//! parsing is bounds-checked, alignment-free and unit-tested on every platform; only the
//! `GetExtended*Table` calls themselves are Windows-only.
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawTcpRow {
    pub laddr: String,
    pub lport: u16,
    pub raddr: String,
    pub rport: u16,
    pub state_raw: u32,
    pub pid: u32,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawUdpRow {
    pub laddr: String,
    pub lport: u16,
    pub pid: u32,
}

/// Everything the four socket tables yielded, plus one error string per table that could
/// not be read (e.g. `"tcp6: GetExtendedTcpTable rc=87"`). Rows from the tables that did
/// read are kept even when another table failed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetTables {
    pub tcp: Vec<RawTcpRow>,
    pub udp: Vec<RawUdpRow>,
    pub errors: Vec<String>,
}

impl NetTables {
    /// True when every table failed (nothing at all could be read).
    pub fn all_failed(&self) -> bool {
        self.errors.len() >= TABLE_COUNT && self.tcp.is_empty() && self.udp.is_empty()
    }
}

/// Number of tables [`read_tables`] reads: tcp4, tcp6, udp4, udp6.
pub const TABLE_COUNT: usize = 4;

/// Win32 ERROR_INSUFFICIENT_BUFFER (122): the table grew between the size probe and the read.
pub const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
/// How many times a read is retried after ERROR_INSUFFICIENT_BUFFER.
pub const MAX_BUFFER_RETRIES: usize = 3;

/// Size-probe-then-read loop shared by the four tables. `call(buf, size)` is one
/// `GetExtended*Table` call: `buf` None is the size probe; `size` is in/out (capacity in,
/// required bytes out). Retries up to [`MAX_BUFFER_RETRIES`] times when the table grows
/// between calls. Returns the filled buffer, or the failing return code. Pure: the FFI is
/// injected, so this is unit-tested off Windows.
pub fn read_with_retry(
    mut call: impl FnMut(Option<&mut [u8]>, &mut u32) -> u32,
) -> Result<Vec<u8>, u32> {
    let mut size = 0u32;
    let rc = call(None, &mut size);
    if rc == 0 {
        // Nothing to read (the API accepted a zero-size request): an empty table.
        return Ok(Vec::new());
    }
    if rc != ERROR_INSUFFICIENT_BUFFER {
        return Err(rc);
    }
    for _ in 0..=MAX_BUFFER_RETRIES {
        // Small headroom so a table that grows by a row or two between calls still fits.
        let cap = (size as usize).saturating_add(size as usize / 8).max(4);
        let mut buf = vec![0u8; cap];
        let mut in_out = cap.min(u32::MAX as usize) as u32;
        match call(Some(&mut buf), &mut in_out) {
            0 => return Ok(buf),
            ERROR_INSUFFICIENT_BUFFER => size = in_out.max(size.saturating_add(1)),
            other => return Err(other),
        }
    }
    Err(ERROR_INSUFFICIENT_BUFFER)
}

// Row sizes of the documented MIB_*ROW_OWNER_PID layouts (all fields are 4-byte aligned
// DWORDs or byte arrays, so there is no padding). Checked against the `windows` structs at
// compile time in the Windows module below.
const TCP4_ROW: usize = 24; // state, laddr, lport, raddr, rport, pid
const TCP6_ROW: usize = 56; // laddr[16], lscope, lport, raddr[16], rscope, rport, state, pid
const UDP4_ROW: usize = 12; // laddr, lport, pid
const UDP6_ROW: usize = 28; // laddr[16], lscope, lport, pid

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}
/// A MIB IPv4 address DWORD is stored in network byte order, i.e. its bytes in memory are
/// the dotted-quad octets in order.
fn ipv4_at(b: &[u8], off: usize) -> String {
    Ipv4Addr::new(b[off], b[off + 1], b[off + 2], b[off + 3]).to_string()
}
fn ipv6_at(b: &[u8], off: usize) -> String {
    let mut a = [0u8; 16];
    a.copy_from_slice(&b[off..off + 16]);
    Ipv6Addr::from(a).to_string()
}
/// A MIB port DWORD holds the port in network byte order in its low 16 bits, i.e. the
/// first two bytes in memory, big-endian.
fn port_at(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([b[off], b[off + 1]])
}

/// Split a `{ dwNumEntries; ROW table[] }` buffer into its rows. A count that claims more
/// rows than the buffer holds is clamped to the rows that fit (never reads out of bounds).
fn rows(buf: &[u8], row: usize) -> impl Iterator<Item = &[u8]> {
    let n = if buf.len() >= 4 {
        u32_at(buf, 0) as usize
    } else {
        0
    };
    let fit = buf.len().saturating_sub(4) / row;
    buf.get(4..)
        .unwrap_or(&[])
        .chunks_exact(row)
        .take(n.min(fit))
}

/// Parse a MIB_TCPTABLE_OWNER_PID buffer.
pub fn parse_tcp4(buf: &[u8]) -> Vec<RawTcpRow> {
    rows(buf, TCP4_ROW)
        .map(|r| RawTcpRow {
            state_raw: u32_at(r, 0),
            laddr: ipv4_at(r, 4),
            lport: port_at(r, 8),
            raddr: ipv4_at(r, 12),
            rport: port_at(r, 16),
            pid: u32_at(r, 20),
        })
        .collect()
}

/// Parse a MIB_TCP6TABLE_OWNER_PID buffer.
pub fn parse_tcp6(buf: &[u8]) -> Vec<RawTcpRow> {
    rows(buf, TCP6_ROW)
        .map(|r| RawTcpRow {
            laddr: ipv6_at(r, 0),
            lport: port_at(r, 20),
            raddr: ipv6_at(r, 24),
            rport: port_at(r, 44),
            state_raw: u32_at(r, 48),
            pid: u32_at(r, 52),
        })
        .collect()
}

/// Parse a MIB_UDPTABLE_OWNER_PID buffer.
pub fn parse_udp4(buf: &[u8]) -> Vec<RawUdpRow> {
    rows(buf, UDP4_ROW)
        .map(|r| RawUdpRow {
            laddr: ipv4_at(r, 0),
            lport: port_at(r, 4),
            pid: u32_at(r, 8),
        })
        .collect()
}

/// Parse a MIB_UDP6TABLE_OWNER_PID buffer.
pub fn parse_udp6(buf: &[u8]) -> Vec<RawUdpRow> {
    rows(buf, UDP6_ROW)
        .map(|r| RawUdpRow {
            laddr: ipv6_at(r, 0),
            lport: port_at(r, 20),
            pid: u32_at(r, 24),
        })
        .collect()
}

/// Assemble [`NetTables`] from the four raw reads (pure; the reads are injected).
pub fn assemble(
    tcp4: Result<Vec<u8>, u32>,
    tcp6: Result<Vec<u8>, u32>,
    udp4: Result<Vec<u8>, u32>,
    udp6: Result<Vec<u8>, u32>,
) -> NetTables {
    let mut t = NetTables::default();
    match tcp4 {
        Ok(b) => t.tcp.extend(parse_tcp4(&b)),
        Err(rc) => t.errors.push(format!("tcp4: GetExtendedTcpTable rc={rc}")),
    }
    match tcp6 {
        Ok(b) => t.tcp.extend(parse_tcp6(&b)),
        Err(rc) => t.errors.push(format!("tcp6: GetExtendedTcpTable rc={rc}")),
    }
    match udp4 {
        Ok(b) => t.udp.extend(parse_udp4(&b)),
        Err(rc) => t.errors.push(format!("udp4: GetExtendedUdpTable rc={rc}")),
    }
    match udp6 {
        Ok(b) => t.udp.extend(parse_udp6(&b)),
        Err(rc) => t.errors.push(format!("udp6: GetExtendedUdpTable rc={rc}")),
    }
    t
}

/// Non-Windows: empty tables, no errors (the live socket path is Windows-only).
#[cfg(not(windows))]
pub fn read_tables() -> NetTables {
    NetTables::default()
}

/// Windows: read tcp4/tcp6/udp4/udp6 owner-PID tables. Never panics, never errors as a
/// whole: per-table failures land in `errors`.
#[cfg(windows)]
pub fn read_tables() -> NetTables {
    win::read_tables()
}

#[cfg(windows)]
mod win {
    use super::{assemble, read_with_retry, NetTables};
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID,
        MIB_UDP6ROW_OWNER_PID, MIB_UDPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
    };
    use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

    // The hand parser's row sizes must match the real structs (compile-time guard).
    const _: () = assert!(std::mem::size_of::<MIB_TCPROW_OWNER_PID>() == super::TCP4_ROW);
    const _: () = assert!(std::mem::size_of::<MIB_TCP6ROW_OWNER_PID>() == super::TCP6_ROW);
    const _: () = assert!(std::mem::size_of::<MIB_UDPROW_OWNER_PID>() == super::UDP4_ROW);
    const _: () = assert!(std::mem::size_of::<MIB_UDP6ROW_OWNER_PID>() == super::UDP6_ROW);

    fn tcp(af: u32) -> Result<Vec<u8>, u32> {
        read_with_retry(|buf, size| {
            let ptr = buf.map(|b| b.as_mut_ptr() as *mut core::ffi::c_void);
            // SAFETY: `ptr` is None (size probe) or points at a live buffer of at least
            // `*size` bytes (read_with_retry passes the buffer's own length as `*size`);
            // `size` is a valid in/out u32. The API writes at most `*size` bytes.
            unsafe { GetExtendedTcpTable(ptr, size, false, af, TCP_TABLE_OWNER_PID_ALL, 0) }
        })
    }

    fn udp(af: u32) -> Result<Vec<u8>, u32> {
        read_with_retry(|buf, size| {
            let ptr = buf.map(|b| b.as_mut_ptr() as *mut core::ffi::c_void);
            // SAFETY: as in `tcp` above: None probe or a live buffer of >= `*size` bytes.
            unsafe { GetExtendedUdpTable(ptr, size, false, af, UDP_TABLE_OWNER_PID, 0) }
        })
    }

    pub fn read_tables() -> NetTables {
        let v4 = AF_INET.0 as u32;
        let v6 = AF_INET6.0 as u32;
        assemble(tcp(v4), tcp(v6), udp(v4), udp(v6))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn le(v: u32) -> [u8; 4] {
        v.to_le_bytes()
    }
    /// A port DWORD as the OS lays it out: network-order u16 in the first two bytes.
    fn port(p: u16) -> [u8; 4] {
        let b = p.to_be_bytes();
        [b[0], b[1], 0, 0]
    }

    #[test]
    fn parses_tcp4_row() {
        let mut b = Vec::new();
        b.extend(le(1));
        b.extend(le(5)); // established
        b.extend([127, 0, 0, 1]);
        b.extend(port(445));
        b.extend([10, 0, 0, 5]);
        b.extend(port(50000));
        b.extend(le(4));
        let rows = parse_tcp4(&b);
        assert_eq!(
            rows,
            vec![RawTcpRow {
                laddr: "127.0.0.1".into(),
                lport: 445,
                raddr: "10.0.0.5".into(),
                rport: 50000,
                state_raw: 5,
                pid: 4,
            }]
        );
    }

    #[test]
    fn parses_tcp6_row() {
        let mut b = Vec::new();
        b.extend(le(1));
        let mut l = [0u8; 16];
        l[15] = 1; // ::1
        b.extend(l);
        b.extend(le(0)); // scope
        b.extend(port(443));
        let r: [u8; 16] = "2001:db8::5".parse::<Ipv6Addr>().unwrap().octets();
        b.extend(r);
        b.extend(le(0));
        b.extend(port(51000));
        b.extend(le(2)); // listen
        b.extend(le(1234));
        assert_eq!(b.len(), 4 + TCP6_ROW);
        let rows = parse_tcp6(&b);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].laddr, "::1");
        assert_eq!(rows[0].lport, 443);
        assert_eq!(rows[0].raddr, "2001:db8::5");
        assert_eq!(rows[0].rport, 51000);
        assert_eq!(rows[0].state_raw, 2);
        assert_eq!(rows[0].pid, 1234);
    }

    #[test]
    fn parses_udp4_and_udp6_rows() {
        let mut b = Vec::new();
        b.extend(le(2));
        for (ip, p, pid) in [([0, 0, 0, 0], 137u16, 900u32), ([192, 168, 1, 2], 53, 901)] {
            b.extend(ip);
            b.extend(port(p));
            b.extend(le(pid));
        }
        let rows = parse_udp4(&b);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].laddr, "192.168.1.2");
        assert_eq!(rows[1].lport, 53);
        assert_eq!(rows[1].pid, 901);

        let mut b6 = Vec::new();
        b6.extend(le(1));
        b6.extend([0u8; 16]); // ::
        b6.extend(le(0));
        b6.extend(port(5353));
        b6.extend(le(77));
        let rows6 = parse_udp6(&b6);
        assert_eq!(rows6.len(), 1);
        assert_eq!(rows6[0].laddr, "::");
        assert_eq!(rows6[0].lport, 5353);
        assert_eq!(rows6[0].pid, 77);
    }

    /// A count larger than the buffer holds is clamped; short/empty buffers yield nothing.
    #[test]
    fn lying_count_and_short_buffers_never_overread() {
        let mut b = Vec::new();
        b.extend(le(1000));
        b.extend([0u8; UDP4_ROW]);
        b.extend([0u8; 5]); // trailing partial row
        assert_eq!(parse_udp4(&b).len(), 1);
        assert!(parse_tcp4(&[]).is_empty());
        assert!(parse_tcp4(&[1, 0]).is_empty());
        assert!(parse_tcp6(&le(3)).is_empty());
    }

    #[test]
    fn retry_succeeds_after_table_grows() {
        // Probe says 8 bytes; first read finds the table grew to 40; second read fits.
        let mut calls = 0;
        let need = [8u32, 40, 40];
        let got = read_with_retry(|buf, size| {
            let want = need[calls.min(2)];
            calls += 1;
            match buf {
                None => {
                    *size = want;
                    ERROR_INSUFFICIENT_BUFFER
                }
                Some(b) if (b.len() as u32) < want => {
                    *size = want;
                    ERROR_INSUFFICIENT_BUFFER
                }
                Some(b) => {
                    b[0] = 0xAA;
                    0
                }
            }
        });
        let buf = got.expect("retry must succeed");
        assert_eq!(buf[0], 0xAA);
        assert!(buf.len() >= 40);
        assert_eq!(calls, 3);
    }

    #[test]
    fn retry_gives_up_after_three_retries() {
        let mut calls = 0usize;
        let got = read_with_retry(|_buf, size| {
            calls += 1;
            *size = (calls as u32) * 1_000_000; // always growing faster than we allocate
            ERROR_INSUFFICIENT_BUFFER
        });
        assert_eq!(got, Err(ERROR_INSUFFICIENT_BUFFER));
        assert_eq!(
            calls,
            1 + 1 + MAX_BUFFER_RETRIES,
            "probe + read + 3 retries"
        );
    }

    #[test]
    fn retry_propagates_other_errors() {
        assert_eq!(read_with_retry(|_, _| 87), Err(87));
        let mut first = true;
        let got = read_with_retry(|_, size| {
            if first {
                first = false;
                *size = 16;
                ERROR_INSUFFICIENT_BUFFER
            } else {
                5
            }
        });
        assert_eq!(got, Err(5));
        assert_eq!(read_with_retry(|_, _| 0), Ok(vec![]));
    }

    /// One failing table is recorded and the other tables are kept.
    #[test]
    fn assemble_keeps_other_tables_when_one_fails() {
        let mut udp4 = Vec::new();
        udp4.extend(le(1));
        udp4.extend([0, 0, 0, 0]);
        udp4.extend(port(137));
        udp4.extend(le(4));
        let t = assemble(Ok(le(0).to_vec()), Err(50), Ok(udp4), Ok(vec![]));
        assert_eq!(t.udp.len(), 1);
        assert!(t.tcp.is_empty());
        assert_eq!(
            t.errors,
            vec!["tcp6: GetExtendedTcpTable rc=50".to_string()]
        );
        assert!(!t.all_failed());

        let all = assemble(Err(1), Err(2), Err(3), Err(4));
        assert_eq!(all.errors.len(), 4);
        assert!(all.all_failed());
    }
}

#[cfg(all(test, windows))]
mod win_tests {
    use super::*;

    /// Smoke test: tables enumerate without panicking (contents vary per host).
    #[test]
    fn tables_enumerate_without_panicking() {
        let t = read_tables();
        assert!(!t.all_failed(), "every socket table failed: {:?}", t.errors);
    }
}
