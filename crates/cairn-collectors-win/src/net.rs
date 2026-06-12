//! TCP/UDP table enumeration with owning PID (raw WinAPI -> plain rows).
use cairn_core::Result;

#[derive(Debug, Clone)]
pub struct RawTcpRow {
    pub laddr: String,
    pub lport: u16,
    pub raddr: String,
    pub rport: u16,
    pub state_raw: u32,
    pub pid: u32,
}
#[derive(Debug, Clone)]
pub struct RawUdpRow {
    pub laddr: String,
    pub lport: u16,
    pub pid: u32,
}

#[cfg(not(windows))]
pub fn tcp_table() -> Result<Vec<RawTcpRow>> {
    Ok(vec![])
}
#[cfg(not(windows))]
pub fn udp_table() -> Result<Vec<RawUdpRow>> {
    Ok(vec![])
}

#[cfg(windows)]
pub fn tcp_table() -> Result<Vec<RawTcpRow>> {
    win::tcp_table()
}
#[cfg(windows)]
pub fn udp_table() -> Result<Vec<RawUdpRow>> {
    win::udp_table()
}

#[cfg(windows)]
mod win {
    use super::{RawTcpRow, RawUdpRow};
    use cairn_core::{CairnError, Result};
    use std::net::Ipv4Addr;
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCPTABLE_OWNER_PID, MIB_UDPTABLE_OWNER_PID,
        TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
    };
    use windows::Win32::Networking::WinSock::AF_INET;

    /// A MIB local/remote address is stored as a 32-bit value already in network byte
    /// order; Ipv4Addr::from wants host-order, so swap from BE.
    fn ipv4(addr: u32) -> String {
        Ipv4Addr::from(u32::from_be(addr)).to_string()
    }
    /// MIB ports are in network byte order in the low 16 bits.
    fn port(p: u32) -> u16 {
        u16::from_be((p & 0xFFFF) as u16)
    }

    pub fn tcp_table() -> Result<Vec<RawTcpRow>> {
        let mut size = 0u32;
        // SAFETY: size-probe form — null buffer, &mut size; returns required bytes.
        unsafe {
            let _ = GetExtendedTcpTable(
                None,
                &mut size,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
        }
        let mut buf = vec![0u8; size as usize];
        // SAFETY: buf has `size` bytes; we pass its pointer + the same size.
        let rc = unsafe {
            GetExtendedTcpTable(
                Some(buf.as_mut_ptr() as *mut _),
                &mut size,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if rc != 0 {
            return Err(CairnError::Collector {
                collector: "net".into(),
                reason: format!("GetExtendedTcpTable rc={rc}"),
            });
        }
        // SAFETY: buf begins with a MIB_TCPTABLE_OWNER_PID: a dwNumEntries count followed
        // by that many rows.
        let table = unsafe { &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
        let n = table.dwNumEntries as usize;
        // SAFETY: the row array has dwNumEntries entries immediately after the count.
        let rows = unsafe { std::slice::from_raw_parts(table.table.as_ptr(), n) };
        Ok(rows
            .iter()
            .map(|r| RawTcpRow {
                laddr: ipv4(r.dwLocalAddr),
                lport: port(r.dwLocalPort),
                raddr: ipv4(r.dwRemoteAddr),
                rport: port(r.dwRemotePort),
                state_raw: r.dwState,
                pid: r.dwOwningPid,
            })
            .collect())
    }

    pub fn udp_table() -> Result<Vec<RawUdpRow>> {
        let mut size = 0u32;
        // SAFETY: size-probe form.
        unsafe {
            let _ = GetExtendedUdpTable(
                None,
                &mut size,
                false,
                AF_INET.0 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );
        }
        let mut buf = vec![0u8; size as usize];
        // SAFETY: buf sized to `size`; pointer + same size passed.
        let rc = unsafe {
            GetExtendedUdpTable(
                Some(buf.as_mut_ptr() as *mut _),
                &mut size,
                false,
                AF_INET.0 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            )
        };
        if rc != 0 {
            return Err(CairnError::Collector {
                collector: "net".into(),
                reason: format!("GetExtendedUdpTable rc={rc}"),
            });
        }
        // SAFETY: buf begins with a MIB_UDPTABLE_OWNER_PID.
        let table = unsafe { &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID) };
        let n = table.dwNumEntries as usize;
        // SAFETY: row array of dwNumEntries entries after the count.
        let rows = unsafe { std::slice::from_raw_parts(table.table.as_ptr(), n) };
        Ok(rows
            .iter()
            .map(|r| RawUdpRow {
                laddr: ipv4(r.dwLocalAddr),
                lport: port(r.dwLocalPort),
                pid: r.dwOwningPid,
            })
            .collect())
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    /// Smoke test: tables enumerate without panicking and return rows with sane ports.
    /// (Exact contents vary; we only prove the FFI path works.)
    #[test]
    fn tables_enumerate_without_panicking() {
        let tcp = tcp_table().expect("tcp");
        let _udp = udp_table().expect("udp");
        // Don't hard-require any specific socket; assert the call is total and any row has
        // a u16 local port (type-level sanity).
        for r in tcp.iter().take(1) {
            let _: u16 = r.lport;
        }
    }
}
