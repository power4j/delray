use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

/// 进程关联表：后台线程定时重建，抓包线程只读查询。
#[derive(Default)]
pub struct ProcTable {
    /// (本机 IP, 本机端口) -> 进程信息。
    entries: HashMap<(IpAddr, u16), ProcInfo>,
    /// pid -> 进程展示名（cmdline 优先）。
    pub names: HashMap<u32, String>,
}

#[derive(Clone)]
struct ProcInfo {
    pid: u32,
}

pub type SharedProcTable = Arc<RwLock<ProcTable>>;

impl ProcTable {
    pub fn lookup(&self, ip: IpAddr, port: u16) -> Option<u32> {
        self.entries.get(&(ip, port)).map(|info| info.pid)
    }
}

/// 启动后台线程定时重建进程表，返回共享句柄。
/// 重建在锁外完成，write 锁仅做瞬时整表替换，抓包线程几乎不阻塞。
pub fn spawn(refresh: Duration) -> SharedProcTable {
    let table: SharedProcTable = Arc::new(RwLock::new(ProcTable::default()));
    let handle = table.clone();
    thread::spawn(move || {
        loop {
            let new_table = build();
            if let Ok(mut w) = handle.write() {
                *w = new_table;
            }
            thread::sleep(refresh);
        }
    });
    table
}

/// 扫描 /proc 重建进程关联表。
fn build() -> ProcTable {
    // 1. /proc/net/{tcp,udp,tcp6,udp6} -> (ip, port) -> inode
    let mut socket_to_inode: HashMap<(IpAddr, u16), u64> = HashMap::new();
    parse_file("/proc/net/tcp", &mut socket_to_inode, false);
    parse_file("/proc/net/udp", &mut socket_to_inode, false);
    parse_file("/proc/net/tcp6", &mut socket_to_inode, true);
    parse_file("/proc/net/udp6", &mut socket_to_inode, true);

    // 2. 反向索引 inode -> sockets，供 fd 扫描时 O(1) 匹配
    let mut inode_to_sockets: HashMap<u64, Vec<(IpAddr, u16)>> = HashMap::new();
    for ((ip, port), inode) in &socket_to_inode {
        inode_to_sockets
            .entry(*inode)
            .or_default()
            .push((*ip, *port));
    }

    // 3. 扫 /proc/*/fd，匹配 socket inode -> pid
    let mut entries: HashMap<(IpAddr, u16), ProcInfo> = HashMap::new();
    let mut names: HashMap<u32, String> = HashMap::new();

    if let Ok(dir) = fs::read_dir("/proc") {
        for entry in dir.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<u32>().ok())
            else {
                continue;
            };
            let mut hits: Vec<(IpAddr, u16)> = Vec::new();
            for inode in socket_inodes_of(pid) {
                if let Some(sockets) = inode_to_sockets.get(&inode) {
                    hits.extend(sockets.iter().copied());
                }
            }
            if hits.is_empty() {
                continue;
            }
            // 仅对命中 socket 的进程读取进程名，控制开销
            let name = read_name(pid).unwrap_or_else(|| pid.to_string());
            names.insert(pid, name);
            for (ip, port) in hits {
                entries.insert((ip, port), ProcInfo { pid });
            }
        }
    }

    ProcTable { entries, names }
}

fn parse_file(path: &str, out: &mut HashMap<(IpAddr, u16), u64>, ipv6: bool) {
    let Ok(content) = fs::read_to_string(path) else {
        return;
    };
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }
        let Some((ip, port)) = parse_local(fields[1], ipv6) else {
            continue;
        };
        let Ok(inode) = fields[9].parse::<u64>() else {
            continue;
        };
        out.insert((ip, port), inode);
    }
}

/// 解析 /proc/net/* 的 local_address 字段 "IP:PORT"（均为十六进制，IP 为 host 字节序）。
fn parse_local(s: &str, ipv6: bool) -> Option<(IpAddr, u16)> {
    let (addr_hex, port_hex) = s.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let ip = if ipv6 {
        IpAddr::V6(parse_ipv6(addr_hex)?)
    } else {
        // host 字节序 hex -> 字节即 IP（假设小端架构，覆盖 x86_64/arm64主流 Linux）
        let n = u32::from_str_radix(addr_hex, 16).ok()?;
        IpAddr::V4(Ipv4Addr::from(n.to_le_bytes()))
    };
    Some((ip, port))
}

fn parse_ipv6(hex: &str) -> Option<Ipv6Addr> {
    if hex.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for i in 0..4 {
        let part = u32::from_str_radix(&hex[i * 8..i * 8 + 8], 16).ok()?;
        bytes[i * 4..i * 4 + 4].copy_from_slice(&part.to_le_bytes());
    }
    Some(Ipv6Addr::from(bytes))
}

/// 读取某进程打开的 socket inode 列表。
fn socket_inodes_of(pid: u32) -> Vec<u64> {
    let mut v = Vec::new();
    let Ok(dir) = fs::read_dir(format!("/proc/{pid}/fd")) else {
        return v;
    };
    for entry in dir.flatten() {
        if let Ok(target) = fs::read_link(entry.path())
            && let Some(inode) = parse_socket_inode(&target.to_string_lossy())
        {
            v.push(inode);
        }
    }
    v
}

fn parse_socket_inode(s: &str) -> Option<u64> {
    let s = s.strip_prefix("socket:[")?;
    let s = s.strip_suffix(']')?;
    s.parse().ok()
}

/// 读取进程展示名：优先 cmdline，其次 exe 基名，最后 comm。
/// comm 可被程序用 prctl 改名（如代理软件改成协议名），定位价值低，
/// 故优先用能反映真实程序的 cmdline / exe 路径。
fn read_name(pid: u32) -> Option<String> {
    if let Some(cmd) = read_cmdline(pid) {
        return Some(cmd);
    }
    if let Some(exe) = read_exe_basename(pid) {
        return Some(exe);
    }
    read_comm(pid)
}

fn read_cmdline(pid: u32) -> Option<String> {
    let data = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    parse_cmdline_bytes(&data)
}

/// 解析 /proc/<pid>/cmdline 原始字节（NUL 分隔参数）为空格连接的命令行。
fn parse_cmdline_bytes(data: &[u8]) -> Option<String> {
    let parts: Vec<&str> = data
        .split(|&b| b == 0)
        .filter_map(|s| std::str::from_utf8(s).ok())
        .filter(|s| !s.is_empty())
        .collect();
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" "))
    }
}

fn read_exe_basename(pid: u32) -> Option<String> {
    let path = fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    path.file_name()?.to_str().map(|s| s.to_string())
}

fn read_comm(pid: u32) -> Option<String> {
    let s = fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    Some(s.trim_end_matches('\n').to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_local_ipv4_loopback() {
        // /proc/net/tcp 中 127.0.0.1:9000 编码为 host 字节序 hex
        let (ip, port) = parse_local("0100007F:2328", false).unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(port, 0x2328);
    }

    #[test]
    fn parse_local_ipv4_wildcard_http() {
        let (ip, port) = parse_local("00000000:0050", false).unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(port, 80);
    }

    #[test]
    fn parse_ipv6_loopback() {
        // ::1 在 /proc/net/tcp6 的 4×u32 host 字节序编码
        let ip = parse_ipv6("00000000000000000000000001000000").unwrap();
        assert_eq!(ip, Ipv6Addr::LOCALHOST);
    }

    #[test]
    fn parse_socket_inode_matches() {
        assert_eq!(parse_socket_inode("socket:[12345]"), Some(12345));
        assert_eq!(parse_socket_inode("socket:[999]"), Some(999));
    }

    #[test]
    fn parse_socket_inode_rejects_non_socket() {
        assert_eq!(parse_socket_inode("/dev/null"), None);
        assert_eq!(parse_socket_inode("socket:[abc]"), None);
    }

    #[test]
    fn parse_cmdline_basic() {
        // NUL 分隔的多个参数 -> 空格连接
        assert_eq!(
            parse_cmdline_bytes(b"/usr/bin/curl\0http://x\0"),
            Some("/usr/bin/curl http://x".to_string())
        );
    }

    #[test]
    fn parse_cmdline_single_arg() {
        assert_eq!(
            parse_cmdline_bytes(b"/usr/sbin/nginx\0"),
            Some("/usr/sbin/nginx".to_string())
        );
    }

    #[test]
    fn parse_cmdline_empty() {
        // 内核线程无 cmdline，应返回 None 以触发 exe/comm 兜底
        assert_eq!(parse_cmdline_bytes(b"\0\0"), None);
        assert_eq!(parse_cmdline_bytes(b""), None);
    }
}
