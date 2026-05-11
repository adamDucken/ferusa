use std::fmt;
use std::time::Duration;

use iroh::endpoint::Connection;
use iroh::Watcher;
use log::info;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrohPathKind {
    Direct,
    Relay,
    Other,
    Unknown,
}

impl fmt::Display for IrohPathKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IrohPathKind::Direct => f.write_str("direct p2p"),
            IrohPathKind::Relay => f.write_str("relay"),
            IrohPathKind::Other => f.write_str("other"),
            IrohPathKind::Unknown => f.write_str("unknown"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct IrohPathReport {
    pub label: String,
    pub remote_id: iroh::PublicKey,
    pub selected: IrohPathKind,
    pub selected_addr: Option<String>,
    pub selected_rtt: Option<Duration>,
    pub selected_tx_datagrams: Option<u64>,
    pub selected_tx_bytes: Option<u64>,
    pub selected_lost_packets: Option<u64>,
    pub direct_paths: usize,
    pub relay_paths: usize,
    pub other_paths: usize,
    pub path_count: usize,
}

impl IrohPathReport {
    pub fn human_summary(&self) -> String {
        let addr = self
            .selected_addr
            .as_deref()
            .unwrap_or("no selected address");
        let rtt = self
            .selected_rtt
            .map(|r| format!("{}ms", r.as_millis()))
            .unwrap_or_else(|| "n/a".to_string());
        let tx = match (self.selected_tx_datagrams, self.selected_tx_bytes) {
            (Some(datagrams), Some(bytes)) => format!("{datagrams} datagrams / {bytes} bytes"),
            _ => "n/a".to_string(),
        };
        let lost = self
            .selected_lost_packets
            .map(|v| v.to_string())
            .unwrap_or_else(|| "n/a".to_string());

        format!(
            "p2p route: {} ({addr}; paths direct={} relay={} other={}; rtt={rtt}; tx={tx}; lost_packets={lost})",
            self.selected, self.direct_paths, self.relay_paths, self.other_paths
        )
    }
}

pub fn iroh_path_report(label: impl Into<String>, conn: &Connection) -> IrohPathReport {
    let label = label.into();
    let remote_id = conn.remote_id();
    let mut watcher = conn.paths();
    let paths = watcher.get();

    let mut report = IrohPathReport {
        label,
        remote_id,
        selected: IrohPathKind::Unknown,
        selected_addr: None,
        selected_rtt: None,
        selected_tx_datagrams: None,
        selected_tx_bytes: None,
        selected_lost_packets: None,
        direct_paths: 0,
        relay_paths: 0,
        other_paths: 0,
        path_count: 0,
    };

    let mut path_details = Vec::new();

    for path in paths.iter() {
        report.path_count += 1;
        let kind = if path.is_ip() {
            report.direct_paths += 1;
            IrohPathKind::Direct
        } else if path.is_relay() {
            report.relay_paths += 1;
            IrohPathKind::Relay
        } else {
            report.other_paths += 1;
            IrohPathKind::Other
        };

        let stats = path.stats();
        let rtt = path.rtt();
        let tx_datagrams = stats.map(|s| s.udp_tx.datagrams);
        let tx_bytes = stats.map(|s| s.udp_tx.bytes);
        let lost_packets = stats.map(|s| s.lost_packets);

        path_details.push(format!(
            "kind={} selected={} closed={} addr={:?} rtt={:?} tx_datagrams={:?} tx_bytes={:?} lost_packets={:?}",
            kind,
            path.is_selected(),
            path.is_closed(),
            path.remote_addr(),
            rtt,
            tx_datagrams,
            tx_bytes,
            lost_packets
        ));

        if path.is_selected() {
            report.selected = kind;
            report.selected_addr = Some(format!("{:?}", path.remote_addr()));
            report.selected_rtt = rtt;
            report.selected_tx_datagrams = tx_datagrams;
            report.selected_tx_bytes = tx_bytes;
            report.selected_lost_packets = lost_packets;
        }
    }

    if report.selected == IrohPathKind::Unknown && report.path_count == 1 {
        if report.direct_paths == 1 {
            report.selected = IrohPathKind::Direct;
        } else if report.relay_paths == 1 {
            report.selected = IrohPathKind::Relay;
        } else if report.other_paths == 1 {
            report.selected = IrohPathKind::Other;
        }
    }

    info!(
        "[ferusa:cli]: iroh_path label={} remote={} selected={} direct_paths={} relay_paths={} other_paths={} paths=[{}]",
        report.label,
        report.remote_id,
        report.selected,
        report.direct_paths,
        report.relay_paths,
        report.other_paths,
        path_details.join(" | ")
    );

    report
}
