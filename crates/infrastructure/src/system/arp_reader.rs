use async_trait::async_trait;
use ferrous_dns_application::ports::{ArpReader, ArpTable};
use ferrous_dns_domain::DomainError;
use std::net::IpAddr;
use std::str::FromStr;
use tokio::fs;
use tracing::{debug, warn};

/// Linux ARP cache reader (reads /proc/net/arp)
pub struct LinuxArpReader {
    arp_path: String,
}

impl LinuxArpReader {
    pub fn new() -> Self {
        Self {
            arp_path: "/proc/net/arp".to_string(),
        }
    }

    /// Create a new LinuxArpReader with a custom ARP file path (useful for testing)
    pub fn with_path(path: String) -> Self {
        Self { arp_path: path }
    }
}

impl Default for LinuxArpReader {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ArpReader for LinuxArpReader {
    async fn read_arp_table(&self) -> Result<ArpTable, DomainError> {
        let content = fs::read_to_string(&self.arp_path).await.map_err(|e| {
            DomainError::InvalidDomainName(format!("Failed to read ARP cache: {}", e))
        })?;

        let mut arp_table = ArpTable::new();

        // Format of /proc/net/arp:
        // IP address       HW type     Flags       HW address            Mask     Device
        // 192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0

        for (line_num, line) in content.lines().enumerate() {
            if line_num == 0 {
                continue; // Skip header
            }

            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 4 {
                continue;
            }

            let ip_str = fields[0];
            let flags = fields[2];
            let mac = fields[3];

            // Check if entry is complete (0x2 = COMPLETE)
            // Incomplete entries have MAC "00:00:00:00:00:00"
            if flags != "0x2" || mac == "00:00:00:00:00:00" {
                continue;
            }

            match IpAddr::from_str(ip_str) {
                Ok(ip) => {
                    arp_table.insert(ip, mac.to_string());
                }
                Err(e) => {
                    warn!(error = %e, ip = ip_str, "Invalid IP in ARP table");
                }
            }
        }

        debug!(entries = arp_table.len(), "ARP table parsed");
        Ok(arp_table)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_parse_arp_table() {
        let content = r#"IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
192.168.1.2      0x1         0x2         11:22:33:44:55:66     *        eth0
192.168.1.3      0x1         0x0         00:00:00:00:00:00     *        eth0
invalid.ip       0x1         0x2         ff:ff:ff:ff:ff:ff     *        eth0
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let reader =
            LinuxArpReader::with_path(temp_file.path().to_str().unwrap().to_string());
        let arp_table = reader.read_arp_table().await.unwrap();

        assert_eq!(arp_table.len(), 2); // Only 2 valid entries
        assert_eq!(
            arp_table.get(&"192.168.1.1".parse::<IpAddr>().unwrap()),
            Some(&"aa:bb:cc:dd:ee:ff".to_string())
        );
        assert_eq!(
            arp_table.get(&"192.168.1.2".parse::<IpAddr>().unwrap()),
            Some(&"11:22:33:44:55:66".to_string())
        );
        assert!(arp_table
            .get(&"192.168.1.3".parse::<IpAddr>().unwrap())
            .is_none()); // Incomplete entry
    }

    #[tokio::test]
    async fn test_empty_arp_table() {
        let content = "IP address       HW type     Flags       HW address            Mask     Device\n";

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let reader =
            LinuxArpReader::with_path(temp_file.path().to_str().unwrap().to_string());
        let arp_table = reader.read_arp_table().await.unwrap();

        assert_eq!(arp_table.len(), 0);
    }

    #[tokio::test]
    async fn test_nonexistent_arp_file() {
        let reader = LinuxArpReader::with_path("/nonexistent/path".to_string());
        let result = reader.read_arp_table().await;

        assert!(result.is_err());
    }
}
