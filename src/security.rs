use colored::{ColoredString, Colorize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityType {
    Open,
    Wep,
    WpaTkip,
    Wpa2Psk,
    Wpa2Wpa3,
    Wpa3Sae,
    Unknown,
}

impl SecurityType {
    pub fn from_airodump(privacy: &str, cipher: &str, auth: &str) -> Self {
        let privacy = privacy.to_uppercase();
        let auth = auth.to_uppercase();

        if privacy.contains("WPA3") || auth.contains("SAE") {
            if privacy.contains("WPA2") || auth.contains("PSK") {
                return Self::Wpa2Wpa3;
            }
            return Self::Wpa3Sae;
        }
        if privacy.contains("WPA2") || auth.contains("PSK") {
            return Self::Wpa2Psk;
        }
        if privacy.contains("WPA") {
            if cipher.to_uppercase().contains("TKIP") {
                return Self::WpaTkip;
            }
            return Self::WpaTkip;
        }
        if privacy.contains("WEP") {
            return Self::Wep;
        }
        if privacy.contains("OPN") || privacy.is_empty() {
            return Self::Open;
        }
        Self::Unknown
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Open => "OPEN",
            Self::Wep => "WEP",
            Self::WpaTkip => "WPA-TKIP",
            Self::Wpa2Psk => "WPA2-PSK",
            Self::Wpa2Wpa3 => "WPA2/WPA3",
            Self::Wpa3Sae => "WPA3-SAE",
            Self::Unknown => "UNKNOWN",
        }
    }

    pub fn needs_handshake(&self) -> bool {
        matches!(
            self,
            Self::WpaTkip | Self::Wpa2Psk | Self::Wpa2Wpa3
        )
    }

    /// 802.11w/PMF is mandatory on WPA3 and common in transition mode.
    /// Unprotected deauth frames are dropped by those clients.
    pub fn pmf_likely(&self) -> bool {
        matches!(self, Self::Wpa2Wpa3 | Self::Wpa3Sae)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VulnerabilityLevel {
    Critical,
    High,
    Medium,
    Low,
    Secure,
}

#[derive(Debug, Clone)]
pub struct Vulnerability {
    pub level: VulnerabilityLevel,
    pub reason: String,
}

impl Vulnerability {
    pub fn assess(security: &SecurityType, essid: &str) -> Self {
        match security {
            SecurityType::Open => Self {
                level: VulnerabilityLevel::Critical,
                reason: "No encryption — anyone can connect".into(),
            },
            SecurityType::Wep => Self {
                level: VulnerabilityLevel::Critical,
                reason: "WEP cracked in minutes with IV capture".into(),
            },
            SecurityType::WpaTkip => Self {
                level: VulnerabilityLevel::High,
                reason: "WPA-TKIP vulnerable to Beck-Tews attack".into(),
            },
            SecurityType::Wpa2Psk => Self {
                level: VulnerabilityLevel::Medium,
                reason: "WPA2-PSK crackable via handshake + wordlist".into(),
            },
            SecurityType::Wpa2Wpa3 => Self {
                level: VulnerabilityLevel::Low,
                reason: "WPA2/WPA3 — PMF clients ignore deauth".into(),
            },
            SecurityType::Wpa3Sae => Self {
                level: VulnerabilityLevel::Secure,
                reason: "WPA3-SAE resistant to offline dictionary attacks".into(),
            },
            SecurityType::Unknown => Self {
                level: VulnerabilityLevel::Medium,
                reason: "Unknown security — investigate manually".into(),
            },
        }
        .with_default_essid(essid)
    }

    fn with_default_essid(mut self, essid: &str) -> Self {
        if essid.is_empty() || essid == "<hidden>" {
            self.reason = format!("{}; hidden SSID", self.reason);
        }
        self
    }

    pub fn is_vulnerable(&self) -> bool {
        !matches!(self.level, VulnerabilityLevel::Secure)
    }

    pub fn label(&self) -> ColoredString {
        match self.level {
            VulnerabilityLevel::Critical => format!("⚠ CRITICAL — {}", self.reason).red().bold(),
            VulnerabilityLevel::High => format!("⚠ HIGH — {}", self.reason).red(),
            VulnerabilityLevel::Medium => format!("⚠ VULN — {}", self.reason).yellow(),
            VulnerabilityLevel::Low => format!("◦ LOW — {}", self.reason).yellow().dimmed(),
            VulnerabilityLevel::Secure => "✓ SECURE".green(),
        }
    }
}
