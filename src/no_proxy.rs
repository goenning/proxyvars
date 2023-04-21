use ipnet::IpNet;
use std::net::{IpAddr, SocketAddr};


/// A NoProxy matcher
/// 
/// ```
/// use envproxy::NoProxy;
/// 
/// let np = NoProxy::from("10.0.0.0");
/// assert_eq!(np.matches("http://10.0.0.0"), true);
/// assert_eq!(np.matches("http://11.0.0.0"), false);
/// ```
pub struct NoProxy {
    matchers: Vec<NoProxyMatcher>,
}

impl NoProxy {
    /// Verify if a target URL should be proxied or not, based on the NoProxy matcher rules
    /// 
    /// ```
    /// use envproxy::NoProxy;
    /// 
    /// let np = NoProxy::from("10.0.0.0");
    /// assert_eq!(np.matches("http://10.0.0.0"), true);
    /// assert_eq!(np.matches("http://11.0.0.0"), false);
    /// ```
    pub fn matches(&self, target: &str) -> bool {
        let target_uri = match target.parse::<http::Uri>() {
            Ok(uri) => uri,
            Err(_) => return false,
        };

        let target_host = target_uri.host().unwrap_or_default();
        let target_port = target_uri
            .port_u16()
            .unwrap_or_else(|| match target_uri.scheme_str() {
                Some("http") => 80,
                Some("https") => 443,
                _ => 0,
            });
        let target_ip = target_host.parse::<IpAddr>().ok();

        for matcher in self.matchers.iter() {
            match matcher {
                NoProxyMatcher::Address(ip, port) => {
                    if let Some(target_ip) = target_ip {
                        if *ip == target_ip && (*port == 0 || *port == target_port) {
                            return true;
                        }
                    }
                }
                NoProxyMatcher::Network(net) => {
                    if let Some(target_ip) = target_ip {
                        if net.contains(&target_ip) {
                            return true;
                        }
                    }
                }
                NoProxyMatcher::Host(host, port, exact) => {
                    let host_matches =
                        (*exact && &host[1..] == target_host) || target_host.ends_with(host);
                    let port_matches = *port == 0 || *port == target_port;

                    if host_matches && port_matches {
                        return true;
                    }
                }
                NoProxyMatcher::Wildcard => {
                    return true;
                }
            }
        }

        false
    }
}

impl From<&str> for NoProxy {
    fn from(value: &str) -> Self {
        let matchers = value
            .split(',')
            .filter(|s| !s.is_empty())
            .map(NoProxyMatcher::from)
            .collect();
        NoProxy { matchers }
    }
}

impl From<String> for NoProxy {
    fn from(value: String) -> Self {
        NoProxy::from(value.as_str())
    }
}

fn parse_ip_port(value: &str) -> Option<(IpAddr, u16)> {
    match value.parse::<SocketAddr>() {
        Ok(addr) => Some((addr.ip(), addr.port())),
        // Otherwise try Ip only
        Err(_) => match value.parse::<IpAddr>() {
            Ok(addr) => Some((addr, 0)),
            Err(_) => None,
        },
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
enum NoProxyMatcher {
    // Matches IP address with an optional port
    Address(IpAddr, u16),
    // Matches all IP addresses based on its CIDR, port is ignored
    Network(IpNet),
    // Matches the host name with an optional port
    Host(String, u16, bool),
    // Matches all hosts and ports
    Wildcard,
}

impl NoProxyMatcher {
    fn from(value: &str) -> Self {
        let v = value.trim();
        match v.parse::<IpNet>() {
            Ok(ip) => NoProxyMatcher::Network(ip),
            // Try parse Ip:Port
            Err(_) => match parse_ip_port(v) {
                Some((ip, port)) => NoProxyMatcher::Address(ip, port),
                // Fallback to Host[:Port]
                None => {
                    if v == "*" {
                        return NoProxyMatcher::Wildcard;
                    }

                    let mut parts = v.split(':');
                    let mut host = parts.next().unwrap_or_default();
                    let port: u16 = parts.next().unwrap_or_default().parse().unwrap_or_default();

                    // *.example should behave like .example
                    if host.starts_with("*.") {
                        host = &host[1..]
                    }

                    // If host starts with a dot, it should only match subdomains
                    if host.starts_with('.') {
                        return NoProxyMatcher::Host(host.into(), port, false);
                    }

                    // Otherwise it should match exact host and subdomains
                    NoProxyMatcher::Host(format!(".{}", host), port, true)
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::NoProxy;
    use crate::no_proxy::NoProxyMatcher;

    #[test]
    fn convert_empty() {
        let np = NoProxy::from("");

        assert_eq!(np.matchers.len(), 0);
    }
    #[test]
    fn convert_skip_empty_entries() {
        let np = NoProxy::from("10.0.0.0,,,,example.com,");

        assert_eq!(np.matchers.len(), 2);
    }

    #[test]
    fn convert_from_string() {
        let np = NoProxy::from("10.0.0.0,192.168.1.0/24,example.com,*.test.org,.foo.org:443");

        assert_eq!(
            np.matchers[0],
            NoProxyMatcher::Address("10.0.0.0".parse().unwrap(), 0)
        );
        assert_eq!(
            np.matchers[1],
            NoProxyMatcher::Network("192.168.1.0/24".parse().unwrap())
        );
        assert_eq!(
            np.matchers[2],
            NoProxyMatcher::Host(".example.com".into(), 0, true)
        );
        assert_eq!(
            np.matchers[3],
            NoProxyMatcher::Host(".test.org".into(), 0, false)
        );
        assert_eq!(
            np.matchers[4],
            NoProxyMatcher::Host(".foo.org".into(), 443, false)
        );
    }

    #[test]
    fn convert_from_string_with_ports() {
        let np = NoProxy::from("10.0.0.0:8080,192.168.1.0/24,example.com:443");

        assert_eq!(
            np.matchers[0],
            NoProxyMatcher::Address("10.0.0.0".parse().unwrap(), 8080)
        );
        assert_eq!(
            np.matchers[1],
            NoProxyMatcher::Network("192.168.1.0/24".parse().unwrap())
        );
        assert_eq!(
            np.matchers[2],
            NoProxyMatcher::Host(".example.com".into(), 443, true)
        );
    }

    #[test]
    fn match_ip() {
        let np = NoProxy::from("10.0.0.0");

        assert_eq!(np.matches("http://10.0.0.0"), true);
        assert_eq!(np.matches("http://10.0.0.0:8080"), true);
        assert_eq!(np.matches("https://10.0.0.0:443"), true);
    }

    #[test]
    fn match_ip_with_port() {
        let np = NoProxy::from("10.0.0.0:443");

        assert_eq!(np.matches("http://10.0.0.0"), false);
        assert_eq!(np.matches("http://10.0.0.0:8080"), false);
        assert_eq!(np.matches("https://10.0.0.0"), true);
        assert_eq!(np.matches("https://10.0.0.0:443"), true);
    }

    #[test]
    fn match_multiple_ips() {
        let np = NoProxy::from("10.0.0.0,64.64.32.32");

        assert_eq!(np.matches("http://64.64.32.32"), true);
        assert_eq!(np.matches("http://64.64.32.32:8080"), true);
        assert_eq!(np.matches("https://10.0.0.0:443"), true);
    }

    #[test]
    fn match_multiple_ip_with_port() {
        let np = NoProxy::from("10.0.0.0:8080,64.64.32.32:8080");

        assert_eq!(np.matches("http://64.64.32.32"), false);
        assert_eq!(np.matches("http://64.64.32.32:8080"), true);
        assert_eq!(np.matches("https://10.0.0.0:443"), false);
        assert_eq!(np.matches("https://10.0.0.0:8080"), true);
    }

    #[test]
    fn match_cidr() {
        let np = NoProxy::from("10.0.0.0/24,64.64.0.0/18,20.20.0.0/32");

        assert_eq!(np.matches("http://20.20.0.0"), true);
        assert_eq!(np.matches("http://20.20.0.1"), false);

        assert_eq!(np.matches("http://10.0.0.0:8080"), true);
        assert_eq!(np.matches("https://10.0.0.255:443"), true);
        assert_eq!(np.matches("https://10.0.1.0:443"), false);
        assert_eq!(np.matches("https//10.0.1.255"), false);

        assert_eq!(np.matches("http://64.64.0.0"), true);
        assert_eq!(np.matches("http://64.64.63.255"), true);
        assert_eq!(np.matches("http://64.65.0.0"), false);
    }

    #[test]
    fn match_wildcard() {
        let np = NoProxy::from("*");

        assert_eq!(np.matches("http://20.20.0.0"), true);
        assert_eq!(np.matches("http://10.0.0.0"), true);
        assert_eq!(np.matches("http://10.0.0.255"), true);
        assert_eq!(np.matches("http://64.64.0.0"), true);
        assert_eq!(np.matches("http://example.com"), true);
        assert_eq!(np.matches("http://blog.example.com"), true);
    }

    #[test]
    fn match_host() {
        let np = NoProxy::from("example.com,company.org,*.domain.io");

        assert_eq!(np.matches("http://example.com"), true);
        assert_eq!(np.matches("http://blog.example.com"), true);

        assert_eq!(np.matches("http://invalid.org"), false);
        assert_eq!(np.matches("http://blog.invalid.org"), false);

        assert_eq!(np.matches("http://company.org:443"), true);
        assert_eq!(np.matches("https://company.org:443"), true);
        assert_eq!(np.matches("https://company.org"), true);

        assert_eq!(np.matches("http://domain.io"), false);
        assert_eq!(np.matches("http://blog.domain.io"), true);
        assert_eq!(np.matches("http://docs.domain.io"), true);
    }

    #[test]
    fn match_host_with_ports() {
        let np = NoProxy::from("example.com:8080,company.org:443,*.domain.io:80");

        assert_eq!(np.matches("http://example.com"), false);
        assert_eq!(np.matches("http://example.com:8080"), true);

        assert_eq!(np.matches("http://company.org"), false);
        assert_eq!(np.matches("http://company.org:443"), true);
        assert_eq!(np.matches("https://company.org"), true);
        assert_eq!(np.matches("https://company.org:443"), true);

        assert_eq!(np.matches("http://domain.io"), false);
        assert_eq!(np.matches("http://domain.io:80"), false);
        assert_eq!(np.matches("http://blog.domain.io"), true);
        assert_eq!(np.matches("http://docs.domain.io:80"), true);
        assert_eq!(np.matches("http://docs.domain.io:8080"), false);
    }
}
