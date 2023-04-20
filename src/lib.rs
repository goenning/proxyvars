pub fn http() -> Option<String> {
    invariant_var("HTTP_PROXY")
}

pub fn https() -> Option<String> {
    invariant_var("HTTPS_PROXY")
}

fn invariant_var(name: &str) -> Option<String> {
    let nonempty = |o: Option<String>| o.filter(|s| !s.is_empty());
    
    nonempty(std::env::var(name).ok()).or_else(|| nonempty(std::env::var(name.to_lowercase()).ok()))
}


#[cfg(test)]
mod tests {
    #[test]
    fn undefined_var() {
        std::env::remove_var("HTTP_PROXY");
        std::env::remove_var("http_proxy");
        std::env::remove_var("https_proxy");
        std::env::remove_var("HTTPS_PROXY");

        let http_proxy = crate::http();
        assert!(http_proxy.is_none());

        let https_proxy = crate::https();
        assert!(https_proxy.is_none());
    }
}