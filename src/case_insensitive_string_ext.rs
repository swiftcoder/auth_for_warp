pub trait CaseInsensitiveStringExt {
    fn strip_prefix_ignore_ascii_case<'a>(&'a self, prefix: &str) -> Option<&'a str>;
}

impl CaseInsensitiveStringExt for String {
    fn strip_prefix_ignore_ascii_case<'a>(&'a self, prefix: &str) -> Option<&'a str> {
        if self.len() < prefix.len() {
            return None;
        }

        let my_prefix = &self[0..prefix.len()];

        if my_prefix.eq_ignore_ascii_case(prefix) {
            Some(&self[prefix.len()..])
        } else {
            None
        }
    }
}
