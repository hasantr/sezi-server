//! A web app's version (Semantic Versioning 2.0.0): `MAJOR.MINOR.PATCH`, an optional
//! `-prerelease` and an optional `+build`. Ordered by the spec — numbers numerically, a
//! prerelease below its release, prerelease identifiers numeric-before-alphanumeric — with the
//! build ignored, so `1.0.0+a` and `1.0.0+b` are the same version. What the host's downgrade
//! refusal compares (`plugin/downgrade`).

use std::cmp::Ordering;

/// A parsed semantic version.
#[derive(Debug, Clone, Eq)]
pub struct Semver {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    /// The dot-separated prerelease identifiers; empty for a release.
    pub pre: Vec<String>,
    /// The build metadata as written, without its `+`; never compared.
    pub build: String,
}

/// The longest version string read.
const MAX_LEN: usize = 128;

fn number(s: &str) -> Option<u64> {
    // No leading zero, digits only — the spec's numeric identifier.
    if s.is_empty() || (s.len() > 1 && s.starts_with('0')) || !s.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

fn idents_ok(s: &str, numeric_no_lead: bool) -> bool {
    s.split('.').all(|id| {
        !id.is_empty()
            && id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
            && (!numeric_no_lead
                || !id.bytes().all(|c| c.is_ascii_digit())
                || id == "0"
                || !id.starts_with('0'))
    })
}

impl Semver {
    /// Parse `s`, or `None` when it is not a semantic version.
    pub fn parse(s: &str) -> Option<Semver> {
        if s.len() > MAX_LEN {
            return None;
        }
        let (rest, build) = match s.split_once('+') {
            Some((r, b)) => {
                if !idents_ok(b, false) {
                    return None;
                }
                (r, b.to_string())
            }
            None => (s, String::new()),
        };
        let (core, pre) = match rest.split_once('-') {
            Some((c, p)) => {
                if !idents_ok(p, true) {
                    return None;
                }
                (c, p.split('.').map(str::to_string).collect())
            }
            None => (rest, Vec::new()),
        };
        let mut parts = core.split('.');
        let major = number(parts.next()?)?;
        let minor = number(parts.next()?)?;
        let patch = number(parts.next()?)?;
        if parts.next().is_some() {
            return None;
        }
        Some(Semver { major, minor, patch, pre, build })
    }
}

impl std::fmt::Display for Semver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if !self.pre.is_empty() {
            write!(f, "-{}", self.pre.join("."))?;
        }
        if !self.build.is_empty() {
            write!(f, "+{}", self.build)?;
        }
        Ok(())
    }
}

fn cmp_ident(a: &str, b: &str) -> Ordering {
    let num = |s: &str| s.bytes().all(|c| c.is_ascii_digit()).then(|| s.parse::<u64>().ok()).flatten();
    match (num(a), num(b)) {
        (Some(x), Some(y)) => x.cmp(&y),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => a.cmp(b),
    }
}

impl Ord for Semver {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| match (self.pre.is_empty(), other.pre.is_empty()) {
                (true, true) => Ordering::Equal,
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => {
                    for (a, b) in self.pre.iter().zip(&other.pre) {
                        let o = cmp_ident(a, b);
                        if o != Ordering::Equal {
                            return o;
                        }
                    }
                    self.pre.len().cmp(&other.pre.len())
                }
            })
    }
}

impl PartialOrd for Semver {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Semver {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Semver {
        Semver::parse(s).unwrap_or_else(|| panic!("{s} parses"))
    }

    #[test]
    fn the_spec_precedence_example_is_ascending() {
        let order = [
            "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2",
            "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.1", "1.1.0", "2.0.0", "10.0.0",
        ];
        for w in order.windows(2) {
            assert!(v(w[0]) < v(w[1]), "{} < {}", w[0], w[1]);
        }
    }

    #[test]
    fn build_metadata_is_not_compared_but_is_kept() {
        assert_eq!(v("1.2.3+a"), v("1.2.3+b"));
        assert_eq!(v("1.2.3+exp.sha.5114f85").to_string(), "1.2.3+exp.sha.5114f85");
    }

    #[test]
    fn what_is_not_a_version() {
        for bad in [
            "", "1", "1.2", "1.2.3.4", "01.2.3", "1.02.3", "1.2.3-", "1.2.3-01", "1.2.3+", "v1.2.3",
            "1.2.3-a..b", "1.2.3 ", "-1.2.3", "1.2.x",
        ] {
            assert!(Semver::parse(bad).is_none(), "{bad:?} is refused");
        }
        assert!(Semver::parse(&"1.2.3-".repeat(40)).is_none(), "past the length cap");
    }
}
