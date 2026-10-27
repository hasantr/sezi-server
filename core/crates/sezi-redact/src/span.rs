//! Candidate spans from every recognizer, and how overlapping ones become one masked span.

use crate::category::Category;
use crate::fold;

/// One recognizer hit, in view bytes. `ident` decides numbering: two hits of one category with
/// the same ident get the same placeholder (§4.6 "the same value always gets the same number").
#[derive(Clone, Debug)]
pub struct Cand {
    pub s: usize,
    pub e: usize,
    pub cat: Category,
    pub ident: String,
}

impl Cand {
    pub fn new(s: usize, e: usize, cat: Category, ident: impl Into<String>) -> Cand {
        Cand { s, e, cat, ident: ident.into() }
    }
}

/// Sorted, merged byte intervals: "is this already masked?".
#[derive(Default)]
pub struct Intervals(Vec<(usize, usize)>);

impl Intervals {
    pub fn of<'a>(cands: impl Iterator<Item = &'a Cand>) -> Intervals {
        let mut v: Vec<(usize, usize)> = cands.filter(|c| c.e > c.s).map(|c| (c.s, c.e)).collect();
        v.sort_unstable();
        let mut out: Vec<(usize, usize)> = Vec::with_capacity(v.len());
        for (s, e) in v {
            match out.last_mut() {
                Some(last) if s <= last.1 => last.1 = last.1.max(e),
                _ => out.push((s, e)),
            }
        }
        Intervals(out)
    }

    /// These intervals plus the given candidates.
    pub fn merged<'a>(&self, more: impl Iterator<Item = &'a Cand>) -> Intervals {
        let mut all: Vec<Cand> = self.0.iter().map(|&(s, e)| Cand::new(s, e, Category::Ad, "")).collect();
        all.extend(more.cloned());
        Intervals::of(all.iter())
    }

    /// Does `[s, e)` overlap any interval?
    pub fn overlaps(&self, s: usize, e: usize) -> bool {
        let k = self.0.partition_point(|iv| iv.1 <= s);
        self.0.get(k).is_some_and(|iv| iv.0 < e)
    }
}

/// A final masked span: overlapping candidates united, so no byte any recognizer claimed is left
/// out (the leak check would refuse it otherwise).
pub struct Cluster {
    pub s: usize,
    pub e: usize,
    pub cat: Category,
    pub ident: String,
}

/// Unites overlapping candidates. The category is the longest member's, then the lower tier's
/// (§4.2: "the longest span wins, then the higher tier"). When the union is wider than that member
/// its ident becomes the union's own text, so the vault holds exactly what was masked.
pub fn resolve(mut cands: Vec<Cand>, text: &str) -> Vec<Cluster> {
    cands.retain(|c| c.e > c.s);
    cands.sort_by(|a, b| a.s.cmp(&b.s).then(b.e.cmp(&a.e)));
    let mut out = Vec::new();
    let mut i = 0;
    while i < cands.len() {
        let (gs, mut ge) = (cands[i].s, cands[i].e);
        let mut j = i + 1;
        while j < cands.len() && cands[j].s < ge {
            ge = ge.max(cands[j].e);
            j += 1;
        }
        let rep = cands[i..j]
            .iter()
            .enumerate()
            .max_by(|(ia, a), (ib, b)| {
                (a.e - a.s)
                    .cmp(&(b.e - b.s))
                    .then(b.cat.tier().cmp(&a.cat.tier()))
                    .then(ib.cmp(ia))
            })
            .map(|(_, c)| c)
            .unwrap_or(&cands[i]);
        let ident = if rep.s == gs && rep.e == ge {
            rep.ident.clone()
        } else {
            format!("u:{}", fold::key(&text[gs..ge]))
        };
        out.push(Cluster { s: gs, e: ge, cat: rep.cat, ident });
        i = j;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlaps_unite_and_the_longest_names_the_category() {
        let text = "0123456789abcdef";
        let c = vec![
            Cand::new(0, 4, Category::Tel, "t"),
            Cand::new(2, 10, Category::Adres, "a"),
            Cand::new(12, 14, Category::Kisi, "k"),
            Cand::new(12, 14, Category::Ad, "x"),
        ];
        let r = resolve(c, text);
        assert_eq!(r.len(), 2);
        assert_eq!((r[0].s, r[0].e, r[0].cat), (0, 10, Category::Adres));
        assert!(r[0].ident.starts_with("u:"));
        assert_eq!((r[1].cat, r[1].ident.as_str()), (Category::Kisi, "k"));
        let iv = Intervals::of([Cand::new(3, 5, Category::Ad, "")].iter());
        assert!(iv.overlaps(4, 9) && iv.overlaps(0, 4) && !iv.overlaps(5, 8) && !iv.overlaps(0, 3));
    }
}
