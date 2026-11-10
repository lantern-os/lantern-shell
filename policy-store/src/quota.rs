//! [RFC-0025](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0025-audit-log-service-operations.md)'s per-grant quota: how many
//! operation records one grant may add per boot. It exists because retention would otherwise let one guest push
//! everyone else's history out. It lives only in memory, so it starts again each boot (unresolved question 3).

/// What a service's `USING` or `USE_FAILED` gets.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Charge {
    /// Within the quota: append it.
    Allowed,
    /// The first one past the quota: record `QUOTA_REACHED` instead, and refuse.
    Reached,
    /// Refuse without recording anything: past the quota already, or the table is full.
    Refused,
}

/// Counts per `(interface, badge)`. `N` is how many grants it tracks across every service, and one more is
/// refused rather than evicting a count, which would reset someone's quota.
pub struct Quota<const N: usize> {
    entries: [(u8, u64, u32); N],
    len: usize,
    limit: u32,
}

impl<const N: usize> Quota<N> {
    pub fn new(limit: u32) -> Self {
        Self { entries: [(0, 0, 0); N], len: 0, limit }
    }

    pub fn charge(&mut self, interface: u8, badge: u64) -> Charge {
        let index = match self.entries[..self.len].iter().position(|&(i, b, _)| (i, b) == (interface, badge)) {
            Some(index) => index,
            None if self.len < N => {
                self.entries[self.len] = (interface, badge, 0);
                self.len += 1;
                self.len - 1
            }
            None => return Charge::Refused,
        };
        let count = &mut self.entries[index].2;
        let charge = match (*count).cmp(&self.limit) {
            core::cmp::Ordering::Less => Charge::Allowed,
            core::cmp::Ordering::Equal => Charge::Reached,
            core::cmp::Ordering::Greater => return Charge::Refused,
        };
        *count += 1;
        charge
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exactly_the_limit_is_allowed_then_one_reached_then_refused() {
        let mut quota = Quota::<4>::new(3);
        let charges: Vec<_> = (0..6).map(|_| quota.charge(1, 7)).collect();
        assert_eq!(
            charges,
            [Charge::Allowed, Charge::Allowed, Charge::Allowed, Charge::Reached, Charge::Refused, Charge::Refused]
        );
    }

    #[test]
    fn each_grant_has_its_own_count_and_the_same_badge_on_another_service_is_another_grant() {
        let mut quota = Quota::<4>::new(1);
        assert_eq!(quota.charge(1, 7), Charge::Allowed);
        assert_eq!(quota.charge(1, 7), Charge::Reached);
        assert_eq!(quota.charge(2, 7), Charge::Allowed);
        assert_eq!(quota.charge(1, 8), Charge::Allowed);
    }

    #[test]
    fn a_full_table_refuses_a_new_grant_and_keeps_the_old_counts() {
        let mut quota = Quota::<2>::new(1);
        quota.charge(1, 1);
        quota.charge(1, 2);
        assert_eq!(quota.charge(1, 3), Charge::Refused);
        assert_eq!(quota.charge(1, 1), Charge::Reached);
    }

    #[test]
    fn a_zero_limit_records_nothing_but_the_reach() {
        let mut quota = Quota::<1>::new(0);
        assert_eq!(quota.charge(1, 1), Charge::Reached);
        assert_eq!(quota.charge(1, 1), Charge::Refused);
    }
}
