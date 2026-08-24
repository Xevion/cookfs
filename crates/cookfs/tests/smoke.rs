//! Proves the integration-test harness links and that `rstest` and `proptest` are wired up.

use assert2::check;
use proptest::prelude::*;
use rstest::rstest;

#[rstest]
#[case(0)]
#[case(1)]
#[case(u64::from(u32::MAX))]
fn page_offsets_fit_in_usize(#[case] offset: u64) {
    check!(usize::try_from(offset).is_ok());
}

proptest! {
    #[test]
    fn usize_offsets_round_trip_through_u64(offset: usize) {
        prop_assert_eq!(usize::try_from(offset as u64), Ok(offset));
    }
}
