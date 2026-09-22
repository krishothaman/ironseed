//! ex04: ownership (who owns data) and borrowing (temporarily looking at it).
//! Security lessons: sums of attacker-supplied sizes can overflow (T14), and
//! Windows treats "A.TXT" and "a.txt" as the SAME file (T2).

use std::collections::HashSet;

/// Sum of all file lengths. BORROWS the slice. `None` on overflow.
pub fn total_len(file_lengths: &[u64]) -> Option<u64> {
    file_lengths
        .iter()
        .try_fold(0u64, |acc, &len| acc.checked_add(len))
}

/// The longest name, returned as a BORROW of the caller's data (no copy).
pub fn longest_name(names: &[String]) -> Option<&str> {
    names.iter().max_by_key(|n| n.len()).map(String::as_str)
}

/// True if two names differ only by upper/lower case.
pub fn has_case_collision(names: &[&str]) -> bool {
    let mut seen = HashSet::new();
    for name in names {
        if !seen.insert(name.to_lowercase()) {
            return true;
        }
    }
    false
}

/// TAKES OWNERSHIP of `name`, changes it in place, and gives it back.
pub fn normalize(mut name: String) -> String {
    name.make_ascii_lowercase();
    name
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sums_lengths() {
        assert_eq!(total_len(&[100, 200, 300]), Some(600));
        assert_eq!(total_len(&[]), Some(0));
    }

    #[test]
    fn t14_sum_overflow_is_caught() {
        assert_eq!(total_len(&[u64::MAX, 1]), None);
    }

    #[test]
    fn finds_longest_name() {
        let names = vec![
            "a.txt".to_string(),
            "movie.mkv".to_string(),
            "b".to_string(),
        ];
        assert_eq!(longest_name(&names), Some("movie.mkv"));
        assert_eq!(longest_name(&[]), None);
    }

    #[test]
    fn t2_detects_case_collision() {
        assert!(has_case_collision(&[
            "Readme.txt",
            "notes.txt",
            "README.TXT"
        ]));
        assert!(!has_case_collision(&["a.txt", "b.txt"]));
    }

    #[test]
    fn normalize_lowercases() {
        let owned = String::from("Ubuntu.ISO");
        let result = normalize(owned);
        // `owned` can't be used here any more: it was MOVED into normalize().
        assert_eq!(result, "ubuntu.iso");
    }
}
