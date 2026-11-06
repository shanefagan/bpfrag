//! Stretches with nothing from the game's server while the game keeps
//! sending: a lost connection the game gets back. Deadlock, 2026-11-04 and
//! -06: ten seconds sending into nothing, a few in its menu, then a new
//! relay, about 20 seconds in all. The gap meter can't see these: the old
//! flow never comes back, so its gap never ends, and the new one starts
//! fresh.

/// Readings in a row of sending with nothing received that start one.
/// Loading a map stops both directions, so it never counts.
pub const SILENT_MIN: u32 = 3;

#[derive(Debug, Default)]
pub struct Silence {
    /// Readings in a row sending with nothing received, and when the
    /// first of them was.
    run: u32,
    run_start: f64,
    /// A silence under way since this time.
    open: Option<f64>,
    count: u32,
    longest: f64,
}

impl Silence {
    /// One reading at `t` seconds: the game's UDP packets a second out and
    /// in (loopback included), and those in from outside (None without the
    /// meter). Returns a silence's length when it ends with the server's
    /// packets coming back.
    pub fn step(&mut self, t: f64, tx: f64, rx: f64, outside_rx: Option<f64>) -> Option<f64> {
        if let Some(start) = self.open {
            // the game's menu over loopback, between losing a server and
            // finding the next, is part of it
            if outside_rx.map_or(rx > 0.0, |o| o > 0.0) {
                self.open = None;
                self.run = 0;
                let d = t - start;
                self.count += 1;
                self.longest = self.longest.max(d);
                return Some(d);
            }
            return None;
        }
        if tx > 0.0 && rx <= 0.0 {
            if self.run == 0 {
                self.run_start = t;
            }
            self.run += 1;
            if self.run >= SILENT_MIN {
                self.open = Some(self.run_start);
            }
        } else {
            self.run = 0;
        }
        None
    }

    /// Silences that ended this match.
    pub fn count(&self) -> u32 {
        self.count
    }

    /// The longest of them, in seconds.
    pub fn longest(&self) -> f64 {
        self.longest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// (tx, rx, outside rx) a second from t = 0
    fn run(s: &mut Silence, rows: &[(f64, f64, f64)]) -> Vec<f64> {
        rows.iter()
            .enumerate()
            .filter_map(|(i, &(tx, rx, o))| s.step(i as f64, tx, rx, Some(o)))
            .collect()
    }

    #[test]
    fn a_lost_server_counts_through_the_menu_until_it_comes_back() {
        // 2026-11-06 19:42: play, 10 s sending into nothing, 5 s of the
        // menu over loopback, 4 s more, then a new relay
        let mut rows = vec![(64.0, 140.0, 140.0); 5];
        rows.extend([(15.0, 0.0, 0.0); 10]);
        rows.extend([(128.0, 128.0, 0.0); 5]);
        rows.extend([(15.0, 0.0, 0.0); 4]);
        rows.extend([(64.0, 150.0, 150.0); 5]);
        let mut s = Silence::default();
        assert_eq!(run(&mut s, &rows), vec![19.0]);
        assert_eq!((s.count(), s.longest()), (1, 19.0));
    }

    #[test]
    fn loading_and_short_gaps_dont_count() {
        let mut s = Silence::default();
        let mut rows = vec![(64.0, 140.0, 140.0); 3];
        // a map load stops both directions
        rows.extend([(0.0, 0.0, 0.0); 6]);
        rows.extend([(64.0, 140.0, 140.0); 3]);
        // two seconds sending into nothing
        rows.extend([(64.0, 0.0, 0.0); 2]);
        rows.extend([(64.0, 140.0, 140.0); 3]);
        assert!(run(&mut s, &rows).is_empty());
        assert_eq!(s.count(), 0);
    }

    #[test]
    fn a_match_that_ends_silent_has_nothing_to_report() {
        let mut s = Silence::default();
        let mut rows = vec![(64.0, 140.0, 140.0); 3];
        rows.extend([(15.0, 0.0, 0.0); 10]);
        assert!(run(&mut s, &rows).is_empty());
        assert_eq!(s.count(), 0);
    }
}
