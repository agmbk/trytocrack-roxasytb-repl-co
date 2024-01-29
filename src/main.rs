//! Bruteforce optimized for performance, not best practices.

use std::fmt::Display;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::num::NonZeroUsize;

struct Bruteforce {
    username: StringGenerator,
    password: StringGenerator,
}

struct Credentials<'a> {
    username: &'a [u8],
    password: &'a [u8],
}

struct StringGenerator {
    /// A valid UTF-8 character set.
    chars: &'static [u8],
    /// The last character in the character set.
    last_char: u8,
    /// The first character in the character set.
    first_char: u8,
    /// The current value containing characters only from the given character set.
    value: Vec<u8>,
    /// The indexes of the characters in the character set for the current value.
    indexes: Vec<usize>,
    /// The minimum length of the generated string.
    min_length: usize,
    /// The maximum length of the generated string.
    max_length: usize,
    started: bool,
}

impl Bruteforce {
    fn new(chars: &'static [u8], min_length: NonZeroUsize, max_length: NonZeroUsize) -> Self {
        Self {
            username: StringGenerator::new(chars, min_length, max_length),
            password: StringGenerator::new(chars, min_length, max_length),
        }
    }

    fn run(&mut self, hash: i32) {
        let mut credentials: Credentials;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open("credentials.txt")
            .unwrap();

        let start = std::time::Instant::now();

        for iterations in 0usize.. {
            if self.password.next().is_some() {
                credentials = Credentials::new(&self.username.value, &self.password.value);
            } else if self.username.next().is_some() {
                self.password.reset();
                credentials = Credentials::new(&self.username.value, &self.password.value);
            } else {
                break;
            }

            if iterations % 100_000_000 == 0 {
                println!(
                    "Iterations: {} M/s | {}",
                    if start.elapsed().as_secs_f64() == 0.0 {
                        iterations
                    } else {
                        (iterations as f64 / start.elapsed().as_secs_f64()) as usize
                    } / 1_000_000,
                    credentials
                );
            }

            // Do not exit as there is many matches
            if credentials.verify(hash) {
                file.write_all(format!("{}\n", credentials).as_bytes())
                    .unwrap();
            }
        }
    }
}

impl<'a> Credentials<'a> {
    /// Username and password must be valid UTF-8 strings.
    fn new(username: &'a [u8], password: &'a [u8]) -> Self {
        Self { username, password }
    }

    fn verify(&self, hash: i32) -> bool {
        const USERNAME: &[u8; 9] = b"username=";
        const PASSWORD: &[u8; 10] = b"&password=";

        let computed_hash = USERNAME
            .iter()
            .chain(self.username)
            .chain(PASSWORD)
            .chain(self.password)
            .fold(0i32, |mut acc, byte| {
                acc = (acc << 0x5).wrapping_sub(acc).wrapping_add(*byte as i32);
                acc &= acc;
                acc
            });

        computed_hash == hash
    }
}

impl<'a> Display for Credentials<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("username: ")?;
        // The username is a known valid UTF-8 string.
        unsafe { f.write_str(std::str::from_utf8_unchecked(self.username))? };
        f.write_str(" password: ")?;
        // The password is a known valid UTF-8 string.
        unsafe { f.write_str(std::str::from_utf8_unchecked(self.password))? };
        Ok(())
    }
}

impl StringGenerator {
    fn new(chars: &'static [u8], min_length: NonZeroUsize, max_length: NonZeroUsize) -> Self {
        let min_length = min_length.get();
        let max_length = max_length.get();

        assert!(
            min_length <= max_length,
            "min_length must be less than or equal to max_length"
        );
        assert!(!chars.is_empty(), "chars must not be empty");

        let mut generator = Self {
            chars,
            last_char: *chars.last().unwrap(),
            first_char: *chars.first().unwrap(),
            value: Vec::with_capacity(max_length),
            indexes: Vec::with_capacity(max_length),
            min_length,
            max_length,
            started: false,
        };
        generator.reset();
        generator
    }

    fn reset(&mut self) {
        self.value.clear();
        self.value.extend(self.chars.iter().take(self.min_length));
        self.indexes.clear();
        self.indexes.extend(
            self.value
                .iter()
                .map(|&c| self.chars.iter().position(|&char| char == c).unwrap()),
        );
    }
}

impl Iterator for StringGenerator {
    type Item = ();

    fn next(&mut self) -> Option<Self::Item> {
        if !self.started {
            self.started = true;
            return Some(());
        }

        let mut i = self.value.len();
        while i > 0 {
            i -= 1;
            if self.value[i] == self.last_char {
                self.value[i] = self.first_char;
                self.indexes[i] = 0;
            } else {
                let idx = self.indexes[i] + 1;
                self.value[i] = self.chars[idx];
                self.indexes[i] = idx;
                return Some(());
            }
        }

        if self.value.len() < self.max_length {
            self.value.push(self.chars[0]);
            self.indexes.push(0);
            return Some(());
        }

        None
    }
}

impl Display for StringGenerator {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        // The value is a known valid UTF-8 string.
        unsafe { f.write_str(std::str::from_utf8_unchecked(&self.value)) }
    }
}

fn main() {
    const HASH: i32 = 1315459805;
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

    let mut generator = Bruteforce::new(
        CHARS,
        NonZeroUsize::new(1).unwrap(),
        NonZeroUsize::new(3).unwrap(),
    );

    let start = std::time::Instant::now();

    // Tests with length 3:
    // Time: 132912ms
    // Time: 128680ms
    // Time: 128196ms
    // Time: 81090ms
    // Time: 75682ms
    // Time: 58193ms
    // Time: 9974ms - With precomputed values, sadly it busts the stack fast enough
    // Time: 28973ms
    // Time: 26977ms - 5x improvement
    // Time: 26886ms
    // Time: 15511ms - 8x improvement
    generator.run(HASH);

    println!("Time: {}ms", start.elapsed().as_millis());
}

#[cfg(test)]
mod test {
    use std::num::NonZeroUsize;

    use super::{Credentials, StringGenerator};

    #[test]
    fn compute_hash() {
        const HASH: i32 = -1608160232;

        let credential = Credentials::new(b"foo", b"bar");

        assert!(credential.verify(HASH));
    }

    #[test]
    fn string_iterator() {
        let mut generator = StringGenerator::new(
            b"abc",
            NonZeroUsize::new(1).unwrap(),
            NonZeroUsize::new(3).unwrap(),
        );

        let expected = vec![
            "a", "b", "c", "aa", "ab", "ac", "ba", "bb", "bc", "ca", "cb", "cc", "aaa", "aab",
            "aac", "aba", "abb", "abc", "aca", "acb", "acc", "baa", "bab", "bac", "bba", "bbb",
            "bbc", "bca", "bcb", "bcc", "caa", "cab", "cac", "cba", "cbb", "cbc", "cca", "ccb",
            "ccc",
        ];

        let result = (0..39)
            .map(|_| {
                assert!(generator.next().is_some());
                generator.to_string()
            })
            .collect::<Vec<_>>();

        assert_eq!(result, expected);
        assert_eq!(generator.value, b"ccc");
        assert_eq!(generator.indexes, &[2, 2, 2]);
        assert!(generator.next().is_none());

        generator.reset();

        assert_eq!(generator.value, b"a");
        assert_eq!(generator.indexes, &[0]);
    }
}
