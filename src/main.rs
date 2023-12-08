use std::fmt::Display;
use std::fs::OpenOptions;
use std::io::Write;
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
        self.username.init();
        self.password.init();

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
                println!("Failed to find credentials");
                break;
            }

            if iterations % 100_000_000 == 0 {
                println!(
                    "Iterations: {} M/s | {}",
                    if start.elapsed().as_secs() == 0 {
                        iterations / 1_000_000
                    } else {
                        iterations / start.elapsed().as_secs() as usize / 1_000_000
                    },
                    credentials
                );
            }

            // Do not exit as there is many matches
            if credentials.verify(hash) {
                file.write_all(credentials.to_string().as_bytes()).unwrap();
            }
        }
    }
}

impl<'a> Credentials<'a> {
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
        write!(f, "username: ")?;
        for char in self.username {
            write!(f, "{}", *char as char)?;
        }
        write!(f, " password: ")?;
        for char in self.password {
            write!(f, "{}", *char as char)?;
        }
        Ok(())
    }
}

impl StringGenerator {
    fn new(chars: &'static [u8], min_length: NonZeroUsize, max_length: NonZeroUsize) -> Self {
        if min_length.get() > max_length.get() {
            panic!("min_length must be less than or equal to max_length");
        }
        if chars.is_empty() {
            panic!("chars must not be empty");
        }

        let min_length = min_length.get();
        let max_length = max_length.get();

        Self {
            chars,
            last_char: *chars.last().unwrap(),
            first_char: *chars.first().unwrap(),
            value: Vec::with_capacity(max_length),
            min_length,
            max_length,
            started: false,
        }
    }

    fn init(&mut self) {
        self.reset();
    }

    fn reset(&mut self) {
        self.value.clear();
        self.value.extend(self.chars.iter().take(self.min_length));
    }
}

impl Iterator for StringGenerator {
    type Item = ();

    fn next(&mut self) -> Option<Self::Item> {
        if !self.started {
            self.started = true;
            return Some(());
        }

        for i in (0..self.value.len()).rev() {
            if self.value[i] == self.last_char {
                self.value[i] = self.first_char;
            } else {
                let idx = {
                    let char = self.value[i];
                    self.chars.iter().position(|&c| c == char).unwrap()
                };
                self.value[i] = self.chars[idx + 1];
                return Some(());
            }
        }

        if self.value.len() < self.max_length {
            self.value.push(self.chars[0]);
            return Some(());
        }

        None
    }
}

impl Display for StringGenerator {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for char in &self.value {
            write!(f, "{}", *char as char)?;
        }
        Ok(())
    }
}

fn main() {
    const HASH: i32 = 1315459805;
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

    let mut generator = Bruteforce::new(
        CHARS,
        NonZeroUsize::new(1).unwrap(),
        NonZeroUsize::new(6).unwrap(),
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
    generator.run(HASH);

    println!("Time: {}ms", start.elapsed().as_millis());
}

#[test]
fn compute_hash() {
    const HASH: i32 = -1608160232;

    let credential = Credentials::new(b"foo", b"bar");

    assert!(credential.verify(HASH));
}
