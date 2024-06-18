//! Provide performance testing utilities.


const PROMPT_LENGTH: usize = 15;

/// Format and print communication. The `name` is a string put before the colon. The `tabs * 2` are how many spaces to put before prompt.
/// If `div > 1`, will print an "average comm" and a "total comm".
#[allow(dead_code)]
pub fn print_communication(name: &str, tabs: usize, bytes: usize, div: usize) {
    // print spaces = tabs * 2
    for _ in 0..tabs {
        print!("  ");
    }
    // print prompt
    print!("{}", name);
    // fill spaces
    if PROMPT_LENGTH > name.len() + tabs * 2 {
        for _ in 0..(PROMPT_LENGTH - name.len() - tabs * 2) {
            print!(" ");
        }
    }
    if bytes / div <= 4 {
        let bits = bytes as f64 * 8.0 / div as f64;
        print!(": {:>9.3} bt", bits);
    } else if bytes / div < 1024 {
        print!(": {:>9.3} B ", bytes / div);
    } else if bytes / div < 1024 * 1024 {
        print!(": {:>9.3} KB", bytes as f64 / 1024.0 / div as f64);
    } else {
        print!(": {:>9.3} MB", bytes as f64 / 1024.0 / 1024.0 / div as f64);
    }
    if div > 1 {
        if bytes <= 4 {
            let bits = bytes * 8;
            print!(" (total {:>9} bt", bits);
        } else if bytes < 1024 {
            print!(" (total {:>9} B ", bytes);
        } else if bytes < 1024 * 1024 {
            print!(" (total {:>9.3} KB", bytes as f64 / 1024.0);
        } else {
            print!(" (total {:>9.3} MB", bytes as f64 / 1024.0 / 1024.0);
        }
        print!(", {} times)", div);
    }
    println!();
}

/// Format and print time. The `prompt` is a string put before the colon. The `tabs * 2` are how many spaces to put before prompt.
/// If `div > 1`, will print an "average time" and a "total time".
pub fn print_time(prompt: &str, tabs: usize, total_time: std::time::Duration, div: usize) {
    let time = total_time / (div as u32);
    // print spaces = tabs * 2
    for _ in 0..tabs {
        print!("  ");
    }
    // print prompt
    print!("{}", prompt);
    // fill spaces
    if PROMPT_LENGTH > prompt.len() + tabs * 2 {
        for _ in 0..(PROMPT_LENGTH - prompt.len() - tabs * 2) {
            print!(" ");
        }
    }
    if time <= std::time::Duration::new(0, 1000) {
        print!(": {:>9} ns", time.as_nanos());
    } else if time <= std::time::Duration::new(0, 1000000) {
        print!(": {:>9.3} us", time.as_nanos() as f64 / 1000.0);
    } else if time <= std::time::Duration::new(0, 1000000000) {
        print!(": {:>9.3} ms", time.as_micros() as f64 / 1000.0);
    } else {
        print!(": {:>9.3} s ", time.as_millis() as f64 / 1000.0);
    }
    if div > 1 {
        let time = total_time;
        if time <= std::time::Duration::new(0, 1000) {
            print!(" (total {:>9} ns", time.as_nanos());
        } else if time <= std::time::Duration::new(0, 1000000) {
            print!(" (total {:>9.3} us", time.as_nanos() as f64 / 1000.0);
        } else if time <= std::time::Duration::new(0, 1000000000) {
            print!(" (total {:>9.3} ms", time.as_micros() as f64 / 1000.0);
        } else {
            print!(" (total {:>9.3} s ", time.as_millis() as f64 / 1000.0);
        }
        print!(", {} times)", div);
    } 
    println!();
}

/// A utility struct that allows tracking multiple timers.
/// 
/// The user needs to register a timer with [`Timer::register`] to get a handle.
/// After that, the user could use [`Timer::tick`] and [`Timer::tock`] to measure a time interval.
/// The interval is accumulated between the pair of calls. Finally, the user could use [`Timer::print`]
/// or [`Timer::print_div`] to print the accumulated time or averaged time.
/// The user could use [`Timer::clear`] to clear all timers.
#[allow(dead_code)]
pub struct Timer {
    start: Vec<std::time::Instant>,
    accumulated: Vec<std::time::Duration>,
    name: Vec<String>,
    tabs: usize,
}
impl Default for Timer {
    fn default() -> Self {
        Self::new()
    }
}

impl Timer {
    /// Create a new timer.
    pub fn new() -> Self {
        Self {
            start: vec![],
            accumulated: vec![],
            name: vec![],
            tabs: 0,
        }
    }
    /// Set the tabs of the timer. See [`print_time`] method for more information.
    pub fn tabs(self, tabs: usize) -> Self {
        Self {
            start: self.start,
            accumulated: self.accumulated,
            name: self.name,
            tabs,
        }
    }
    /// Register a timer with a name. Returns a handle to be used with [`Timer::tick`] and [`Timer::tock`].
    /// Note that when you register, a [`Timer::tick`] is automatically called. Therefore, if you need only
    /// record one interval, you could directly call [`Timer::tock`] after [`Timer::register`].
    pub fn register(&mut self, name: &str) -> usize {
        self.start.push(std::time::Instant::now());
        self.accumulated.push(std::time::Duration::new(0, 0));
        self.name.push(name.to_string());
        self.start.len() - 1
    }
    /// Starts the timer with the given handle.
    pub fn tick(&mut self, index: usize) {
        self.start[index] = std::time::Instant::now();
    }
    /// Stops the timer with the given handle. The time interval from the previous call of [`Timer::tick`] is accumulated.
    pub fn tock(&mut self, index: usize) {
        self.accumulated[index] += self.start[index].elapsed();
    }
    /// Print the accumulated time of all timers.
    pub fn print(&self) {
        for i in 0..self.start.len() {
            let acc = &self.accumulated[i];
            print_time(&self.name[i], self.tabs, *acc, 1);
        }
    }
    /// Print the accumulated time of all timers, divided by `div` (averaged time).
    pub fn print_div(&self, div: usize) {
        for i in 0..self.start.len() {
            let acc = self.accumulated[i];
            print_time(&self.name[i], self.tabs, acc, div);
        }
    }
    /// Clear all timers. Semantically equivalent to creating a new timer.
    pub fn clear(&mut self) {
        self.start.clear();
        self.accumulated.clear();
        self.name.clear();
    }
}

/// A utility struct that allows tracking a single timer.
/// 
/// This is similar to [`Timer`] because you could call [`TimerSingle::tick`] and [`TimerSingle::tock`] multiple times.
/// But it tracks only one timer. The name of the timer is only needed when printing.
#[allow(dead_code)]
pub struct TimerSingle {
    start: std::time::Instant,
    accumulated: std::time::Duration,
    tabs: usize,
}

impl Default for TimerSingle {
    fn default() -> Self {
        Self::new()
    }
}
#[allow(dead_code)]

impl TimerSingle {
    /// Create a new timer.
    /// Note that when you create, a [`TimerSingle::tick`] is automatically called. Therefore, if you need only
    /// record one interval, you could directly call [`TimerSingle::tock`] after creation.
    pub fn new() -> Self {
        Self {
            start: std::time::Instant::now(),
            accumulated: std::time::Duration::new(0, 0),
            tabs: 0,
        }
    }
    /// Set the tabs of the timer. See [`print_time`] method for more information.
    pub fn tabs(self, tabs: usize) -> Self {
        Self {
            start: self.start,
            accumulated: self.accumulated,
            tabs: tabs,
        }
    }
    /// Starts the timer.
    pub fn tick(&mut self) {
        self.start = std::time::Instant::now();
    }
    /// Stops the timer. The time interval from the previous call of [`TimerSingle::tick`] is accumulated.
    pub fn tock(&mut self) {
        self.accumulated += self.start.elapsed();
    }
    /// Print the accumulated time of the timer.
    pub fn print(&self, name: &str) {
        let acc = &self.accumulated;
        print_time(name, self.tabs, *acc, 1);
    }
    /// This is simply a combination of [`TimerSingle::tock`] and [`TimerSingle::print`].
    /// Useful if you need only record one interval.
    pub fn finish(mut self, name: &str) {
        self.tock();
        self.print(name);
    }
    /// Print the accumulated time of the timer, divided by `div` (averaged time).
    pub fn print_div(&self, name: &str, div: usize) {
        let acc = self.accumulated;
        print_time(name, self.tabs, acc, div);
    }
}

/// A utility struct that allows measuing a time interval.
/// 
/// User simply creates a new [`TimerOnce`] and calls [`TimerOnce::finish`] (or [`TimerOnce::finish_div`]) to print the time interval or averaged time interval
#[allow(dead_code)]
pub struct TimerOnce {
    start: std::time::Instant,
    tabs: usize,
}
#[allow(dead_code)]

impl Default for TimerOnce {
    fn default() -> Self {
        Self::new()
    }
}
#[allow(dead_code)]
impl TimerOnce {
    /// Create a new timer.
    pub fn new() -> Self {
        Self {
            start: std::time::Instant::now(),
            tabs: 0,
        }
    }
    /// Set the tabs of the timer. See [`print_time`] method for more information.
    pub fn tabs(self, tabs: usize) -> Self {
        Self {
            start: self.start,
            tabs: tabs,
        }
    }
    /// Print the time interval.
    pub fn finish(self, prompt: &str) -> std::time::Duration {
        let elapsed = self.start.elapsed();
        print_time(prompt, self.tabs, elapsed, 1);
        elapsed
    }
    /// Print the averaged time interval.
    pub fn finish_div(self, prompt: &str, div: usize) {
        let elapsed = self.start.elapsed();
        print_time(prompt, self.tabs, elapsed, div);
    }
    /// Get the time duration
    pub fn elapsed(&self) -> std::time::Duration {
        self.start.elapsed()
    }
}