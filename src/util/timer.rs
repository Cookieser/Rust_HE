#![allow(unused)]
use std::time::{Instant, Duration};


pub struct Timer {
    starts: Vec<Instant>,
    accumulated: Vec<Duration>,
    names: Vec<String>,
}

impl Timer {

    pub fn new() -> Self {
        Timer {
            starts: Vec::new(),
            accumulated: Vec::new(),
            names: Vec::new(),
        }
    }

    pub fn register(&mut self, name: &str) -> usize {
        self.starts.push(Instant::now());
        self.accumulated.push(Duration::new(0, 0));
        self.names.push(name.to_string());
        self.starts.len() - 1
    }

    pub fn tick(&mut self, index: usize) {
        let now = Instant::now();
        self.starts[index] = now;
    }

    pub fn tock(&mut self, index: usize) {
        let now = Instant::now();
        self.accumulated[index] += now.duration_since(self.starts[index]);
    }

    pub fn clear(&mut self) {
        self.starts.clear();
        self.accumulated.clear();
        self.names.clear();
    }

    pub fn gather(&self, average_time: usize) -> Vec<(String, Duration)> {
        let mut result = Vec::new();
        for (name, time) in self.names.iter().zip(self.accumulated.iter()) {
            result.push((name.clone(), (*time) / average_time.try_into().unwrap()));
        }
        result
    }

    pub fn print(&mut self, average_time: usize) {
        let result = self.gather(average_time);
        for (name, time) in result {
            // Print names with 20-chars width, time with 10 width. Both right-aligned
            println!("{:>20}: {:>10} μs", name, time.as_micros());
        }
        self.clear();
    }


}
