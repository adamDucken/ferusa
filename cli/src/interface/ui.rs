use std::io::{self, Write};

pub fn execute(msg: &str) {
    println!("\x1b[1mexecute:\x1b[0m {}", msg);
    io::stdout().flush().ok();
}

pub fn success(msg: &str) {
    println!("\x1b[1;32msuccess:\x1b[0m {}", msg);
    io::stdout().flush().ok();
}

pub fn failed(msg: &str) {
    println!("\x1b[1;31mfailed:\x1b[0m  {}", msg);
    io::stdout().flush().ok();
}

pub fn warn(msg: &str) {
    println!("\x1b[1;33mwarn:\x1b[0m {}", msg);
    io::stdout().flush().ok();
}

pub fn info(msg: &str) {
    println!("\x1b[1minfo:\x1b[0m {}", msg);
    // println!("        {}", msg);
    io::stdout().flush().ok();
}

pub fn input(msg: &str) {
    println!("\x1b[1minput:\x1b[0m {}", msg);
    io::stdout().flush().ok();
}
