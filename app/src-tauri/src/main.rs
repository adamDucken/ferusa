#[cfg(target_os = "android")]
fn main() {
    ferusa_lib::run();
}

#[cfg(not(target_os = "android"))]
fn main() {}
