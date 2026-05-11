// --- 2FA BLOCK RENDER MODULE ---
//
// Usage:
//   render_code(7036);
//   render_code_str("7036");
//
// No dependencies. Pure terminal rendering.

pub fn render_code(code: u32) {
    render_code_str(&code.to_string());
}

pub fn render_code_str(code: &str) {
    let scale = 1; // tweak if needed

    println!();
    // println!("2FA code:\n");

    render(code, scale);

    println!();
}

// 5x5 bitmap digits
const DIGITS: [[[u8; 5]; 5]; 10] = [
    [
        [1, 1, 1, 1, 1],
        [1, 0, 0, 0, 1],
        [1, 0, 0, 0, 1],
        [1, 0, 0, 0, 1],
        [1, 1, 1, 1, 1],
    ], // 0
    [
        [0, 0, 1, 0, 0],
        [0, 1, 1, 0, 0],
        [0, 0, 1, 0, 0],
        [0, 0, 1, 0, 0],
        [0, 1, 1, 1, 0],
    ], // 1
    [
        [1, 1, 1, 1, 1],
        [0, 0, 0, 0, 1],
        [1, 1, 1, 1, 1],
        [1, 0, 0, 0, 0],
        [1, 1, 1, 1, 1],
    ], // 2
    [
        [1, 1, 1, 1, 1],
        [0, 0, 0, 0, 1],
        [0, 1, 1, 1, 1],
        [0, 0, 0, 0, 1],
        [1, 1, 1, 1, 1],
    ], // 3
    [
        [1, 0, 0, 1, 0],
        [1, 0, 0, 1, 0],
        [1, 1, 1, 1, 1],
        [0, 0, 0, 1, 0],
        [0, 0, 0, 1, 0],
    ], // 4
    [
        [1, 1, 1, 1, 1],
        [1, 0, 0, 0, 0],
        [1, 1, 1, 1, 1],
        [0, 0, 0, 0, 1],
        [1, 1, 1, 1, 1],
    ], // 5
    [
        [1, 1, 1, 1, 1],
        [1, 0, 0, 0, 0],
        [1, 1, 1, 1, 1],
        [1, 0, 0, 0, 1],
        [1, 1, 1, 1, 1],
    ], // 6
    [
        [1, 1, 1, 1, 1],
        [0, 0, 0, 0, 1],
        [0, 0, 0, 1, 0],
        [0, 0, 1, 0, 0],
        [0, 1, 0, 0, 0],
    ], // 7
    [
        [1, 1, 1, 1, 1],
        [1, 0, 0, 0, 1],
        [1, 1, 1, 1, 1],
        [1, 0, 0, 0, 1],
        [1, 1, 1, 1, 1],
    ], // 8
    [
        [1, 1, 1, 1, 1],
        [1, 0, 0, 0, 1],
        [1, 1, 1, 1, 1],
        [0, 0, 0, 0, 1],
        [1, 1, 1, 1, 1],
    ], // 9
];

fn render(code: &str, scale: usize) {
    let on = "██";
    let off = "  ";

    for row in 0..5 {
        for _ in 0..scale {
            for ch in code.chars() {
                let digit = match ch.to_digit(10) {
                    Some(d) => d as usize,
                    None => continue,
                };

                for col in 0..5 {
                    let pixel = DIGITS[digit][row][col];
                    let symbol = if pixel == 1 { on } else { off };

                    for _ in 0..scale {
                        print!("{}", symbol);
                    }
                }

                print!("  ");
            }
            println!();
        }
    }
}
