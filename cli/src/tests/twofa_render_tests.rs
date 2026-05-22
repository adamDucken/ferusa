#[cfg(test)]
mod tests {
    use crate::twofa::render::render_code_str;

    #[test]
    fn test_render_does_not_panic() {
        render_code_str("1234");
        render_code_str("9999");
        render_code_str("ABCD");
    }
}
