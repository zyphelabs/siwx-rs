pub fn generate_mock_hex_string(length: usize, hex_number: u8, with_prefix: bool) -> String {
    let hex_char = format!("{:02X}", hex_number);
    if with_prefix {
        "0x".to_string() + &hex_char.repeat(length)
    } else {
        hex_char.repeat(length)
    }
}
