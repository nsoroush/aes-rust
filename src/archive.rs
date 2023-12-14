//key = 000102030405060708090a0b0c0d0e0fd6aa74fdd2af72fadaa678f1d6ab76feb692cf0b643dbdf1be9bc5006830b3feb6ff744ed2c2c9bf6c590cbf0469bf4147f7f7bc95353e03f96c32bcfd058dfd3caaa3e8a99f9deb50f3af57adf622aa5e390f7df7a69296a7553dc10aa31f6b14f9701ae35fe28c440adf4d4ea9c02647438735a41c65b9e016baf4aebf7ad2549932d1f08557681093ed9cbe2c974e13111d7fe3944a17f307a78b4d2b30c5
//
// TEsting
/*let key = Key::from([
0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
0x0F,
]);
exp_key [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 214, 170, 116, 253, 210, 175, 114, 250, 218, 166, 120, 241, 214, 171, 118, 254, 182, 146, 207, 11, 100, 61, 189, 241, 190, 155, 197, 0, 104, 48, 179, 254, 182, 255, 116, 78, 210, 194, 201, 191, 108, 89, 12, 191, 4, 105, 191, 65, 71, 247, 247, 188, 149, 53, 62, 3, 249, 108, 50, 188, 253, 5, 141, 253, 60, 170, 163, 232, 169, 159, 157, 235, 80, 243, 175, 87, 173, 246, 34, 170, 94, 57, 15, 125, 247, 166, 146, 150, 167, 85, 61, 193, 10, 163, 31, 107, 20, 249, 112, 26, 227, 95, 226, 140, 68, 10, 223, 77, 78, 169, 192, 38, 71, 67, 135, 53, 164, 28, 101, 185, 224, 22, 186, 244, 174, 191, 122, 210, 84, 153, 50, 209, 240, 133, 87, 104, 16, 147, 237, 156, 190, 44, 151, 78, 19, 17, 29, 127, 227, 148, 74, 23, 243, 7, 167, 139, 77, 43, 48, 197]
expand_key = 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
    d7 a9 75 fa d2af72f2dba579fed6ab76297fde8cfbd0ac7e2075d580f6dea3a989002f5259ac51722c79d184f2da780df2f52a545ea458782775dc8afdfc73a668d627f8cc8e5fdfb952d5224521734a93068b861d59543f4f8c767a6eff3ce96874baf4312085bbbd56ffd5426a16bd36d0e28c165559314030124b9626af7d46c4236b139d122b238f59bd052024fbc1034fe85c1164cbd348d9cef36c220ff023ca53e100
    000102030405060708090a0b0c0d0e0f
    d6 aa 74 fd d2af72fadaa678f1d6ab76feb692cf0b643dbdf1be9bc5006830b3feb6ff744ed2c2c9bf6c590cbf0469bf4147f7f7bc95353e03f96c32bcfd058dfd3caaa3e8a99f9deb50f3af57adf622aa5e390f7df7a69296a7553dc10aa31f6b14f9701ae35fe28c440adf4d4ea9c02647438735a41c65b9e016baf4aebf7ad2549932d1f08557681093ed9cbe2c974e13111d7fe3944a17f307a78b4d2b30c5
    key_test = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 215, 169, 117, 250, 210, 175, 114, 242, 219, 165, 121, 254, 214, 171, 118, 41, 127, 222, 140, 251, 208, 172, 126, 32, 117, 213, 128, 246, 222, 163, 169, 137, 0, 47, 82, 89, 172, 81, 114, 44, 121, 209, 132, 242, 218, 120, 13, 242, 165, 69, 234, 69, 135, 130, 119, 93, 200, 175, 223, 199, 58, 102, 141, 98, 127, 140, 200, 229, 253, 191, 149, 45, 82, 36, 82, 23, 52, 169, 48, 104, 184, 97, 213, 149, 67, 244, 248, 199, 103, 122, 111, 255, 60, 233, 104, 116, 186, 244, 49, 32, 133, 187, 189, 86, 255, 213, 66, 106, 22, 189, 54, 208, 226, 140, 22, 85, 89, 49, 64, 3, 1, 36, 185, 98, 106, 175, 125, 70, 196, 35, 107, 19, 157, 18, 43, 35, 143, 89, 189, 5, 32, 36, 251, 193, 3, 79, 232, 92, 17, 100, 203, 211, 72, 217, 206, 243, 108, 34, 15, 240, 35, 202, 83, 225, 0]
0xd5
0xaa
0x74
0xfd

0xd6
0xaa
0x74
0xfd
 */

//

const AES_SBOX: [u8; 256] = [..];
fn g_function(word : &[u8;4], round_number : usize) -> [u8;4]{
    word.iter().enumerate().map(|(index , _)| AES_SBOX[&word[index + 1 % 4]]).take(4).collect()
    return word_r;
}






//use block_macro::Block;
use std::fmt::Display;

//use aes::{Aes256, BlockCipher, NewBlockCipher};

fn key_expansion(key: &[u8; 32]) -> [u8; 176] {
    let mut expanded_key: [u8; 176] = [0; 176];
    let mut current_size: usize = 0;

    // Copy the original key to the beginning of the expanded key
    expanded_key[..key.len()].clone_from_slice(key);
    current_size += key.len();

    while current_size < expanded_key.len() {
        // Copy the last 4 bytes of the expanded key to a temporary array
        let mut temp: [u8; 4] = [0; 4];
        temp.copy_from_slice(&expanded_key[current_size - 4..current_size]);

        // Perform Byte Substitution (S-Box) on the temporary array
        for byte in temp.iter_mut() {
            *byte = s_box(*byte);
        }

        // XOR the result with the corresponding round constant
        temp[0] ^= r_con_tlu((current_size / 16) as u8);

        // XOR the result with the 4 bytes (32 bits) before the temporary array
        for i in 0..temp.len() {
            expanded_key[current_size] = expanded_key[current_size - 16] ^ temp[i];
            current_size += 1;
        }
    }

    expanded_key
}

// Byte Substitution (S-Box)
fn s_box(byte: u8) -> u8 {
    // Your S-Box implementation here
    // Example: S_BOX[byte as usize]
    // Replace this with the actual S-Box lookup
    // For simplicity, you can create a lookup table or use the existing Rust AES library's S-Box
    // This is a placeholder implementation, and you should replace it with the correct S-Box lookup.
    byte
}

// Round Constants (R_CON) table lookup
fn r_con_tlu(round: u8) -> u8 {
    // Your R_CON table lookup implementation here
    // Example: R_CON[round as usize]
    // Replace this with the actual R_CON lookup
    // This is a placeholder implementation, and you should replace it with the correct R_CON lookup.
    round
}

const RCON: [u8; 10] = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
];

const AES_SBOX: [u8; 256] = [
    //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, //0
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, //1
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, //2
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, //3
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, //4
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, //5
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, //6
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, //7
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, //8
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, //9
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, //A
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, //B
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, //C
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, //D
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, //E
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 ]; //F


// Function to perform byte substitution using S-box
fn substitute_byte(byte: u8) -> u8 {
    AES_SBOX[byte as usize]
}

// Function to generate round constants


fn generate_round_constant(index: usize) -> [u8; 4] {
    let rcon_byte = AES_SBOX[index];
    [rcon_byte, 0x00, 0x00, (2u16.pow((index - 1) as u32) % 0x11Bu16) as u8]
}



fn g_function_old(word : &[u8;4], round_number : usize) -> [u8;4]{
    println!("here");
    // 1 left-shift
    let mut word_r : [u8;4]= rotate(&word);
    println!("1. {:?}", word_r);
    // substitutioan
    for i in 0..4{
        word_r[i ] = AES_SBOX[word_r[i] as usize];
    }

    println!("2. {:?}", word_r);
    // XOR xor the first byte  with round constant
    word_r[0] ^= &ROUND_C[round_number];
    println!("3. {:?}", word_r);
    return word_r;
}

// Example usage
fn main() {
    let original_byte: u8 = 0x00;
    let substituted_byte = substitute_byte(original_byte);
    println!("Original Byte: {:02X}", original_byte);
    println!("Substituted Byte: {:02X}", substituted_byte);

    for i in 1..11 {
        let round_constant = generate_round_constant(i);
        println!("Round {}: {:?}", i, round_constant);
    }
    let key: [u8; 32] = [0; 32]; // Replace with your actual key
    let expanded_key = key_expansion(&key);
}

