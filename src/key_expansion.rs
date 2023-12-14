use std::fmt::Display;

const ROUND_C: [u8; 10] = [
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

pub fn substitute_byte(byte: u8) -> u8 {
    AES_SBOX[byte as usize]
}

pub fn rotate(word : &[u8;4]) -> [u8;4]{
    //word.iter().cycle().skip(1).take(4).cloned().collect::<Vec<u8>>()
    //word.iter().enumerate().map(|(index , w)| word[index + 1 % 4]).take(4).collect()
    let mut rotate_w : [u8;4] = [0x00;4];//word.iter().enumerate().map(|(index , w)| word[index + 1 % 4]).take(4).collect();
    for i in 0..4{
        rotate_w[i] = word[(i+1 )% 4];
    }
    return rotate_w;
}

pub fn print_byte(my_vec :&Vec<u8>){
    for i in my_vec{
        print!("{:02x}", i);
    }
}

pub fn g_function(word: &[u8; 4], round_number: usize) -> [u8; 4] {

    let results = word
        .iter()
        .enumerate()
        .map(|(index, _)| AES_SBOX[word[(index + 1) % 4] as usize]);

    // create an array to place our results
    let mut g_word: [u8; 4] = Default::default();

    // enumerate over each result and populate the array
    for (i, result) in results.enumerate() {
        g_word[i] = result;
    }
    // println!("1.g_word =  {:?}", g_word);
    g_word[0] ^= &ROUND_C[round_number];
    // println!("2. g_word =  {:?}", g_word);
    return g_word;

}
pub fn xor (a : &[u8;4] , b :&[u8;4])-> [u8;4]{
    //let a_xor_b = a.iter().zip(b.iter()).map(||(x, y)| x ^ y);
    let mut a_xor_b : [u8; 4] = Default::default();
    for i in 0..4{
        a_xor_b[i] = a[i] ^ b[i];
    }
    return a_xor_b;
}
pub fn left_shift(k: &[u8; 16]) -> [u8; 16] {
    let mut k_shift: [u8; 16] = [0x00; 16];
    for (index, chunk) in k.chunks_exact(4).into_iter().enumerate() {
        let i = 4 * index;
        k_shift[i..i+4].copy_from_slice(& chunk.iter().cycle().skip(1).take(4).cloned().collect::<Vec<u8>>());
    }
    k_shift
}
pub fn split_words(word_16 : &[u8;16]) -> [[u8;4];4]{
    let result = word_16.chunks_exact(4);
    let mut word: [[u8; 4];4] = Default::default();
    for (i, result) in result.enumerate() {
        let word_temp:Result<[u8;4],_> = result.try_into();
        word[i] = match word_temp{
            Ok(array) => array,
            Err(_) => [0x0;4],
        };
    }
    return word;
}

pub fn key_expansion( key_init : &[u8;16])  -> [[u8;16];11]{
    let mut word :[[u8;4];44] = [[0;4];44];
    word[0..4].copy_from_slice(&split_words(key_init));
    for i in 0..10{
        word[4 * i + 4 ] = xor(&g_function(&word[4 * i + 3],i), &word[4 * i] );
        word[4 * i + 5] = xor(&word[4 * i + 4], &word[4 * i + 1] );
        word[4 * i + 6] = xor(&word[4 * i + 5], &word[4 * i + 2] );
        word[4 * i + 7] = xor(&word[4 * i + 6], &word[4 * i + 3] );
        // println!("word : {:?}", word);
        //round_iteration += 1;

    }
    let mut key  : [[u8;16];11] = [[0x00;16];11];
    print!("here");
    println!("{:?}", key);


    for z in 0..11{
        for i in 0..4{
            for j in 0..4{
                key[z][4 * i + j] = word[4 * z + i as usize][j];
               // println!("i :{i} j = {j} z = {z} , { }",4 * i +j);
            }
        }
    }
        // println!("{:?}", word);
    //println!("{:?}", key);

    return  key;

}
/*
pub fn main() {
    let key_init : [u8;16] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
    let key = key_expansion(&key_init);
    println!("extended_key : {:?}", key);
    let mut index = 1 ;
    for i in key{
        print_byte(&i.to_vec());
        match index % 8 {
            0 => println!("  "),
            4 => println!("  "),
            _ => (),
        }
        index += 1;
    }

}

 */

#[test]
pub fn key_expansion_test(){

    let key_expected = ["000102030405060708090a0b0c0d0e0f"
        , "d6aa74fdd2af72fadaa678f1d6ab76fe"
        , "b692cf0b643dbdf1be9bc5006830b3fe"
        , "b6ff744ed2c2c9bf6c590cbf0469bf41"
        , "47f7f7bc95353e03f96c32bcfd058dfd"
        , "3caaa3e8a99f9deb50f3af57adf622aa"
        , "5e390f7df7a69296a7553dc10aa31f6b"
        , "14f9701ae35fe28c440adf4d4ea9c026"
        , "47438735a41c65b9e016baf4aebf7ad2"
        , "549932d1f08557681093ed9cbe2c974e"
        , "13111d7fe3944a17f307a78b4d2b30c5"];
    let key_init : [u8;16] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
    let key = key_expansion(&key_init);
    println!("extended_key : {:?}", key);
    let mut index = 1 ;
    for i in key{
        print_byte(&i.to_vec());
        match index % 8 {
            0 => println!("  "),
            4 => println!("  "),
            _ => (),
        }
        index += 1;
    }


}