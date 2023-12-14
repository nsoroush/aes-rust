mod key_expansion;
use key_expansion::*;

use hex::FromHex;


use itertools::iproduct;

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
const AES_SBOX_INV :[u8; 256] =[
       //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
        0x52, 0x9, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0xb, 0x42, 0xfa, 0xc3, 0x4e,
        0x8, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x0, 0x8c, 0xbc, 0xd3, 0xa, 0xf7, 0xe4, 0x58, 0x5, 0xb8, 0xb3, 0x45, 0x6,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0xf, 0x2, 0xc1, 0xaf, 0xbd, 0x3, 0x1, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0xe, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x7, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0xd, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x4, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0xc, 0x7d
    ];

#[derive(Debug)]
pub struct State([[u8; 4]; 4]);

impl State {
    pub fn new() -> State{
        State([[0x00; 4]; 4])
    }
    pub fn from(input: [u8; 16]) -> State {
        let mut state = State([[0; 4]; 4]);

       // println!(" the state");

        for i in 0..4 {
            for j in 0..4 {
                state.0[i][j] = input[i * 4 + j];
               // print!("{:0x} ", state.0[i][j]);
            }
            //println!(" ");
        }


        state
    }

    pub fn get(&self, row: usize, col: usize) -> u8 {
        //self.0.get(row).and_then(|r| r.get(col))
        self.0[row][col]
    }

    pub fn sub_bytes(&mut self) {

        let mut sub_state = State::new();
        for (i, j) in iproduct!(0..4, 0..4) {
            //println!("i: {}, j: {}", i, j);
           // println!("{}",self.get(i,j) as usize);
            self.0[i][j] = AES_SBOX[self.get(i,j) as usize];
        }
        //return sub_state;
    }
    pub fn sub_bytes_inv(&mut self) {

        let mut sub_state = State::new();
        for (i, j) in iproduct!(0..4, 0..4) {
            //println!("i: {}, j: {}", i, j);
            // println!("{}",self.get(i,j) as usize);
            self.0[i][j] = AES_SBOX_INV[self.get(i,j) as usize];
        }
        //return sub_state;
    }
    pub fn print(&self, name : &str){
        println!("\n{}: ", name);
        for row in self.0.iter() {
            for &byte in row.iter() {
                print!("{:02x} ", byte);
            }

        }
        print!("\n");
    }
    fn shift_rows(&mut self) {

         let mut b = self.0[0][1];
         self.0[0][1] = self.0[1][1];
         self.0[1][1] = self.0[2][1];
         self.0[2][1] = self.0[3][1];
         self.0[3][1] = b;

         b = self.0[0][2];
         let d = self.0[1][2];
         self.0[0][2] = self.0[2][2];
         self.0[1][2] = self.0[3][2];
         self.0[3][2] = d;
         self.0[2][2] = b;

         b = self.0[0][3];
         self.0[0][3] = self.0[3][3];
         self.0[3][3] = self.0[2][3];
         self.0[2][3] = self.0[1][3];
         self.0[1][3] = b;

/*

         let mut j = 0;
         for i in 1..4 {
             let b = self.0[0][i];
             self.0[0][i] = self.0[(1 + j) % 3 as usize][i];
             self.0[1][i] = self.0[(2 + j) % 3 as usize][i];
             self.0[2][i] = self.0[(3 + j) % 3 as usize][i];
             self.0[3][i] = b;
             println!("         i = {i}, {:0x}",b);
             j += 1;}

             /*
        // Row 1: Shift left by 1 position

        self.0[1].rotate_left(1);

        // Row 2: Shift left by 2 positions
        self.0[2].rotate_left(2);

        // Row 3: Shift left by 3 positions
        self.0[3].rotate_left(3);

         */

 */}
    fn shift_rows_inv(&mut self) {
        let mut b = self.0[3][1];
        self.0[3][1] = self.0[2][1];
        self.0[2][1] = self.0[1][1];
        self.0[1][1] = self.0[0][1];
        self.0[0][1] = b;


        b = self.0[0][2];
        let d = self.0[1][2];
        self.0[0][2] = self.0[2][2];
        self.0[1][2] = self.0[3][2];
        self.0[3][2] = d;
        self.0[2][2] = b;

        b = self.0[0][3];
        self.0[0][3] = self.0[1][3];
        self.0[1][3] = self.0[2][3];
        self.0[2][3] = self.0[3][3];
        self.0[3][3] = b;
    }

    fn mix_columns(&mut self) {
        for i in 0..4 {
            /*let a0 = self.0[0][i];
            let a1 = self.0[1][i];
            let a2 = self.0[2][i];
            let a3 = self.0[3][i];

             */

            let a0 = self.0[i][0];
            let a1 = self.0[i][1];
            let a2 = self.0[i][2];
            let a3 = self.0[i][3];

            self.0[i][0] = multiplication_gf(0x02, a0) ^ multiplication_gf(0x03, a1) ^ a2 ^ a3;
            self.0[i][1] = a0 ^ multiplication_gf(0x02, a1) ^ multiplication_gf(0x03, a2) ^ a3;
            self.0[i][2]= a0 ^ a1 ^ multiplication_gf(0x02, a2) ^ multiplication_gf(0x03, a3);
            self.0[i][3] = multiplication_gf(0x03, a0) ^ a1 ^ a2 ^ multiplication_gf(0x02, a3);
        }
    }
    // Inverse MixColumns operation


    fn inv_mix_column_0(&mut self) {
        for i in 0..4 {
            let a0 = self.0[i][0];
            let a1 = self.0[i][1];
            let a2 = self.0[i][2];
            let a3 = self.0[i][3];

            self.0[i][0] = multiplication_gf(a0, 0x0e) ^ multiplication_gf(a3, 0x0b) ^ multiplication_gf(a2, 0x0d) ^ multiplication_gf(a1, 0x09);
            self.0[i][1] = multiplication_gf(a1, 0x0e) ^ multiplication_gf(a0, 0x0b) ^ multiplication_gf(a3, 0x0d) ^ multiplication_gf(a2, 0x09);
            self.0[i][2] = multiplication_gf(a2, 0x0e) ^ multiplication_gf(a1, 0x0b) ^ multiplication_gf(a0, 0x0d) ^ multiplication_gf(a3, 0x09);
            self.0[i][3] = multiplication_gf(a3, 0x0e) ^ multiplication_gf(a2, 0x0b) ^ multiplication_gf(a1, 0x0d) ^ multiplication_gf(a0, 0x09);
        }
    }
    fn mix_columns_inv(&mut self) {
        for i in 0..4 {
            let a0 = self.0[i][0];
            let a1 = self.0[i][1];
            let a2 = self.0[i][2];
            let a3 = self.0[i][3];

            self.0[i][0] = multiplication_gf(0x0e, a0) ^ multiplication_gf(0x0b, a1) ^ multiplication_gf(0x0d, a2) ^ multiplication_gf(0x09, a3);
            self.0[i][1] = multiplication_gf(0x09, a0) ^ multiplication_gf(0x0e, a1) ^ multiplication_gf(0x0b, a2) ^ multiplication_gf(0x0d, a3);
            self.0[i][2] = multiplication_gf(0x0d, a0) ^ multiplication_gf(0x09, a1) ^ multiplication_gf(0x0e, a2) ^ multiplication_gf(0x0b, a3);
            self.0[i][3] = multiplication_gf(0x0b, a0) ^ multiplication_gf(0x0d, a1) ^ multiplication_gf(0x09, a2) ^ multiplication_gf(0x0e, a3);
        }
    }
    pub fn to_hex_string(&self) -> String {
        let mut hex_string = String::new();

        for row in &self.0 {
            for &byte in row {
                hex_string.push_str(&format!("{:02X} ", byte));
            }
        }

        hex_string.trim().to_string()
    }

}

/*
    // Row 1: Shift left by 1 position
    state.0[1].rotate_left(1);

    // Row 2: Shift left by 2 positions
    state.0[2].rotate_left(2);

    // Row 3: Shift left by 3 positions
    state.0[3].rotate_left(3);

 */

fn print_state(state: &State, name: &str) {
    println!("{}",name);
    for row in state.0.iter() {
        for &byte in row.iter() {
            print!("{:02x} ", byte);
        }
        println!();
    }
}
fn s_box() -> [[u8;16];16] {
    let mut s_box : [[u8;16];16] = [[0x00;16];16];
    for (x, y) in iproduct!(0..16, 0..16){
        s_box[x][y] = AES_SBOX[16 * x + y ];
        //print!("{:0x}, ", s_box[x][y]);
        if y == 15{
           // println!(" ");
        }
    }
    return s_box;

}

fn s_box_inv() -> [[u8;16];16] {
        let s_box : [[u8;16];16] = s_box();
        let mut s_box_inv: [[u8;16];16]  = [[0x00;16];16];
        for (x, y) in iproduct!(0..16, 0..16){
            let b = s_box[x][y] % 16 ;
            let a = s_box[x][y] / 16 ;
            s_box_inv[a as usize][b as usize]  = (16 * x + y) as u8 ;
            //print!("{:0x}, ", s_box_inv[a as usize][b as usize]);
            //println!("x = {} , y = {}, s(x, y ) = {:0x}, a= {:0x} , b = {:0x}", x,y, s_box[x][y], s_box_inv[a as usize][b as usize], b);
            //if y == 15{
                //println!(" ");
            //}
        }
        return s_box_inv;

}

// MixColumns operation
fn mix_columns(state: &mut State) {
    for i in 0..4 {
        let a0 = state.0[0][i];
        let a1 = state.0[1][i];
        let a2 = state.0[2][i];
        let a3 = state.0[3][i];

        state.0[0][i] = multiplication_gf(0x02, a0) ^ multiplication_gf(0x03, a1) ^ a2 ^ a3;
        state.0[1][i] = a0 ^ multiplication_gf(0x02, a1) ^ multiplication_gf(0x03, a2) ^ a3;
        state.0[2][i] = a0 ^ a1 ^ multiplication_gf(0x02, a2) ^ multiplication_gf(0x03, a3);
        state.0[3][i] = multiplication_gf(0x03, a0) ^ a1 ^ a2 ^ multiplication_gf(0x02, a3);
    }
}

pub fn add_round_key(state :&mut State, round_key: &[u8; 16]) {
    for i in 0..4 {
        for j in 0..4 {
            state.0[i][j] ^= round_key[4 * i + j];
        }
    }
}

/*fn mix_columns(state: &mut State) {
    let mut tmp = [0; 4];

    for i in 0..4 {
        tmp[0] = gf_mult(state.0[i], 0x02) ^ gf_mult(state[4 + i], 0x03) ^ state[8 + i] ^ state[12 + i];
        tmp[1] = state[i] ^ gf_mult(state[4 + i], 0x02) ^ gf_mult(state[8 + i], 0x03) ^ state[12 + i];
        tmp[2] = state[i] ^ state[4 + i] ^ gf_mult(state[8 + i], 0x02) ^ gf_mult(state[12 + i], 0x03);
        tmp[3] = gf_mult(state[i], 0x03) ^ state[4 + i] ^ state[8 + i] ^ gf_mult(state[12 + i], 0x02);

        for j in 0..4 {
            state[i + 4 * j] = tmp[j];
        }
    }
}

 */
fn multiplication_gf(mut a: u8, mut b: u8) -> u8 {
    let mut result: u8 = 0;
    let mut hi_bits: u8;
    let mut i = 0;
    while i < 8 {
        if (b & 1) == 1 {
            result ^= a;
        }
        hi_bits = a & 0x80;
        a <<= 1;
        if hi_bits == 0x80 {
            a ^= 0x1b;
        }
        b >>= 1;
        i += 1;
    }
    return result;
}

fn state_to_str(state : &State) -> String{
    let mut state_str =String::new();
    for i in 0..4 {
        for j in 0..4 {
            state_str.push_str(format!("{:02x}", state.0[i][j]).as_str());

        }
    }
    return state_str;
}
fn main_enc(){
    let expected_round_0_input = "00102030405060708090a0b0c0d0e0f0";
    let after_S_Box = "63cab7040953d051cd60e0e7ba70e18c";
    let after_permutation = "6353e08c0960e104cd70b751bacad0e7";
    let after_mult = "5f72641557f5bc92f7be3b291db9f91a";

    let initial_key = [ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
    let expanded_key = key_expansion(&initial_key);
    let mut plaintext = State::from([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
    ]);
    println!("plaintext      {:?}", plaintext);
/*
    //println!("state_to_str {}",state_to_str(&plaintext));
    //1. Key Expansion
    let key = key_expansion(&initial_key);
    //println!("plaintext      {:?}", initial_key);
    //println!("plaintext_test {:?}", key[0]);



    // 2 . adding the round_key _0 // TEst is ok
    add_round_key(&mut plaintext, &key[0]);
    plaintext.print("initial state");
   // let expected_round_o_byte_vec = str_to_u8(&expected_round_0_input);
  //  vec_print(&expected_round_o_byte_vec.to_vec());



        for round in 1..10{
            println!("Round {round}:");
            plaintext.sub_bytes();
            plaintext.print("After subbyte");
            //str_print(&after_S_Box);
            plaintext.shift_rows();
            plaintext.print("After shift ");
            //str_print(&after_permutation);
            println!(" ");
            plaintext.mix_columns();
            plaintext.print("After mix column");
            //str_print(&after_mult);
            println!("used sub key {:?}", expanded_key[round]);
            add_round_key(&mut plaintext, &expanded_key[round]);
            plaintext.print("After round key");
        }
    println!("Round 11:");
    plaintext.sub_bytes();
    plaintext.print("After subbyte");
    plaintext.shift_rows();
    plaintext.print("After shift ");
    println!("used sub key {:?}", expanded_key[10]);
    add_round_key(&mut plaintext, &expanded_key[10]);
    plaintext.print("After round key");
    //69 c4 e0 d8 6a 7b 04 30 d8 cd b7 80 70 b4 c5 5a

    let initial_key = [ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
    //let expanded_key = key_expansion(&initial_key);
    let mut plaintext = State::from([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
    ]);

 */
    plaintext.print("the plaintext");
    let mut cipher_text = aes_encryption(plaintext, &initial_key);
    cipher_text.print(" The cipher");

    let mut re_clear_text = aes_encryption(cipher_text, &initial_key);
    re_clear_text.print(" re_clear_text");



}
fn aes_decryption(mut ciphertext : State, initial_key: &[u8;16]) -> State{
    let expanded_key = key_expansion(initial_key);
    add_round_key(&mut ciphertext, &expanded_key[10]);
    ciphertext.print("10.  after key round");


    for round in (1..10).rev(){
        println!("{round}: ");
        ciphertext.shift_rows_inv();
        ciphertext.print(".  after permutation");
        ciphertext.sub_bytes_inv();
        ciphertext.print("after s_box");
        add_round_key(&mut ciphertext, &expanded_key[round]);
        ciphertext.print("After round key");
        ciphertext.mix_columns_inv();
        ciphertext.print("After mix column");

    }
    ciphertext.shift_rows_inv();
    ciphertext.print(".  after permutation");
    ciphertext.sub_bytes_inv();
    ciphertext.print("after s_box");
    add_round_key(&mut ciphertext, &expanded_key[0]);
    ciphertext.print("After round key");

    //add_round_key(&mut ciphertext, &expanded_key[0]);
    //plaintext.print("After round key");

    return ciphertext;
}

fn aes_encryption(mut plaintext : State, initial_key: &[u8;16]) -> State{
    let expanded_key = key_expansion(initial_key);
   //println!("plaintext      {:?}", plaintext);

    //println!("state_to_str {}",state_to_str(&plaintext));
    //1. Key Expansion
    let key = key_expansion(&initial_key);
    //println!("plaintext      {:?}", initial_key);
    println!("plaintext_test {:?}", key);

    // 2 . adding the round_key _0 // TEst is ok
    add_round_key(&mut plaintext, &key[0]);
    //plaintext.print("initial state");
    // let expected_round_o_byte_vec = str_to_u8(&expected_round_0_input);
    //  vec_print(&expected_round_o_byte_vec.to_vec());

    for round in 1..10{
        //println!("Round {round}:");
        plaintext.sub_bytes();
        //plaintext.print("After subbyte");
        //str_print(&after_S_Box);
        plaintext.shift_rows();
        //plaintext.print("After shift ");
        //str_print(&after_permutation);
        //println!(" ");
        plaintext.mix_columns();
        //plaintext.print("After mix column");
        //str_print(&after_mult);
        //println!("used sub key {:?}", expanded_key[round]);
        add_round_key(&mut plaintext, &expanded_key[round]);
        //plaintext.print("After round key");
    }
    //println!("Round 11:");
    plaintext.sub_bytes();
    //plaintext.print("After subbyte");
    plaintext.shift_rows();
    //plaintext.print("After shift ");
    //println!("used sub key {:?}", expanded_key[10]);
    add_round_key(&mut plaintext, &expanded_key[10]);
//    plaintext.print("After round key");
    return plaintext;
}
fn test(){
    // CONST
    let expanded_key_expected = "000102030405060708090a0b0c0d0e0fd6aa74fdd2af72fadaa678f1d6ab76feb692cf0b643dbdf1be9bc5006830b3feb6ff744ed2c2c9bf6c590cbf0469bf4147f7f7bc95353e03f96c32bcfd058dfd3caaa3e8a99f9deb50f3af57adf622aa5e390f7df7a69296a7553dc10aa31f6b14f9701ae35fe28c440adf4d4ea9c02647438735a41c65b9e016baf4aebf7ad2549932d1f08557681093ed9cbe2c974e13111d7fe3944a17f307a78b4d2b30c5";
    let key_expanded : [u8;176 ] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 214, 170, 116, 253, 210, 175, 114, 250, 218, 166, 120, 241, 214, 171, 118, 254, 182, 146, 207, 11, 100, 61, 189, 241, 190, 155, 197, 0, 104, 48, 179, 254, 182, 255, 116, 78, 210, 194, 201, 191, 108, 89, 12, 191, 4, 105, 191, 65, 71, 247, 247, 188, 149, 53, 62, 3, 249, 108, 50, 188, 253, 5, 141, 253, 60, 170, 163, 232, 169, 159, 157, 235, 80, 243, 175, 87, 173, 246, 34, 170, 94, 57, 15, 125, 247, 166, 146, 150, 167, 85, 61, 193, 10, 163, 31, 107, 20, 249, 112, 26, 227, 95, 226, 140, 68, 10, 223, 77, 78, 169, 192, 38, 71, 67, 135, 53, 164, 28, 101, 185, 224, 22, 186, 244, 174, 191, 122, 210, 84, 153, 50, 209, 240, 133, 87, 104, 16, 147, 237, 156, 190, 44, 151, 78, 19, 17, 29, 127, 227, 148, 74, 23, 243, 7, 167, 139, 77, 43, 48, 197];
    let round_0_input = "00102030405060708090a0b0c0d0e0f0";
    let round_o_byte_vec = str_to_u8(&round_0_input);

    let plaintext : &str = "00112233445566778899aabbccddeeff";
    let initial_key_str = "000102030405060708090a0b0c0d0e0f";
    let initial_key = str_to_u8(&initial_key_str);
    //println!("initial_key {:?}", initial_key);
    let k = Vec::from_hex(expanded_key_expected).expect("invalid");
    println!("expanded_key_expected");
    println!("{:?}", k);
    // key is Correct !
    let expanded_key = key_expansion(&initial_key);
    println!("my key");
    println!("expanded_key{:?}", expanded_key);
    let mut my_key_str : String = Default::default();
    for i in expanded_key.iter(){
        for ch in i.iter(){
            my_key_str.push_str(&format!("{0:x}", ch));
        }
    }
    //println!("my_key_str {} \n, len {}", my_key_str, my_key_str.len());
    //println!("   key_str {} \n, len {}", expanded_key_expected, expanded_key_expected.len());

}
fn str_to_u8(hex_str: &str) -> [u8;16]{
    let bytes_vec = Vec::from_hex(hex_str).expect("Invalid hex string");
    let mut bytes_array = [0; 16];
    bytes_array.copy_from_slice(&bytes_vec);
    return  bytes_array;
}
fn vec_print(my_vec : &Vec<u8>) {
    for i in my_vec{
        print!("{:02x} ", i);
    }
}

fn str_print(my_str : &str){
    let mut j = 0;
    for i in my_str.chars(){
        print!("{i}");
        if j % 2 ==1 {
            print!(" ");
        }
        j += 1;
    }
}
fn test_shift_inv() {
    println!("hi inverse");
    let mut plaintext = State::from([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
    ]);
    //println!("plaintext      {:?}", plaintext);
    print_state(&plaintext, " original");
    plaintext.shift_rows();
    //plaintext.print("shift");
    print_state(&plaintext, " shift");
    plaintext.shift_rows_inv();
    print_state(&plaintext, " shift inverse");
}
fn test_mix_column_invers(){
    println!("hi test_mix_column_invers");
    let mut plaintext = State::from([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
    ]);
    plaintext.print("original");
    plaintext.mix_columns();
    plaintext.print(" mix");
    plaintext.mix_columns_inv();
    plaintext.print(" after mix ");




}
fn main(){
    let initial_key = [ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
    let mut plaintext = State::from([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
    ]);

    let initial_key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let mut plaintext = State::from([
        0x00, 0x00, 0x01, 0x01, 0x03, 0x03, 0x07, 0x07, 0x0f, 0x0f, 0x1f, 0x1f, 0x3f, 0x3f, 0x7f, 0x7f
    ]);


    let mut ciphertext = aes_encryption(plaintext, &initial_key);
    ciphertext.print("cipher");
    let plain_test = aes_decryption(ciphertext, &initial_key);
    plain_test.print(" test");


}

