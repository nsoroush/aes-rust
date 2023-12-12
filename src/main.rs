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

#[derive(Debug)]
pub struct State([[u8; 4]; 4]);

impl State {
    pub fn new() -> State{
        State([[0x00; 4]; 4])
    }
    pub fn get(&self, row: usize, col: usize) -> u8 {
        //self.0.get(row).and_then(|r| r.get(col))
        self.0[row][col]
    }

    pub fn sub_bytes(&self) -> State{
        let mut sub_state = State::new();
        for (i, j) in iproduct!(0..4, 0..4) {
            //println!("i: {}, j: {}", i, j);
           // println!("{}",self.get(i,j) as usize);
            sub_state.0[i][j] = AES_SBOX[self.get(i,j) as usize];
        }
        return sub_state;
    }
    pub fn print(&self){
        for row in self.0.iter() {
            for &byte in row.iter() {
                print!("{:02x} ", byte);
            }
            println!();
        }
    }
    pub fn shift_rows(&mut self) {
        // Row 1: Shift left by 1 position
        self.0[1].rotate_left(1);

        // Row 2: Shift left by 2 positions
        self.0[2].rotate_left(2);

        // Row 3: Shift left by 3 positions
        self.0[3].rotate_left(3);
    }

}

fn shift_rows(state: &mut [[u8; 4]; 4]) {
    // Row 1: Shift left by 1 position
    state[1].rotate_left(1);

    // Row 2: Shift left by 2 positions
    state[2].rotate_left(2);

    // Row 3: Shift left by 3 positions
    state[3].rotate_left(3);
}

/*
fn main() {
    let mut state: State([
        [0x00, 0x11, 0x22, 0x33],
        [0x44, 0x55, 0x66, 0x77],
        [0x88, 0x99, 0xaa, 0xbb],
        [0xcc, 0xdd, 0xee, 0xff],
    ]);

    println!("Before ShiftRows:");
    print_state(&state);

    shift_rows(&mut state);

    println!("After ShiftRows:");
    print_state(&state);
}

 */

fn print_state(state: &[[u8; 4]; 4]) {
    for row in state.iter() {
        for &byte in row.iter() {
            print!("{:02x} ", byte);
        }
        println!();
    }
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

pub fn add_round_key(state :&mut State, round_key: &[[u8; 4]; 4]) {
    for i in 0..4 {
        for j in 0..4 {
            state.0[i][j] ^= round_key[i][j];
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

/*fn main() {
    // Example state matrix
    let mut state: State = State {
        bytes: [
            0x32, 0x88, 0x31, 0xe0,
            0x43, 0x5a, 0x31, 0x37,
            0xf6, 0x30, 0x98, 0x07,
            0xa8, 0x8d, 0xa2, 0x34,
        ],
    };

    // Print the original state
    println!("Original State:");
    print_state(&state);

    // Apply MixColumns operation
    mix_columns(&mut state);

    // Print the state after MixColumns
    println!("\nAfter MixColumns:");
    print_state(&state);
}



 */

fn main() {
    let mut state = State([
        [0x00, 0x11, 0x22, 0x33],
        [0x44, 0x55, 0x66, 0x77],
        [0x88, 0x99, 0xAA, 0xBB],
        [0xCC, 0xDD, 0xEE, 0xFF],
    ]);
   // state.print();

    // Print the original state
    println!("Original State:");
    state.print();

    // Apply MixColumns operation
    mix_columns(&mut state);

    // Print the state after MixColumns
    println!("\nAfter MixColumns:");
    state.print();

/*
    let a = state.get(0,1);
   // println!("{:0X}", a);

   // println!("{:?}", state);
    let new_stat= state.sub_bytes();
    println!("{:?}", new_stat);
    new_stat.print();

    println!("shift ");

    state.shift_rows();
    state.print();

 */
}




