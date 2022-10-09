// referenced by https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

// 4.2.2 SHA-224 and SHA-256 Constants
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

// 5.3.3 SHA-256
const H0: [u32; 8] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];

// 5.1 Padding the Message
fn padding(message: &[u8]) -> Vec<u32> {
    let len = message.len();
    let mut tmp: Vec<u32> = Vec::new();
    tmp.push(0x80);
    tmp.extend_from_slice(&[0; 63]);

    let mut bs = message.to_vec().iter().map(|&x| x as u32).collect::<Vec<u32>>();
    
    bs = match len % 64 < 56 {
        true => {
            bs.extend_from_slice(&tmp[..56 - len % 64]);
            bs
        },
        false => {
            bs.extend_from_slice(&tmp[..64 - len % 64 + 56]);
            bs
        },
    };
    
    let bits = (len as u64) * 8;
    let mut size = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    size[4] = ((bits & 0xff) >> 24) as u32;
    size[5] = ((bits & 0xff) >> 16) as u32;
    size[6] = ((bits & 0xff) >> 8) as u32;
    size[7] = (bits & 0xff) as u32;

    bs.append(&mut size.clone());
    bs
    
}

// 4.1.2 SHA-224 and SHA-256 Functions
#[allow(non_snake_case)]
fn Ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}
#[allow(non_snake_case)]
fn Maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}
#[allow(non_snake_case)]
fn Sigma0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}
#[allow(non_snake_case)]
fn Sigma1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}
#[allow(non_snake_case)]
fn sigma0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}
#[allow(non_snake_case)]
fn sigma1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

// 6.2.2 SHA-256 Hash Computation
fn compute(message: Vec<u32>) -> [u32; 8] {
    #[allow(non_snake_case)]
    let N = message.len() / 64;
    #[allow(non_snake_case)]
    let W = &mut [0u32; 64];
    #[allow(non_snake_case)]
    let mut H = H0;

    for i in 1..N + 1 {
        let chunk = &message[(i - 1) * 64..i * 64];
        for t in 0..16 {
            W[t] = (chunk[t * 4] as u32) << 24
                | (chunk[t * 4 + 1] as u32) << 16
                | (chunk[t * 4 + 2] as u32) << 8
                | (chunk[t * 4 + 3] as u32);
        }
        for t in 16..64 {
            W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16];
        }

        let mut a = H[0];
        let mut b = H[1];
        let mut c = H[2];
        let mut d = H[3];
        let mut e = H[4];
        let mut f = H[5];
        let mut g = H[6];
        let mut h = H[7];

        for j in 0..64 {
            #[allow(non_snake_case)]
            let T1 = (h + Sigma1(e) + Ch(e, f, g) + K[j] + W[j]) & 0xffffffff;
            #[allow(non_snake_case)]
            let T2 = (Sigma0(a) + Maj(a, b, c)) & 0xffffffff;

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(T1) & 0xffffffff;
            d = c;
            c = b;
            b = a;
            a = T1.wrapping_add(T2) & 0xffffffff;
        }

        H[0] = (H[0] + a) & 0xffffffff;
        H[1] = (H[1] + b) & 0xffffffff;
        H[2] = (H[2] + c) & 0xffffffff;
        H[3] = (H[3] + d) & 0xffffffff;
        H[4] = (H[4] + e) & 0xffffffff;
        H[5] = (H[5] + f) & 0xffffffff;
        H[6] = (H[6] + g) & 0xffffffff;
        H[7] = (H[7] + h) & 0xffffffff;
    }

    H
}

fn to_hex(bytes: &[u32]) -> String {
    let mut s = String::new();
    for &byte in bytes {
        s.push_str(&format!("{:02x}", byte));
    }
    s
}

fn main() {
    let input = b"takurinton";
    let padded = padding(input);
    let hex = compute(padded);
    let bin = to_hex(&hex);
    // expect: c04bdbc0411b0f0fffcc8147ba10411f334da5d6c5bb8e6db9358c5f14aeb0cc
    println!("{}", bin);
}

