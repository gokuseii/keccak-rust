use crate::sponge::KeccakSponge;
use std::ops::{Add, Mul};

static RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

static ROT_OFFSETS: [[u32; 5]; 5] = [
    [0, 1, 62, 28, 27],
    [36, 44, 6, 55, 20],
    [3, 10, 43, 25, 39],
    [41, 45, 15, 21, 8],
    [18, 2, 61, 56, 14],
];

fn fmt_hash(h: Vec<u8>) -> String {
    h.iter().map(|s| format!("{:02x}", s)).collect::<String>()
}

#[derive(Clone)]
pub struct KeccakF {
    w: u32,
    n: u32,
}

impl KeccakF {
    pub fn new(w: u32) -> Self {
        let l = (w as f32).log2() as u32;
        let n = 12.add(2.mul(l));
        KeccakF { w, n }
    }

    pub fn perm(&self, state: &mut [u64; 25]) {
        for i in 0..self.n {
            self.round_b(state, RC[i as usize]);
        }
    }

    pub fn round_b(&self, state: &mut [u64; 25], rc: u64) {
        self.theta(state);
        self.chi(state);
        self.iota(state, rc);
    }

    fn theta(&self, state: &mut [u64; 25]) {
        let mut c: [u64; 5] = [0; 5];
        let mut d: [u64; 5] = [0; 5];

        for x in 0..5 {
            for y in 0..5 {
                c[y] ^= state[x + 5 * y];
            }
        }

        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }

        for x in 0..5 {
            for y in 0..5 {
                state[x + 5 * y] ^= d[y];
            }
        }
    }

    fn rho_and_pi(&self, state: &mut [u64; 25]) -> [u64; 25] {
        let mut s: [u64; 25] = [0; 25];
        for x in 0..5 {
            for y in 0..5 {
                let f = (2 * x + 3 * y) % 5;
                let q = y % self.w;
                s[(f + 5 * q) as usize] =
                    state[(y + 5 * x) as usize].rotate_left(ROT_OFFSETS[y as usize][x as usize])
            }
        }
        s
    }

    fn chi(&self, state: &mut [u64; 25]) {
        let s = self.rho_and_pi(state);
        for x in 0..5 {
            for y in 0..5 {
                state[y + 5 * x] =
                    s[x * 5 + y] ^ (!s[((x + 1) % 5) * 5 + y] & s[((x + 2) % 5) * 5 + y]);
            }
        }
    }

    fn iota(&self, state: &mut [u64; 25], rc: u64) {
        state[0] ^= rc;
    }
}

struct Keccak {
    sponge: KeccakSponge,
}

impl Keccak {
    fn new(rate: u32, capacity: u32, out: u32) -> Self {
        Keccak {
            sponge: KeccakSponge::new(rate, capacity, out),
        }
    }

    fn clear(&mut self) {
        self.sponge.clear();
    }

    fn update(&mut self, message: &String) {
        self.sponge.update(message);
    }

    fn hash(&mut self) -> String {
        let mut temp = self.sponge.clone();
        temp.absorb_all();
        let digest = temp.squeeze();
        fmt_hash(digest)
    }
}

#[cfg(test)]
mod tests {
    use super::Keccak;

    #[test]
    fn keccak224() {
        let mut keccak224 = Keccak::new(1152, 448, 224);

        let data = [
            ("f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd", ""),
            ("b6385e16b205b680c017d9e8b388a8e304c1c9abe8bbe318b61f1fb4", "Keccak is a versatile cryptographic function. Best known as a hash function, it nevertheless can also be used for authentication, (authenticated) encryption and pseudo-random number generation. Its structure is the extremely simple sponge construction and internally it uses the innovative Keccak-f cryptographic permutation."),
            ("d07f73bdc42fd8e4f88b647d5454bbdc8c8504fc3d141bc882d2e409", "Lorem Ipsum - это текст - рыба, часто используемый в печати и вэб-дизайне. Lorem Ipsum является стандартной рыбой для текстов на латинице с начала XVI века. В то время некий безымянный печатник создал большую коллекцию размеров и форм шрифтов, используя Lorem Ipsum для распечатки образцов. Lorem Ipsum не только успешно пережил без заметных изменений пять веков, но и перешагнул в электронный дизайн. Его популяризации в новое время послужили публикация листов Letraset с образцами Lorem Ipsum в 60-х годах и, в более недавнее время, программы электронной вёрстки типа Aldus PageMaker, в шаблонах которых используется Lorem Ipsum."),
        ];

        for (hash, message) in data {
            keccak224.update(&message.to_string());
            assert_eq!(hash.to_string(), keccak224.hash());
            keccak224.clear();
        }
    }

    #[test]
    fn keccak256() {
        let mut keccak256 = Keccak::new(1088, 512, 256);

        let data = [
            ("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", ""),
            ("6343389879f3554ec67ef38b35b05ed18f0c8ca8c3d98de690d0254d7c21e0ed", "Keccak is a versatile cryptographic function. Best known as a hash function, it nevertheless can also be used for authentication, (authenticated) encryption and pseudo-random number generation. Its structure is the extremely simple sponge construction and internally it uses the innovative Keccak-f cryptographic permutation."),
            ("3f0e5a58ccb7fb33cf3bc4f6e8e10a25613503e59cf4b248bc50bee038bb06e7", "Lorem Ipsum - это текст - рыба, часто используемый в печати и вэб-дизайне. Lorem Ipsum является стандартной рыбой для текстов на латинице с начала XVI века. В то время некий безымянный печатник создал большую коллекцию размеров и форм шрифтов, используя Lorem Ipsum для распечатки образцов. Lorem Ipsum не только успешно пережил без заметных изменений пять веков, но и перешагнул в электронный дизайн. Его популяризации в новое время послужили публикация листов Letraset с образцами Lorem Ipsum в 60-х годах и, в более недавнее время, программы электронной вёрстки типа Aldus PageMaker, в шаблонах которых используется Lorem Ipsum."),
        ];

        for (hash, message) in data {
            keccak256.update(&message.to_string());
            assert_eq!(hash.to_string(), keccak256.hash());
            keccak256.clear();
        }
    }

    #[test]
    fn keccak384() {
        let mut keccak384 = Keccak::new(832, 768, 384);

        let data = [
            ("2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff", ""),
            ("8df7836732d924dfe5a27c8a4ee17626d9a0396c9560783585632d3cf5867be06782b7c4099c51340bcf13b447e7040a", "Keccak is a versatile cryptographic function. Best known as a hash function, it nevertheless can also be used for authentication, (authenticated) encryption and pseudo-random number generation. Its structure is the extremely simple sponge construction and internally it uses the innovative Keccak-f cryptographic permutation."),
            ("a38f0262379f0284408eb41fd630a8778fd6b9d25511e0631b65baf24d6c1e69bd8de66da1da80ea6f4c8089b540ed0e", "Lorem Ipsum - это текст - рыба, часто используемый в печати и вэб-дизайне. Lorem Ipsum является стандартной рыбой для текстов на латинице с начала XVI века. В то время некий безымянный печатник создал большую коллекцию размеров и форм шрифтов, используя Lorem Ipsum для распечатки образцов. Lorem Ipsum не только успешно пережил без заметных изменений пять веков, но и перешагнул в электронный дизайн. Его популяризации в новое время послужили публикация листов Letraset с образцами Lorem Ipsum в 60-х годах и, в более недавнее время, программы электронной вёрстки типа Aldus PageMaker, в шаблонах которых используется Lorem Ipsum."),
        ];

        for (hash, message) in data {
            keccak384.update(&message.to_string());
            assert_eq!(hash.to_string(), keccak384.hash());
            keccak384.clear();
        }
    }

    #[test]
    fn keccak512() {
        let mut keccak512 = Keccak::new(576, 1024, 512);

        let data = [
            ("0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e", ""),
            ("19b35db1e83341a52ac56fc6716434edba935c39a9fd2604ed1bc0c742b8875aa8538b3b7c71e839ca4ae9e859fc43aa38ca332c6e00426f5b978dab5d09642c", "Keccak is a versatile cryptographic function. Best known as a hash function, it nevertheless can also be used for authentication, (authenticated) encryption and pseudo-random number generation. Its structure is the extremely simple sponge construction and internally it uses the innovative Keccak-f cryptographic permutation."),
            ("764762a87da1408b5361209c6c591f647e5b677f8a1d47487ac53d15e96a52337cc475f25427bc5326b54a20b22b57a8164293c72bced082ef199671e17a6802", "Lorem Ipsum - это текст - рыба, часто используемый в печати и вэб-дизайне. Lorem Ipsum является стандартной рыбой для текстов на латинице с начала XVI века. В то время некий безымянный печатник создал большую коллекцию размеров и форм шрифтов, используя Lorem Ipsum для распечатки образцов. Lorem Ipsum не только успешно пережил без заметных изменений пять веков, но и перешагнул в электронный дизайн. Его популяризации в новое время послужили публикация листов Letraset с образцами Lorem Ipsum в 60-х годах и, в более недавнее время, программы электронной вёрстки типа Aldus PageMaker, в шаблонах которых используется Lorem Ipsum."),
        ];

        for (hash, message) in data {
            keccak512.update(&message.to_string());
            assert_eq!(hash.to_string(), keccak512.hash());
            keccak512.clear();
        }
    }
}
