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

pub struct Keccak {
    sponge: KeccakSponge,
}

impl Keccak {
    pub fn new(out: u32) -> Self {
        let (rate, capacity) = match out {
            224 => (1152, 448),
            256 => (1088, 512),
            384 => (832, 768),
            512 => (576, 1024),
            _ => panic!("Incorrect out length"),
        };
        Keccak {
            sponge: KeccakSponge::new(rate, capacity, out),
        }
    }

    pub fn clear(&mut self) {
        self.sponge.clear();
    }

    pub fn update(&mut self, message: &String) {
        self.sponge.update(message);
    }

    pub fn hash(&mut self) -> String {
        let mut sponge = self.sponge.clone();
        sponge.absorb_all();
        let digest = sponge.squeeze();
        fmt_hash(digest)
    }
}

#[cfg(test)]
mod tests {
    use super::Keccak;
    use crate::utils::{get_hash_orig_keccak224, get_hash_orig_keccak256, get_hash_orig_keccak384, get_hash_orig_keccak512};
    use std::time::Instant;
    const ITERATIONS: i32 = 1000;

    #[test]
    fn keccak224() {
        let mut keccak224 = Keccak::new(224);
        let data = [
            "",
            "Keccak is a versatile cryptographic function. Best known as a hash function, it nevertheless can also be used for authentication, (authenticated) encryption and pseudo-random number generation. Its structure is the extremely simple sponge construction and internally it uses the innovative Keccak-f cryptographic permutation.",
            "Lorem Ipsum - это текст - рыба, часто используемый в печати и вэб-дизайне. Lorem Ipsum является стандартной рыбой для текстов на латинице с начала XVI века. В то время некий безымянный печатник создал большую коллекцию размеров и форм шрифтов, используя Lorem Ipsum для распечатки образцов. Lorem Ipsum не только успешно пережил без заметных изменений пять веков, но и перешагнул в электронный дизайн. Его популяризации в новое время послужили публикация листов Letraset с образцами Lorem Ipsum в 60-х годах и, в более недавнее время, программы электронной вёрстки типа Aldus PageMaker, в шаблонах которых используется Lorem Ipsum.",
        ];

        for message in data {
            keccak224.update(&message.to_string());
            assert_eq!(get_hash_orig_keccak224(message), keccak224.hash());
            keccak224.clear();
        }
    }

    #[test]
    fn keccak256() {
        let mut keccak256 = Keccak::new(256);

        let data = [
            "",
            "Keccak is a versatile cryptographic function. Best known as a hash function, it nevertheless can also be used for authentication, (authenticated) encryption and pseudo-random number generation. Its structure is the extremely simple sponge construction and internally it uses the innovative Keccak-f cryptographic permutation.",
            "Lorem Ipsum - это текст - рыба, часто используемый в печати и вэб-дизайне. Lorem Ipsum является стандартной рыбой для текстов на латинице с начала XVI века. В то время некий безымянный печатник создал большую коллекцию размеров и форм шрифтов, используя Lorem Ipsum для распечатки образцов. Lorem Ipsum не только успешно пережил без заметных изменений пять веков, но и перешагнул в электронный дизайн. Его популяризации в новое время послужили публикация листов Letraset с образцами Lorem Ipsum в 60-х годах и, в более недавнее время, программы электронной вёрстки типа Aldus PageMaker, в шаблонах которых используется Lorem Ipsum.",
        ];

        for message in data {
            keccak256.update(&message.to_string());
            assert_eq!(get_hash_orig_keccak256(message), keccak256.hash());
            keccak256.clear();
        }
    }

    #[test]
    fn keccak384() {
        let mut keccak384 = Keccak::new(384);

        let data = [
            "",
            "Keccak is a versatile cryptographic function. Best known as a hash function, it nevertheless can also be used for authentication, (authenticated) encryption and pseudo-random number generation. Its structure is the extremely simple sponge construction and internally it uses the innovative Keccak-f cryptographic permutation.",
            "Lorem Ipsum - это текст - рыба, часто используемый в печати и вэб-дизайне. Lorem Ipsum является стандартной рыбой для текстов на латинице с начала XVI века. В то время некий безымянный печатник создал большую коллекцию размеров и форм шрифтов, используя Lorem Ipsum для распечатки образцов. Lorem Ipsum не только успешно пережил без заметных изменений пять веков, но и перешагнул в электронный дизайн. Его популяризации в новое время послужили публикация листов Letraset с образцами Lorem Ipsum в 60-х годах и, в более недавнее время, программы электронной вёрстки типа Aldus PageMaker, в шаблонах которых используется Lorem Ipsum.",
        ];

        for message in data {
            keccak384.update(&message.to_string());
            assert_eq!(get_hash_orig_keccak384(message), keccak384.hash());
            keccak384.clear();
        }
    }

    #[test]
    fn keccak512() {
        let mut keccak512 = Keccak::new(512);

        let data = [
            "",
            "Keccak is a versatile cryptographic function. Best known as a hash function, it nevertheless can also be used for authentication, (authenticated) encryption and pseudo-random number generation. Its structure is the extremely simple sponge construction and internally it uses the innovative Keccak-f cryptographic permutation.",
            "Lorem Ipsum - это текст - рыба, часто используемый в печати и вэб-дизайне. Lorem Ipsum является стандартной рыбой для текстов на латинице с начала XVI века. В то время некий безымянный печатник создал большую коллекцию размеров и форм шрифтов, используя Lorem Ipsum для распечатки образцов. Lorem Ipsum не только успешно пережил без заметных изменений пять веков, но и перешагнул в электронный дизайн. Его популяризации в новое время послужили публикация листов Letraset с образцами Lorem Ipsum в 60-х годах и, в более недавнее время, программы электронной вёрстки типа Aldus PageMaker, в шаблонах которых используется Lorem Ipsum.",
        ];

        for message in data {
            keccak512.update(&message.to_string());
            assert_eq!(get_hash_orig_keccak512(message), keccak512.hash());
            keccak512.clear();
        }
    }

    #[test]
    fn speed_keccak224() {
        let message = "Keccak is a versatile cryptographic function. Best known as a hash function, it nevertheless can also be used for authentication, (authenticated) encryption and pseudo-random number generation. Its structure is the extremely simple sponge construction and internally it uses the innovative Keccak-f cryptographic permutation.".to_string();
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            let mut keccak224 = Keccak::new(224);
            keccak224.update(&message);
            keccak224.hash();
        }
        println!("Own with 224 len: {:?}", start.elapsed());

        let message = message.as_str();
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            get_hash_orig_keccak224(message);
        }
        println!("Library with 224 len: {:?}", start.elapsed());
    }

    #[test]
    fn speed_keccak256() {
        let message = "Keccak is a versatile cryptographic function. Best known as a hash function, it nevertheless can also be used for authentication, (authenticated) encryption and pseudo-random number generation. Its structure is the extremely simple sponge construction and internally it uses the innovative Keccak-f cryptographic permutation.".to_string();

        let start = Instant::now();
        for _ in 0..ITERATIONS {
            let mut keccak256 = Keccak::new(256);
            keccak256.update(&message.to_string());
            keccak256.hash();
        }
        println!("Own with 256 len: {:?}", start.elapsed());
        
        let message = message.as_str();
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            get_hash_orig_keccak256(message);
        }
        println!("Library with 256 len: {:?}", start.elapsed());
    }

    #[test]
    fn speed_keccak384() {
        let message = "Keccak is a versatile cryptographic function. Best known as a hash function, it nevertheless can also be used for authentication, (authenticated) encryption and pseudo-random number generation. Its structure is the extremely simple sponge construction and internally it uses the innovative Keccak-f cryptographic permutation.".to_string();

        let start = Instant::now();
        for _ in 0..ITERATIONS {
            let mut keccak384 = Keccak::new(384);
            keccak384.update(&message.to_string());
            keccak384.hash();
        }
        println!("Own with 384 len: {:?}", start.elapsed());

        let message = message.as_str();
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            get_hash_orig_keccak384(message);
        }
        println!("Library with 384 len: {:?}", start.elapsed());
    }

    #[test]
    fn speed_keccak512() {
        let message = "Keccak is a versatile cryptographic function. Best known as a hash function, it nevertheless can also be used for authentication, (authenticated) encryption and pseudo-random number generation. Its structure is the extremely simple sponge construction and internally it uses the innovative Keccak-f cryptographic permutation.".to_string();

        let start = Instant::now();
        for _ in 0..ITERATIONS {
            let mut keccak512 = Keccak::new(512);
            keccak512.update(&message.to_string());
            keccak512.hash();
        }
        println!("Own with 512 len: {:?}", start.elapsed());

        let message = message.as_str();
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            get_hash_orig_keccak512(message);
        }
        println!("Library with 512 len: {:?}", start.elapsed());
    }
}
