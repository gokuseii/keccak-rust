use std::ops::Div;

use crate::KeccakF;

#[derive(Clone)]
pub struct KeccakSponge {
    b: u32,
    d: u32,
    capacity: u32,
    block_size: u32,
    state: [u64; 25],
    data: Vec<u8>,
    keccak_f: KeccakF,
}

impl KeccakSponge {
    pub fn new(rate: u32, capacity: u32, out: u32) -> Self {
        let b = rate + capacity;
        let w = b.div(25);
        KeccakSponge {
            b,
            d: out.div(8),
            capacity,
            block_size: rate.div(8),
            state: [0; 25],
            data: Vec::default(),
            keccak_f: KeccakF::new(w),
        }
    }

    fn padding(&self) -> Vec<u8> {
        let mut data = self.data.clone();
        let padd: u32 = self.block_size - data.len() as u32;
        if padd == 1 {
            data.push(0x81);
        } else {
            data.push(0x01);
            for _ in 0..(padd - 2) {
                data.push(0x00);
            }
            data.push(0x80);
        }
        data
    }

    pub fn update(&mut self, message: &String) {
        let m_bytes = message.as_bytes().to_vec();
        self.data = [self.clone().data, m_bytes].concat();
        while self.data.len() as u32 >= self.block_size {
            self.absorb_chunks(self.data[0..self.block_size as usize].to_vec());
            self.data = self.data[(self.block_size as usize)..].to_vec();
        }
    }

    pub fn absorb_chunks(&mut self, message_bytes: Vec<u8>) {
        let mut m = message_bytes.clone();
        for _ in 0..self.b.div(8) {
            m.push(0x00);
        }
        let mut i = 0;
        for x in 0..5 {
            for y in 0..5 {
                let mut word_bits: [u8; 8] = Default::default();
                word_bits.copy_from_slice(&m[i..i + 8]);
                self.state[x + 5 * y] ^= u64::from_le_bytes(word_bits);
                i += 8;
            }
        }
        self.keccak_f.perm(&mut self.state);
    }

    pub fn sqz(&mut self) -> Vec<u8> {
        let mut rc: Vec<u8> = Vec::default();
        let e = self.capacity.div(2).div(8);
        let mut c = 0;
        'q: for x in 0..5 {
            for y in 0..5 {
                rc = [rc, self.state[x + 5 * y].to_le_bytes().to_vec()].concat();
                if c == e {
                    break 'q;
                }
                c += 1;
            }
        }
        self.keccak_f.perm(&mut self.state);
        rc
    }

    pub fn squeeze(&mut self) -> Vec<u8> {
        let mut o: Vec<u8> = Vec::default();
        while (o.len() as u32) < self.d {
            o = [o, self.sqz()].concat();
        }
        o[..self.d as usize].to_vec()
    }

    pub fn absorb_all(&mut self) {
        let data = self.padding();
        self.absorb_chunks(data);
        self.data = Vec::default();
    }

    pub fn clear(&mut self) {
        self.data = Vec::new();
        self.state = [0; 25];
    }
}
