use std::time::{SystemTime, UNIX_EPOCH};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use ring::hmac;
use ring::hmac::{HMAC_SHA1_FOR_LEGACY_USE_ONLY, HMAC_SHA256, HMAC_SHA384, HMAC_SHA512, Key};

/// the base32 charset using generate secret
const ALPHABET: [char; 32] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '2', '3', '4', '5', '6', '7',
];

/// The Max pin code length
const MAX_PINCODE_LENGTH: u16 = 9;

const SECRET_MAX_LEN: usize = 128;
const SECRET_MIN_LEN: usize = 16;
//                               0  1    2     3     4      5       6         7          8          9
const DIGITS_POWER: [i32; 10] = [1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000];

/// The cropto signer
pub trait Signer {
    fn sign(&self, data: &[u8]) -> Vec<u8>;
}

impl Signer for Key {
    fn sign(&self, data: &[u8]) -> Vec<u8> {
        let tag = hmac::sign(&self, data);
        tag.as_ref().to_vec()
    }
}


#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Algorithm {
    /// HMAC using SHA-1. Obsolete.
    SHA1,

    /// HMAC using SHA-256.
    SHA256,

    /// HMAC using SHA-384.
    SHA384,

    /// HMAC using SHA-512.
    SHA512,
}

/// create a random secret
pub fn create_secret(length: u8) -> String {
    let mut secret = Vec::<&char>::new();
    let mut index: usize;
    for _ in 0..length {
        index = (rand::random::<u8>() & 0x1F) as usize;
        secret.push(&ALPHABET[index]);
    }
    secret.into_iter().collect()
}

/// create TOTP url
pub fn create_totp_url_schema(user: &str, secret: &str) -> String {
    let name = utf8_percent_encode(user, NON_ALPHANUMERIC);
    format!("otpauth://totp/{}?secret={}", name, secret)
}

/// create qrCode
pub fn create_qr_code_url(user: &str, secret: &str) -> String {
    let totp_url_schema = create_totp_url_schema(user, secret);
    let schema = utf8_percent_encode(totp_url_schema.as_str(), NON_ALPHANUMERIC);
    let width = "200";
    let height = "200";
    return format!("https://api.qrserver.com/v1/create-qr-code/?data={}&size={}x{}&ecc=M", schema, width, height);
}


fn get_signer(secret_key: &[u8], algorithm: Algorithm) -> Box<dyn Signer> {
    match algorithm {
        Algorithm::SHA1 => { Box::new(Key::new(HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret_key)) }
        Algorithm::SHA256 => { Box::new(Key::new(HMAC_SHA256, secret_key)) }
        Algorithm::SHA384 => { Box::new(Key::new(HMAC_SHA384, secret_key)) }
        Algorithm::SHA512 => { Box::new(Key::new(HMAC_SHA512, secret_key)) }
    }
}

fn base32_decode(secret: &str) -> Result<Vec<u8>, String> {
    match base32::decode(base32::Alphabet::RFC4648 { padding: true }, secret) {
        Some(_decode_str) => Ok(_decode_str),
        _ => Err(String::from("secret must be base32 decodeable.")),
    }
}

pub struct Authenticator {
    algorithm: Algorithm,
    secret_key: String,
    code_len: usize,
}

impl Authenticator {
    pub fn new(algorithm: Algorithm, secret_key: String, code_len: usize) -> Result<Self, String> {
        if code_len <= 0 || code_len > MAX_PINCODE_LENGTH.into() {
            return Err(format!("PinCode Length must be between 1 and {} digits", MAX_PINCODE_LENGTH));
        }
        Ok(Authenticator { algorithm, secret_key, code_len })
    }

    pub fn generate_response_code(&self) -> Result<String, String> {
        let otp_state = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() / 30;
        let secret = &self.secret_key;
        if secret.len() < SECRET_MIN_LEN || secret.len() > SECRET_MAX_LEN {
            return Err(String::from("Bad secret length. must be less than 128 and more than 16, recommend 32"));
        }
        let result = base32_decode(secret);
        match result {
            Ok(key) => {
                let signer = get_signer(key.as_slice(), self.algorithm);
                let msg_bytes = otp_state.to_be_bytes();
                let hash = &signer.sign(&msg_bytes)[..];
                let offset = hash[hash.len() - 1] & 0x0F;
                let mut truncated_hash: [u8; 4] = Default::default();
                truncated_hash.copy_from_slice(&hash[offset as usize..(offset + 4) as usize]);
                let mut code = i32::from_be_bytes(truncated_hash);
                code &= 0x7FFFFFFF;
                code %= DIGITS_POWER[self.code_len];
                let mut code_str = code.to_string();
                for i in 0..(&self.code_len - code_str.len()) {
                    code_str.insert(i, '0');
                }
                Ok(code_str)
            }
            Err(e) => { Err(e) }
        }
    }

    pub fn verify_pin_code(&self, pin_code: &str) -> bool {
        let code = self.generate_response_code();
        match code {
            Ok(pcode) => { pcode.as_str().eq_ignore_ascii_case(pin_code) }
            Err(_) => { false }
        }
    }
}