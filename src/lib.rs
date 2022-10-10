pub mod authenticator;

/// This Rust crate can be used to interact with the Google Authenticator mobile app for 2-factor-authentication.
/// This Rust crates can generate secrets, generate codes, validate codes and present a QR-Code for scanning the secret.
/// It implements TOTP according to RFC6238
/// # Example
/// ```rust
/// use crate::authenticator_rs::authenticator;
/// fn main(){
///     let secret =  authenticator::create_secret(32); // create a random secret
///     let pin_code_rs = authenticator::current_pin_code(secret.as_str(), 6);
///     match pin_code_rs {
///             Ok(code) => { println!("Current Pin Code: {}", code) }
///             Err(e) => { println!("Something has error: {}", e) }
///         }
/// }
///
/// ```
#[cfg(test)]
mod test {
    use crate::authenticator;

    #[test]
    fn test_create_secret() {
        let secret = authenticator::create_secret(32);
        println!("{:?}", secret.as_str());
        assert_eq!(secret.len(), 32);
    }

    #[test]
    fn test_pin_code() {
        let pin_code = authenticator::current_pin_code("abf3j5csiu2jn6wehechiuuclyh44yaw", 6);
        match pin_code {
            Ok(code) => { println!("Current Pin Code: {}", code) }
            Err(e) => { println!("Something has error: {}", e) }
        }
    }

    #[test]
    fn test_qr_code_url() {
        let qr_code_url = authenticator::create_qr_code_url("foobar", "abf3j5csiu2jn6wehechiuuclyh44yaw");
        println!("{}", qr_code_url)
    }

    #[test]
    fn test_verify_pin_code() {
        let res = authenticator::verify_pin_code("abf3j5csiu2jn6wehechiuuclyh44yaw", "281087", 6);
        println!("{}", res)
    }
}