extern crate core;

pub mod authenticator;

/// This Rust crate can be used to interact with the Google Authenticator mobile app for 2-factor-authentication.
/// This Rust crates can generate secrets, generate codes, validate codes and present a QR-Code for scanning the secret.
/// It implements TOTP according to RFC6238
/// # Example
/// ```rust
/// use crate::authenticator_rs::authenticator;
/// fn main(){
///     use authenticator_rs::authenticator::{Algorithm, Authenticator};
///     let secret =  authenticator::create_secret(32); // create a random secret
///     let authenticator_r = Authenticator::new(Algorithm::SHA384, "abf3j5csiu2jn6wehechiuuclyh44yaw".to_string(), 6);
///         match authenticator_r {
///             Ok(authenticator) => {
///                 match authenticator.generate_response_code() {
///                     Ok(p_code) => { println!("Current Pin Code: {}", p_code) }
///                     Err(e) => { println!("Something has error: {}", e) }
///                 }
///             }
///             Err(e) => { println!("Something has error: {}", e) }
///         }
/// }
///
/// ```
///
#[cfg(test)]
mod test {
    use crate::authenticator;
    use crate::authenticator::{Algorithm, Authenticator};

    #[test]
    fn test_create_secret() {
        let secret = authenticator::create_secret(32);
        println!("{:?}", secret.as_str());
        assert_eq!(secret.len(), 32);
    }

    #[test]
    fn test_pin_code() {
        let authenticator_r = Authenticator::new(Algorithm::SHA384, "abf3j5csiu2jn6wehechiuuclyh44yaw".to_string(), 6);
        match authenticator_r {
            Ok(authenticator) => {
                match authenticator.generate_response_code() {
                    Ok(p_code) => { println!("Current Pin Code: {}", p_code) }
                    Err(e) => { println!("Something has error: {}", e) }
                }
            }
            Err(e) => { println!("Something has error: {}", e) }
        }
    }

    #[test]
    fn test_qr_code_url() {
        let qr_code_url = authenticator::create_qr_code_url("foobar", "abf3j5csiu2jn6wehechiuuclyh44yaw");
        println!("{}", qr_code_url)
    }
}