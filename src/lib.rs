mod authenticator;

#[cfg(test)]
mod test {
    use crate::authenticator;

    #[test]
    fn test_create_secret() {
        let secret = authenticator::create_secret(32);
        println!("{:?}", secret);
        assert_eq!(secret.len(), 32);
    }

    #[test]
    fn test_pin_code() {
        let pin_code = authenticator::current_pin_code("DGF3J5CSIU2JN6WEHECHIUUCLYHCNYAW", 6);
        match pin_code {
            Ok(code) => { println!("Current Pin Code: {}", code) }
            Err(e) => { println!("Something has error: {}", e) }
        }
    }
}