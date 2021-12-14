# authenticator-rs
The rust implementation for google authenticator with 2FA authentication

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
authenticator-rs = "0.2.0"
```

## Example
```rust
use crate::authenticator;

fn main(){
    let secret =  authenticator::create_secret(32); // create a random secret
    let pin_code_rs = authenticator::current_pin_code(secret.as_str(), 6);
    match pin_code_rs {
            Ok(code) => { println!("Current Pin Code: {}", code) }
            Err(e) => { println!("Something has error: {}", e) }
        }
}

```