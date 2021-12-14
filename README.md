# authenticator-rs

The rust implementation for google authenticator with 2FA authentication

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
authenticator-rs = "0.2.0"
```

## Example

Get current pin code:

```rust
use crate::authenticator;

fn main() {
    let secret = authenticator::create_secret(32); // create a random secret
    let pin_code_rs = authenticator::current_pin_code(secret.as_str(), 6);
    match pin_code_rs {
        Ok(code) => { println!("Current Pin Code: {}", code) }
        Err(e) => { println!("Something has error: {}", e) }
    }
}

```

Verify pin code:

```rust
use crate::authenticator;

fn main() {
    let secret = "DGF3J5CSIU2JN6WEHECHIUUCLYHCNYAW";
    let pcode = "281087";
    let verify_rs = authenticator::verify_pin_code(secret, pcode, 6);
    println!("Pin code: {} verify result:{}", pcode, verify_rs)
}

```