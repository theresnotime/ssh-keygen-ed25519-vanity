extern crate rand;
extern crate regex;
extern crate base64;
extern crate bytebuffer;
extern crate ed25519_dalek;

use clap::Parser;
use std::mem::size_of;
use std::error::Error;
use std::io::Write;
use std::fs::{File, Permissions};
use std::os::unix::fs::PermissionsExt;

use rand::rngs::OsRng;
use regex::Regex;
use base64::encode; // TODO: deprecated
use bytebuffer::{ByteBuffer, Endian::BigEndian};
use ed25519_dalek::{Keypair, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};

const KEYTYPE: &[u8] = b"ssh-ed25519";
const MAGIC: &[u8] = b"openssh-key-v1\x00";
const NONE: &[u8] = b"none";
const BLOCKSIZE: usize = 8;

/// Generate an d25519 keypair with a vanity public key
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Substring to search for
    #[arg(short, long)]
    pattern: String,

    /// Output file (optional)
    #[arg(short, long, default_value = "")]
    out: String,

    /// Verbose mode
    #[arg(short, long, default_value = "false")]
    verbose: bool,

    /// Yes to all prompts
    #[arg(short, long, default_value = "false")]
    yes: bool,
}

fn get_sk(pk: &[u8], keypair: Keypair) -> String {
  let mut buffer = ByteBuffer::new();
  buffer.write_bytes(MAGIC);
  buffer.write_u32(NONE.len() as u32);
  buffer.write_bytes(NONE);                   // cipher
  buffer.write_u32(NONE.len() as u32);
  buffer.write_bytes(NONE);                   // kdfname
  buffer.write_u32(0);                        // no kdfoptions
  buffer.write_u32(1);                        // public keys
  buffer.write_u32(pk.len() as u32);
  buffer.write_bytes(pk);                     // public key

  let mut sk = ByteBuffer::new();
  sk.write_u32(0xf0cacc1a);                   // check bytes
  sk.write_u32(0xf0cacc1a);
  sk.write_bytes(pk);                         // public key (again)
  sk.write_u32((SECRET_KEY_LENGTH + PUBLIC_KEY_LENGTH) as u32);
  sk.write_bytes(&keypair.secret.to_bytes()); // private key
  sk.write_bytes(&keypair.public.to_bytes()); // public part of private key
  sk.write_u32(0);                            // no comments
  for p in 1..=(buffer.len() + sk.len() + size_of::<u32>()) % BLOCKSIZE {
    sk.write_u8(p as u8);                     // padding
  }

  buffer.write_u32(sk.len() as u32);
  buffer.write_bytes(&sk.into_bytes()); // TODO: deprecated
  return encode(buffer.into_bytes()); // TODO: deprecated
}

fn prompt_keep_looking() -> bool {
  // Don't prompt in tests
  if cfg!(test) {
    return false;
  }

  print!("Continue searching? [y/N]: ");
  std::io::stdout().flush().unwrap();
  let mut input = String::new();
  std::io::stdin().read_line(&mut input).unwrap();
  return input.trim().to_lowercase() == "y";
}

fn run(pattern: String, path: String, verbose: bool, yes: bool) -> Result<(String, String), Box<dyn Error>> {
  // Check that pattern is only alphanumeric
  if (pattern.chars().all(char::is_alphanumeric)) == false {
    return Err("Pattern must be alphanumeric".into());
  }
  let regex = Regex::new(&pattern)?;
  println!("Searching for substring: {}", pattern);
  if path.is_empty() {
    println!("Writing to stdout");
  } else {
    println!("Writing to: {}", path);
  }
  let mut csprng = OsRng{};
  let mut buffer = ByteBuffer::new();
  buffer.set_endian(BigEndian);
  buffer.write_u32(KEYTYPE.len() as u32);
  buffer.write_bytes(KEYTYPE);
  buffer.write_u32(PUBLIC_KEY_LENGTH as u32);

  loop {
    let keypair = Keypair::generate(&mut csprng);
    buffer.write_bytes(&keypair.public.to_bytes());
    let pk = buffer.into_bytes(); // TODO: deprecated
    let pk64 = encode(&pk); // TODO: deprecated
    if verbose {
      println!("Trying: {}", pk64);
    }
    if regex.is_match(&pk64) {
      println!("Found: ssh-ed25519 {}", pk64);
      println!("{}", yes);
      if yes == false {
        if prompt_keep_looking() {
          buffer.set_wpos(buffer.get_wpos() - PUBLIC_KEY_LENGTH);
          continue;
        }
      }
      let sk64 = get_sk(&pk, keypair);
      if path.is_empty() {
        println!("-----BEGIN OPENSSH PRIVATE KEY-----");
        println!("{}", sk64);
        println!("-----END OPENSSH PRIVATE KEY-----");
        // This makes sense, right?
        println!("-----BEGIN OPENSSH PUBLIC KEY-----");
        println!("{}", pk64);
        println!("-----END OPENSSH PUBLIC KEY-----");
      } else {
        let mut file = File::create(path.clone())?;
        let mut file_pub = File::create(path.clone() + ".pub")?;
        if cfg!(unix) {
          file.set_permissions(Permissions::from_mode(0o600))?;
        }
        writeln!(file, "-----BEGIN OPENSSH PRIVATE KEY-----")?;
        writeln!(file, "{}", sk64)?;
        writeln!(file, "-----END OPENSSH PRIVATE KEY-----")?;
        println!("Wrote private key to: {}", path);
        // This makes sense, right?
        writeln!(file_pub, "-----BEGIN OPENSSH PUBLIC KEY-----")?;
        writeln!(file_pub, "{}", pk64)?;
        writeln!(file_pub, "-----END OPENSSH PUBLIC KEY-----")?;
        println!("Wrote public key to: {}", path + ".pub");
      }
      return Ok((pattern, pk64));
    }
    buffer.set_wpos(buffer.get_wpos() - PUBLIC_KEY_LENGTH);
  }
}

fn main() -> std::process::ExitCode {
  let args = Args::parse();
  let verbose = args.verbose;
  let yes = args.yes;
  let pattern = args.pattern;
  let path = args.out;
  let start = std::time::Instant::now();
  if verbose {
    println!("Verbose mode");
    println!("Pattern: {}", pattern);
    println!("Out path: {}", path);
    println!("Start time: {:?}", start);
  }
  let result = run(pattern, path, verbose, yes);
  let end = start.elapsed();
  match result {
    Ok(returns  ) => {
        println!("Found a key containing \"{}\" in {:?}", returns.0, end);
        std::process::ExitCode::SUCCESS
    }
    Err(e) => {
        eprintln!("Error: {}", e);
        std::process::ExitCode::FAILURE
    }
  }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_valid() {
      let pattern = "aa";
      let path = "";
      let verbose = true;
      let result = run(pattern.to_string(), path.to_string(), verbose, true).unwrap();
      let (returned_pattern, returned_key) = result;
      assert_eq!(returned_pattern, pattern);
      assert_eq!(returned_key.contains(pattern), true);
    }

    #[test]
    fn test_generate_invalid() {
      let pattern = "**(0";
      let path = "";
      let verbose = true;
      let result = run(pattern.to_string(), path.to_string(), verbose, true);
      assert_eq!(result.unwrap_err().to_string(), "Pattern must be alphanumeric");
    }
}