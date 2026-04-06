//This code generates Ethereum Address from a private key

use hex::{decode, encode};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{AffinePoint, NonZeroScalar, PublicKey};
use std::io;
use tiny_keccak::{Hasher, Keccak};
fn main() {
    println!("Enter your 32 bytes private key ");
    //Sample Private Key - f8f8a2f43c8376ccb0871305060d7b27b0554d2cc72bccf41b2705608452f315
    let mut private_key = String::new();
    io::stdin()
        .read_line(&mut private_key)
        .expect("Failed to read line");
    //Add a check here to validate private key has
    let private_key: String = private_key
        .trim()
        .parse()
        .expect("Please type a correct Private key");
    let private_key_in_bytes = decode(private_key).unwrap(); //Decode returns result, In rust we can't directly Use result, we need to unwrap it first
    //Convert private key in bytes to NonZeroScalar
    let private_key_in_non_zero_scalar =
        NonZeroScalar::try_from(private_key_in_bytes.as_slice()).unwrap(); //I was using from_uint here instead of try_from because I couldn't find it in Docs of implementation of NonZeroScalar. TryFrom Came from the Trait Implementation Section!
    //Calculate the Public Key
    let public_key = PublicKey::from_secret_scalar(&private_key_in_non_zero_scalar);
    //Needs to be converted to AffinePoint to use to_encoded_point
    let pub_key_affine_point = AffinePoint::from(&public_key);
    let public_key_uncompressed = AffinePoint::to_encoded_point(&pub_key_affine_point, false);
    //println!("{:?}", public_key_uncompressed);
    // This shows as x and y coordinates, needs to be converted in simple bytes
    let public_key_uncompressed_bytes = public_key_uncompressed.as_bytes();
    // Skip the 1st byte i.e. 4
    let public_key_with_skipped_byte = &public_key_uncompressed_bytes[1..];
    //Apply keccak256 on this
    let mut hasher = Keccak::v256(); //Hasher trait Hashes any arbitrary stream of bytes

    let mut output = [0u8; 32];
    hasher.update(public_key_with_skipped_byte);
    hasher.finalize(&mut output);
    // Taking the last 20 bytes
    let last_20_bytes = &output[12..];
    let address = encode(last_20_bytes);
    println!("Ethereum address :{:?}", address);

    //Applying EIP-55 checksum Format

    //Hashing the lowercase hex string
    let mut hasher2 = Keccak::v256();

    let mut keccak_hash = [0u8; 32];
    hasher2.update(address.as_bytes());
    hasher2.finalize(&mut keccak_hash);
    println! {"Hashed Address is {:?}", encode(keccak_hash)};
    //Creating a New String
    let mut checksum_address = String::new();
    //Comparing address to hash, for every alphabet in address if the corresponding hex in keccak hash is greater than 8, the alphabet will be capitalised
    for (i, ch) in address.chars().enumerate() {
        if ch.is_alphabetic() {
            let nibble = if i % 2 == 0 {
                keccak_hash[i / 2] >> 4
            } else {
                keccak_hash[i / 2] & 0x0f
            };

            if nibble >= 8 {
                checksum_address.push(ch.to_ascii_uppercase());
            } else {
                checksum_address.push(ch.to_ascii_lowercase());
            }
        } else {
            checksum_address.push(ch);
        }
    }
    println!("The checksum address is : {:?}", checksum_address);
}
