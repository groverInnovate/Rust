//This code generates a public key from a private key 

//private key -  random 32 byte hex string
use hex::decode;
use hex::encode;
use k256::NonZeroScalar;
use k256::PublicKey;
use k256::AffinePoint;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use tiny_keccak::{Hasher, Keccak};
fn main() {
let private_key = String::from("f8f8a2f43c8376ccb0871305060d7b27b0554d2cc72bccf41b2705608452f315");
let private_key_in_bytes = decode(private_key).unwrap(); //Decode returns result, In rust we can't directly Use result, we need to unwrap it first
//Convert private key in bytes to NonZeroScalar
let private_key_in_non_zero_scalar = NonZeroScalar::try_from(private_key_in_bytes.as_slice()).unwrap(); //I was using from_uint here instead of try_from because I couldn't find it in Docs of implementation of NonZeroScalar. TryFrom Came from the Trait Implementation Section!
let public_key = PublicKey::from_secret_scalar(&private_key_in_non_zero_scalar);
//Needs to be converted to AffinePoint to use to_encoded_point
let pub_key_affine_point = AffinePoint::from(&public_key);
let public_key_uncompressed = AffinePoint::to_encoded_point(&pub_key_affine_point,false);
println!("{:?}", public_key_uncompressed);
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
println!("{:?}", address);


}
