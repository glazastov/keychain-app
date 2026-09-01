//! JNI bridge exposing post-quantum primitives from liboqs (ML-KEM / ML-DSA)
//! to the Kotlin `:crypto-pqc` module.
//!
//! This crate is original code: it does not link against, wrap, or derive
//! from any OpenKeychain (GPL) source. It knows nothing about OpenPGP packet
//! formats, keyrings, or passphrase caching — those concerns live entirely
//! in `:crypto-pqc` (Kotlin), which calls into this crate only for the raw
//! algorithm operations (keygen / encapsulate / decapsulate / sign / verify).

use jni::objects::{JByteArray, JClass};
use jni::sys::jbyteArray;
use jni::JNIEnv;
use oqs::kem::{self, Kem};
use oqs::sig::{self, Sig};

/// Kyber/ML-KEM-768 is used as the default KEM: NIST security level 3,
/// matches the level most OpenPGP-PQC drafts pair with Curve25519/P-384 hybrids.
const KEM_ALG: kem::Algorithm = kem::Algorithm::MlKem768;
/// Dilithium/ML-DSA-65 is used as the default signature scheme (level 3).
const SIG_ALG: sig::Algorithm = sig::Algorithm::MlDsa65;

fn init() {
    oqs::init();
}

fn throw_and_default(env: &mut JNIEnv, msg: &str) -> jbyteArray {
    let _ = env.throw_new("java/security/GeneralSecurityException", msg);
    std::ptr::null_mut()
}

fn to_jbytearray<'l>(env: &JNIEnv<'l>, data: &[u8]) -> jni::errors::Result<JByteArray<'l>> {
    let arr = env.new_byte_array(data.len() as i32)?;
    env.set_byte_array_region(&arr, 0, bytemuck_i8(data))?;
    Ok(arr)
}

// jni's set_byte_array_region wants &[i8]; bytes are the same bits as u8.
fn bytemuck_i8(data: &[u8]) -> &[i8] {
    // Safety: u8 and i8 have identical size/alignment; this is a reinterpret, not a transmute of ownership.
    unsafe { std::slice::from_raw_parts(data.as_ptr() as *const i8, data.len()) }
}

fn jbytearray_to_vec(env: &JNIEnv, arr: &JByteArray) -> jni::errors::Result<Vec<u8>> {
    let signed = env.convert_byte_array(arr)?;
    Ok(signed)
}

/// Generates an ML-KEM-768 keypair. Returns a Java `byte[][]{ publicKey, secretKey }`
/// via two out-params instead (JNI has no easy multi-return), see the paired
/// getters below — kept simple: we return the concatenation `pk || sk` and let
/// the Kotlin side slice it using the known fixed lengths for the algorithm.
#[no_mangle]
pub extern "system" fn Java_com_keychain_crypto_pqc_native_KemNative_generateKeypair(
    mut env: JNIEnv,
    _class: JClass,
) -> jbyteArray {
    init();
    let kem = match Kem::new(KEM_ALG) {
        Ok(k) => k,
        Err(e) => return throw_and_default(&mut env, &format!("KEM init failed: {e}")),
    };
    let (pk, sk) = match kem.keypair() {
        Ok(pair) => pair,
        Err(e) => return throw_and_default(&mut env, &format!("keypair() failed: {e}")),
    };
    let mut combined = Vec::with_capacity(pk.as_ref().len() + sk.as_ref().len());
    combined.extend_from_slice(pk.as_ref());
    combined.extend_from_slice(sk.as_ref());
    match to_jbytearray(&env, &combined) {
        Ok(arr) => arr.into_raw(),
        Err(e) => throw_and_default(&mut env, &format!("JNI array conversion failed: {e}")),
    }
}

/// Encapsulates against `publicKey`, returning `ciphertext || sharedSecret`.
#[no_mangle]
pub extern "system" fn Java_com_keychain_crypto_pqc_native_KemNative_encapsulate<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    public_key: JByteArray<'l>,
) -> jbyteArray {
    init();
    let kem = match Kem::new(KEM_ALG) {
        Ok(k) => k,
        Err(e) => return throw_and_default(&mut env, &format!("KEM init failed: {e}")),
    };
    let pk_bytes = match jbytearray_to_vec(&env, &public_key) {
        Ok(b) => b,
        Err(e) => return throw_and_default(&mut env, &format!("bad public key: {e}")),
    };
    let pk = match kem.public_key_from_bytes(&pk_bytes) {
        Some(pk) => pk,
        None => return throw_and_default(&mut env, "public key has wrong length for MlKem768"),
    };
    let (ct, ss) = match kem.encapsulate(pk) {
        Ok(pair) => pair,
        Err(e) => return throw_and_default(&mut env, &format!("encapsulate() failed: {e}")),
    };
    let mut combined = Vec::with_capacity(ct.as_ref().len() + ss.as_ref().len());
    combined.extend_from_slice(ct.as_ref());
    combined.extend_from_slice(ss.as_ref());
    match to_jbytearray(&env, &combined) {
        Ok(arr) => arr.into_raw(),
        Err(e) => throw_and_default(&mut env, &format!("JNI array conversion failed: {e}")),
    }
}

/// Decapsulates `ciphertext` using `secretKey`, returning the shared secret.
#[no_mangle]
pub extern "system" fn Java_com_keychain_crypto_pqc_native_KemNative_decapsulate<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    secret_key: JByteArray<'l>,
    ciphertext: JByteArray<'l>,
) -> jbyteArray {
    init();
    let kem = match Kem::new(KEM_ALG) {
        Ok(k) => k,
        Err(e) => return throw_and_default(&mut env, &format!("KEM init failed: {e}")),
    };
    let sk_bytes = match jbytearray_to_vec(&env, &secret_key) {
        Ok(b) => b,
        Err(e) => return throw_and_default(&mut env, &format!("bad secret key: {e}")),
    };
    let ct_bytes = match jbytearray_to_vec(&env, &ciphertext) {
        Ok(b) => b,
        Err(e) => return throw_and_default(&mut env, &format!("bad ciphertext: {e}")),
    };
    let sk = match kem.secret_key_from_bytes(&sk_bytes) {
        Some(sk) => sk,
        None => return throw_and_default(&mut env, "secret key has wrong length for MlKem768"),
    };
    let ct = match kem.ciphertext_from_bytes(&ct_bytes) {
        Some(ct) => ct,
        None => return throw_and_default(&mut env, "ciphertext has wrong length for MlKem768"),
    };
    let ss = match kem.decapsulate(sk, ct) {
        Ok(ss) => ss,
        Err(e) => return throw_and_default(&mut env, &format!("decapsulate() failed: {e}")),
    };
    match to_jbytearray(&env, ss.as_ref()) {
        Ok(arr) => arr.into_raw(),
        Err(e) => throw_and_default(&mut env, &format!("JNI array conversion failed: {e}")),
    }
}

/// Generates an ML-DSA-65 keypair, returning `publicKey || secretKey`.
#[no_mangle]
pub extern "system" fn Java_com_keychain_crypto_pqc_native_SigNative_generateKeypair(
    mut env: JNIEnv,
    _class: JClass,
) -> jbyteArray {
    init();
    let signer = match Sig::new(SIG_ALG) {
        Ok(s) => s,
        Err(e) => return throw_and_default(&mut env, &format!("Sig init failed: {e}")),
    };
    let (pk, sk) = match signer.keypair() {
        Ok(pair) => pair,
        Err(e) => return throw_and_default(&mut env, &format!("keypair() failed: {e}")),
    };
    let mut combined = Vec::with_capacity(pk.as_ref().len() + sk.as_ref().len());
    combined.extend_from_slice(pk.as_ref());
    combined.extend_from_slice(sk.as_ref());
    match to_jbytearray(&env, &combined) {
        Ok(arr) => arr.into_raw(),
        Err(e) => throw_and_default(&mut env, &format!("JNI array conversion failed: {e}")),
    }
}

/// Signs `message` with `secretKey`, returning the detached signature.
#[no_mangle]
pub extern "system" fn Java_com_keychain_crypto_pqc_native_SigNative_sign<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    secret_key: JByteArray<'l>,
    message: JByteArray<'l>,
) -> jbyteArray {
    init();
    let signer = match Sig::new(SIG_ALG) {
        Ok(s) => s,
        Err(e) => return throw_and_default(&mut env, &format!("Sig init failed: {e}")),
    };
    let sk_bytes = match jbytearray_to_vec(&env, &secret_key) {
        Ok(b) => b,
        Err(e) => return throw_and_default(&mut env, &format!("bad secret key: {e}")),
    };
    let msg_bytes = match jbytearray_to_vec(&env, &message) {
        Ok(b) => b,
        Err(e) => return throw_and_default(&mut env, &format!("bad message: {e}")),
    };
    let sk = match signer.secret_key_from_bytes(&sk_bytes) {
        Some(sk) => sk,
        None => return throw_and_default(&mut env, "secret key has wrong length for MlDsa65"),
    };
    let sig = match signer.sign(&msg_bytes, sk) {
        Ok(s) => s,
        Err(e) => return throw_and_default(&mut env, &format!("sign() failed: {e}")),
    };
    match to_jbytearray(&env, sig.as_ref()) {
        Ok(arr) => arr.into_raw(),
        Err(e) => throw_and_default(&mut env, &format!("JNI array conversion failed: {e}")),
    }
}

/// Verifies `signature` over `message` against `publicKey`. Returns a Java boolean (jni::sys::jboolean).
#[no_mangle]
pub extern "system" fn Java_com_keychain_crypto_pqc_native_SigNative_verify<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    public_key: JByteArray<'l>,
    message: JByteArray<'l>,
    signature: JByteArray<'l>,
) -> jni::sys::jboolean {
    init();
    let signer = match Sig::new(SIG_ALG) {
        Ok(s) => s,
        Err(e) => {
            let _ = env.throw_new("java/security/GeneralSecurityException", format!("Sig init failed: {e}"));
            return 0;
        }
    };
    let pk_bytes = match jbytearray_to_vec(&env, &public_key) {
        Ok(b) => b,
        Err(e) => {
            let _ = env.throw_new("java/security/GeneralSecurityException", format!("bad public key: {e}"));
            return 0;
        }
    };
    let msg_bytes = match jbytearray_to_vec(&env, &message) {
        Ok(b) => b,
        Err(e) => {
            let _ = env.throw_new("java/security/GeneralSecurityException", format!("bad message: {e}"));
            return 0;
        }
    };
    let sig_bytes = match jbytearray_to_vec(&env, &signature) {
        Ok(b) => b,
        Err(e) => {
            let _ = env.throw_new("java/security/GeneralSecurityException", format!("bad signature: {e}"));
            return 0;
        }
    };
    let pk = match signer.public_key_from_bytes(&pk_bytes) {
        Some(pk) => pk,
        None => return 0,
    };
    let sig = match signer.signature_from_bytes(&sig_bytes) {
        Some(sig) => sig,
        None => return 0,
    };
    match signer.verify(&msg_bytes, sig, pk) {
        Ok(()) => 1,
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kem_roundtrip() {
        oqs::init();
        let kem = Kem::new(KEM_ALG).expect("kem init");
        let (pk, sk) = kem.keypair().expect("keypair");
        let (ct, ss1) = kem.encapsulate(&pk).expect("encapsulate");
        let ss2 = kem.decapsulate(&sk, &ct).expect("decapsulate");
        assert_eq!(ss1.as_ref(), ss2.as_ref());
    }

    #[test]
    fn sig_roundtrip() {
        oqs::init();
        let signer = Sig::new(SIG_ALG).expect("sig init");
        let (pk, sk) = signer.keypair().expect("keypair");
        let msg = b"crypto-pqc: original code, no OpenKeychain GPL lineage";
        let sig = signer.sign(msg, &sk).expect("sign");
        signer.verify(msg, &sig, &pk).expect("verify should succeed");

        let tampered = b"crypto-pqc: original code, no OpenKeychain GPL LINEAGE";
        assert!(signer.verify(tampered, &sig, &pk).is_err());
    }
}
