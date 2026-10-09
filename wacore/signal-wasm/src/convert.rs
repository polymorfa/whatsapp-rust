//! Conversions between JS values and the ops/record types.

use js_sys::{Array, Error, Object, Reflect, Uint8Array};
use std::sync::Arc;
use wacore::libsignal::protocol::{DeviceId, ProtocolAddress};
use wacore_recordstore::{Fence, Lease};
use wacore_signal_ops::{OpsError, PublicIdentity, PublicPreKey, PublicSignedPreKey, RemoteBundle};
use wasm_bindgen::{JsCast, JsValue};

pub fn set(target: &Object, key: &str, value: &JsValue) {
    // Setting a property on a plain object we just created cannot fail.
    let _ = Reflect::set(target, &JsValue::from_str(key), value);
}

fn get(source: &JsValue, key: &str) -> JsValue {
    Reflect::get(source, &JsValue::from_str(key)).unwrap_or(JsValue::UNDEFINED)
}

/// A JS `Error` with a machine-readable `code`.
pub fn coded_error(code: &str, message: &str) -> JsValue {
    let error = Error::new(message);
    set(&error, "code", &JsValue::from_str(code));
    error.into()
}

pub fn ops_error(error: OpsError) -> JsValue {
    if error.is_fence_lost() {
        return coded_error("fence_lost", "another holder took this scope");
    }
    match error {
        OpsError::Pairing { code, text } => {
            let js = coded_error("pairing_refused", text);
            set(
                js.unchecked_ref(),
                "status",
                &JsValue::from_f64(f64::from(code)),
            );
            js
        }
        OpsError::InvalidInput(message) => coded_error("invalid_input", &message),
        OpsError::NotInitialised => coded_error("not_initialised", "scope has no device keys"),
        OpsError::Signal(e) => coded_error("signal", &e.to_string()),
        OpsError::Store(e) => coded_error("store", &error_chain(&e)),
    }
}

fn error_chain(error: &dyn std::error::Error) -> String {
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(inner) = source {
        message.push_str(": ");
        message.push_str(&inner.to_string());
        source = inner.source();
    }
    message
}

pub fn address(user: &str, device: u32) -> ProtocolAddress {
    ProtocolAddress::new(user, DeviceId::from(device))
}

fn bytes(value: &[u8]) -> JsValue {
    Uint8Array::from(value).into()
}

pub fn signed_prekey(key: &PublicSignedPreKey) -> JsValue {
    let out = Object::new();
    set(&out, "id", &JsValue::from_f64(f64::from(key.id)));
    set(&out, "publicKey", &bytes(&key.public_key));
    set(&out, "signature", &bytes(&key.signature));
    out.into()
}

pub fn public_identity(identity: &PublicIdentity) -> JsValue {
    let out = Object::new();
    set(
        &out,
        "registrationId",
        &JsValue::from_f64(f64::from(identity.registration_id)),
    );
    set(&out, "identityKey", &bytes(&identity.identity_key));
    set(
        &out,
        "signedPrekey",
        &signed_prekey(&identity.signed_prekey),
    );
    set(&out, "advSecret", &bytes(&identity.adv_secret));
    out.into()
}

pub fn public_prekeys(keys: &[PublicPreKey]) -> JsValue {
    let list = Array::new();
    for key in keys {
        let item = Object::new();
        set(&item, "id", &JsValue::from_f64(f64::from(key.id)));
        set(&item, "publicKey", &bytes(&key.public_key));
        list.push(&item);
    }
    list.into()
}

fn invalid(message: &str) -> JsValue {
    coded_error("invalid_input", message)
}

fn u32_field(source: &JsValue, key: &str) -> Result<u32, JsValue> {
    let value = get(source, key)
        .as_f64()
        .ok_or_else(|| invalid(&format!("{key} must be a number")))?;
    if value.fract() != 0.0 || !(0.0..=f64::from(u32::MAX)).contains(&value) {
        return Err(invalid(&format!("{key} must be a 32-bit unsigned integer")));
    }
    Ok(value as u32)
}

fn fixed_bytes<const N: usize>(source: &JsValue, key: &str) -> Result<[u8; N], JsValue> {
    let value = get(source, key);
    let array: Uint8Array = value
        .dyn_into()
        .map_err(|_| invalid(&format!("{key} must be a Uint8Array")))?;
    array
        .to_vec()
        .try_into()
        .map_err(|_| invalid(&format!("{key} must be {N} bytes")))
}

pub fn remote_bundle(value: &JsValue) -> Result<RemoteBundle, JsValue> {
    let prekey = if get(value, "prekey").is_undefined() || get(value, "prekey").is_null() {
        None
    } else {
        Some((u32_field(value, "prekeyId")?, fixed_bytes(value, "prekey")?))
    };
    Ok(RemoteBundle {
        registration_id: u32_field(value, "registrationId")?,
        device_id: u32_field(value, "deviceId")?,
        identity_key: fixed_bytes(value, "identityKey")?,
        signed_prekey_id: u32_field(value, "signedPrekeyId")?,
        signed_prekey: fixed_bytes(value, "signedPrekey")?,
        signed_prekey_signature: fixed_bytes(value, "signedPrekeySignature")?,
        prekey,
    })
}

/// Generations and expiry times travel as JS numbers; both stay far below
/// 2^53 in practice, and the conversion rejects anything that is not.
fn safe_u64(value: f64, what: &str) -> Result<u64, String> {
    if value.fract() != 0.0 || !(0.0..=9_007_199_254_740_991.0).contains(&value) {
        return Err(format!("{what} must be a non-negative safe integer"));
    }
    Ok(value as u64)
}

pub fn fence_to_js(fence: &Fence) -> JsValue {
    let out = Object::new();
    set(&out, "scope", &JsValue::from_str(&fence.scope));
    set(
        &out,
        "generation",
        &JsValue::from_f64(fence.generation as f64),
    );
    out.into()
}

pub fn lease_to_js(lease: &Lease) -> JsValue {
    let out = Object::new();
    set(&out, "scope", &JsValue::from_str(&lease.fence.scope));
    set(
        &out,
        "generation",
        &JsValue::from_f64(lease.fence.generation as f64),
    );
    set(&out, "holder", &JsValue::from_str(&lease.holder));
    set(
        &out,
        "expiresAtMs",
        &JsValue::from_f64(lease.expires_at_ms as f64),
    );
    out.into()
}

pub fn to_lease(value: &JsValue) -> Result<Lease, String> {
    let scope = get(value, "scope")
        .as_string()
        .ok_or("lease.scope must be a string")?;
    let holder = get(value, "holder")
        .as_string()
        .ok_or("lease.holder must be a string")?;
    let generation = safe_u64(
        get(value, "generation")
            .as_f64()
            .ok_or("lease.generation must be a number")?,
        "lease.generation",
    )?;
    let expires_at_ms = safe_u64(
        get(value, "expiresAtMs")
            .as_f64()
            .ok_or("lease.expiresAtMs must be a number")?,
        "lease.expiresAtMs",
    )?;
    Ok(Lease {
        fence: Fence {
            scope: Arc::from(scope),
            generation,
        },
        holder: Arc::from(holder),
        expires_at_ms,
    })
}
