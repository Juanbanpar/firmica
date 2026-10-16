//! JNI boundary called only by the Dioxus MainActivity override.

use firmica_protocol::MAX_URI_BYTES;
use jni::{
    objects::{JObject, JString},
    sys::{jboolean, JNI_FALSE, JNI_TRUE},
    JNIEnv,
};

/// Receives a bounded URI after Wry has loaded the native library. No invocation
/// value is logged and no network, file, or signing operation is started here.
#[no_mangle]
pub extern "system" fn Java_dev_dioxus_main_MainActivity_receiveInvocation(
    mut env: JNIEnv<'_>,
    _activity: JObject<'_>,
    uri: JString<'_>,
) -> jboolean {
    let result = (|| -> jni::errors::Result<bool> {
        // Bound the conversion before allocating a Rust String. UTF-8 byte size
        // is checked again by the shared parser after modified UTF-8 conversion.
        let units = env.call_method(&uri, "length", "()I", &[])?.i()?;
        if units < 0 || units as usize > MAX_URI_BYTES {
            return Ok(false);
        }
        let java = env.get_string(&uri)?;
        // jni's String conversion is lossy for unpaired UTF-16 surrogates.
        let Ok(text) = cesu8::from_java_cesu8(java.to_bytes()) else {
            return Ok(false);
        };
        Ok(super::receive_invocation(&text))
    })();
    match result {
        Ok(true) => JNI_TRUE,
        Ok(false) => JNI_FALSE,
        Err(_) => {
            // Return rejection rather than leaving a pending JNI exception.
            let _ = env.exception_clear();
            JNI_FALSE
        }
    }
}
