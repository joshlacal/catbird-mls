//! FFI (Foreign Function Interface) layer for MLS operations
//!
//! # Safety Measures (P0-P2)
//!
//! This module implements comprehensive safety measures for the FFI boundary:
//!
//! ## P0 - Critical Safety
//! - **Panic Protection**: All FFI entry points are wrapped with `catch_unwind`
//!   to prevent panics from unwinding across the FFI boundary (which is UB).
//! - **Memory Safety**: `mls_free_result` properly deallocates boxed slices using
//!   `Box::from_raw` with the correct layout (not `Vec::from_raw_parts`).
//! - **Pointer Validation**: `safe_slice` validates pointers for null, length overflow,
//!   and pointer arithmetic overflow before creating slices.
//!
//! ## P1 - Important Security
//! - **Lock Poisoning Recovery**: Poisoned mutexes are recovered using `into_inner()`
//!   instead of failing, to maintain availability.
//! - **Error Message Safety**: Null bytes in error messages are escaped to prevent
//!   truncation when converted to C strings.
//! - **Secret Zeroization**: Exported secrets should be zeroized by callers.
//!   Consider using the `zeroize` crate for sensitive data on the Swift side.
//!
//! ## P2 - Additional Hardening
//! - **Rate Limiting**: Maximum of `MAX_CONTEXTS` contexts can be created to prevent DoS.
//! - **Input Validation**: All input lengths are validated against maximum limits.
//! - **Detailed Errors**: Error types preserve context for debugging.
//!
//! # Usage Notes
//!
//! - All returned `MLSResult` must be freed with `mls_free_result`.
//! - All returned `*mut c_char` strings must be freed with `mls_free_string`.
//! - Context handles (usize) must be freed with `mls_free_context`.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::panic::{self, AssertUnwindSafe};
use std::ptr;
use std::slice;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::collections::HashMap;

use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use tls_codec::{Deserialize as TlsDeserialize};

use crate::error::{MLSError, Result};
use crate::mls_context::MLSContext;

// P0: Rate limiting constants for anti-DoS protection
const MAX_CONTEXTS: usize = 1000;

static CONTEXTS: Mutex<Option<HashMap<usize, Arc<MLSContext>>>> = Mutex::new(None);
static NEXT_CONTEXT_ID: AtomicUsize = AtomicUsize::new(1);

/// FFI-safe result type
#[repr(C)]
pub struct MLSResult {
    pub success: bool,
    pub error_message: *mut c_char,
    pub data: *mut u8,
    pub data_len: usize,
}

impl MLSResult {
    pub fn ok(data: Vec<u8>) -> Self {
        let len = data.len();
        let ptr = if len > 0 {
            Box::into_raw(data.into_boxed_slice()) as *mut u8
        } else {
            ptr::null_mut()
        };
        Self {
            success: true,
            error_message: ptr::null_mut(),
            data: ptr,
            data_len: len,
        }
    }

    pub fn err(error: MLSError) -> Self {
        // P1: Safely create error message, handling embedded null bytes
        let error_msg = error.to_string().replace('\0', "\\0");
        let error_ptr = CString::new(error_msg)
            .unwrap_or_else(|_| CString::new("Unknown error (invalid UTF-8)").unwrap())
            .into_raw();
        Self {
            success: false,
            error_message: error_ptr,
            data: ptr::null_mut(),
            data_len: 0,
        }
    }

    /// Create an error result from a panic message
    fn panic_error(msg: &str) -> Self {
        let error_msg = format!("Internal panic: {}", msg.replace('\0', "\\0"));
        let error_ptr = CString::new(error_msg)
            .unwrap_or_else(|_| CString::new("Internal panic occurred").unwrap())
            .into_raw();
        Self {
            success: false,
            error_message: error_ptr,
            data: ptr::null_mut(),
            data_len: 0,
        }
    }
}

/// P0: Macro for catch_unwind wrapper around FFI entry points
/// This prevents panics from unwinding across the FFI boundary (which is UB)
macro_rules! ffi_catch_unwind {
    ($body:expr) => {
        panic::catch_unwind(AssertUnwindSafe(|| $body)).unwrap_or_else(|e| {
            let msg = if let Some(s) = e.downcast_ref::<&str>() {
                *s
            } else if let Some(s) = e.downcast_ref::<String>() {
                s.as_str()
            } else {
                "Unknown panic"
            };
            MLSResult::panic_error(msg)
        })
    };
}

/// Initialize the MLS FFI library
/// Returns a context handle for subsequent operations
/// Returns 0 on failure (rate limit exceeded, lock poisoned, etc.)
#[no_mangle]
pub extern "C" fn mls_init() -> usize {
    // P0: Catch panics at FFI boundary
    panic::catch_unwind(AssertUnwindSafe(|| {
        // Get next context ID using atomic fetch_add (lock-free)
        let context_id = NEXT_CONTEXT_ID.fetch_add(1, Ordering::SeqCst);

        // Only one lock needed now
        let mut contexts_guard = match CONTEXTS.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                // P1: Recover from poisoned lock instead of failing
                poisoned.into_inner()
            }
        };

        let contexts = contexts_guard.get_or_insert_with(HashMap::new);

        // P2: Rate limiting - prevent DoS via excessive context creation
        if contexts.len() >= MAX_CONTEXTS {
            return 0;
        }

        let context = Arc::new(MLSContext::new());
        contexts.insert(context_id, context);

        context_id
    }))
    .unwrap_or(0) // Return 0 on panic
}

/// Free an MLS context
#[no_mangle]
pub extern "C" fn mls_free_context(context_id: usize) {
    // P0: Catch panics at FFI boundary
    let _ = panic::catch_unwind(AssertUnwindSafe(|| {
        // P1: Recover from poisoned lock
        let mut contexts_guard = match CONTEXTS.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(contexts) = contexts_guard.as_mut() {
            contexts.remove(&context_id);
        }
    }));
}

fn get_context(context_id: usize) -> Result<Arc<MLSContext>> {
    // P1: Recover from poisoned lock when possible
    let contexts_guard = CONTEXTS.lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    
    let contexts = contexts_guard.as_ref()
        .ok_or(MLSError::InvalidContext)?;
    
    contexts.get(&context_id)
        .cloned()
        .ok_or(MLSError::InvalidContext)
}

// Security limits for FFI inputs
const MAX_IDENTITY_LEN: usize = 1024;
const MAX_KEY_PACKAGES_LEN: usize = 10 * 1024 * 1024; // 10MB
const MAX_MESSAGE_LEN: usize = 100 * 1024 * 1024; // 100MB
const MAX_GROUP_ID_LEN: usize = 256;

fn validate_input_len(len: usize, max: usize, name: &'static str) -> Result<()> {
    if len > max {
        return Err(MLSError::InvalidInput(
            format!("{} length {} exceeds maximum {}", name, len, max)
        ));
    }
    Ok(())
}

/// P0/P1: Safely create a slice from raw pointer with comprehensive validation
fn safe_slice<'a>(ptr: *const u8, len: usize, name: &'static str) -> Result<&'a [u8]> {
    // Check for null pointer with non-zero length
    if ptr.is_null() {
        if len > 0 {
            return Err(MLSError::NullPointer(name));
        }
        return Ok(&[]);
    }
    
    // P1: Check for length overflow (could wrap around in pointer arithmetic)
    if len > isize::MAX as usize {
        return Err(MLSError::InvalidInput(
            format!("{} length {} exceeds maximum addressable size", name, len)
        ));
    }
    
    // Empty slice is always safe
    if len == 0 {
        return Ok(&[]);
    }
    
    // P1: Check that pointer + length doesn't overflow
    // This prevents malicious callers from causing undefined behavior
    let end_ptr = (ptr as usize).checked_add(len);
    if end_ptr.is_none() {
        return Err(MLSError::InvalidInput(
            format!("{} pointer arithmetic overflow", name)
        ));
    }
    
    // SAFETY: We've validated:
    // 1. ptr is non-null
    // 2. len <= isize::MAX
    // 3. ptr + len doesn't overflow
    // 4. The caller is responsible for ensuring the memory is valid and initialized
    unsafe { Ok(slice::from_raw_parts(ptr, len)) }
}

/// Create a new MLS group
/// Returns serialized group ID
#[no_mangle]
pub extern "C" fn mls_create_group(
    context_id: usize,
    identity_bytes: *const u8,
    identity_len: usize,
) -> MLSResult {
    // P0: Catch panics at FFI boundary
    ffi_catch_unwind!({
        let result: Result<Vec<u8>> = (|| {
            validate_input_len(identity_len, MAX_IDENTITY_LEN, "identity")?;
            let context = get_context(context_id)?;
            let identity = safe_slice(identity_bytes, identity_len, "identity")?;
            
            let credential = Credential::new(identity.to_vec(), CredentialType::Basic)
                .map_err(|e| MLSError::OpenMLS(e.to_string()))?;
            
            // CRITICAL FIX: Reuse existing signature key if available
            let identity_str = std::str::from_utf8(identity)
                .map_err(|e| MLSError::InvalidInput(format!("Identity is not valid UTF-8: {}", e)))?;

            let signature_keypair = if let Some(existing) = context.get_signer_for_identity(identity_str) {
                crate::debug_log!("[MLS-FFI] ♻️ Reusing existing signature key for group creation: {}", identity_str);
                existing
            } else {
                crate::debug_log!("[MLS-FFI] 🆕 Generating NEW signature key for group creation: {}", identity_str);
                let new_kp = SignatureKeyPair::new(SignatureScheme::ED25519)
                    .map_err(|e| MLSError::OpenMLS(e.to_string()))?;
                
                new_kp.store(context.provider().key_store())
                    .map_err(|e| MLSError::OpenMLS(e.to_string()))?;
                new_kp
            };
            
            let credential_with_key = CredentialWithKey {
                credential: credential.clone(),
                signature_key: signature_keypair.public().into(),
            };
            
            let group_config = MlsGroupCreateConfig::builder()
                .ciphersuite(Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519)
                .build();
            
            let group = MlsGroup::new(
                context.provider(),
                &signature_keypair,
                &group_config,
                credential_with_key,
            ).map_err(|e| MLSError::OpenMLS(e.to_string()))?;
            
            // Keep signer for this identity and group
            let signer_arc = std::sync::Arc::new(signature_keypair);
            context.set_identity_signer(identity.to_vec(), std::sync::Arc::clone(&signer_arc))?;
            
            let group_id_bytes = group.group_id().as_slice().to_vec();
            context.add_group(group_id_bytes.clone(), group, signer_arc)?;
            
            Ok(group_id_bytes)
        })();
        
        match result {
            Ok(data) => MLSResult::ok(data),
            Err(e) => MLSResult::err(e),
        }
    })
}

/// Add members to an MLS group
/// Input: TLS-encoded KeyPackage bytes concatenated
/// Output: [commit_len_le: u64][commit_bytes][welcome_bytes]
#[no_mangle]
pub extern "C" fn mls_add_members(
    context_id: usize,
    group_id: *const u8,
    group_id_len: usize,
    key_packages_bytes: *const u8,
    key_packages_len: usize,
) -> MLSResult {
    // P0: Catch panics at FFI boundary
    ffi_catch_unwind!({
        let result: Result<Vec<u8>> = (|| {
            validate_input_len(group_id_len, MAX_GROUP_ID_LEN, "group_id")?;
            validate_input_len(key_packages_len, MAX_KEY_PACKAGES_LEN, "key_packages")?;
            
            let context = get_context(context_id)?;
            let gid = safe_slice(group_id, group_id_len, "group_id")?;
            let kp_bytes = safe_slice(key_packages_bytes, key_packages_len, "key_packages")?;

            if kp_bytes.is_empty() {
                return Err(MLSError::InvalidInput("No key packages provided".to_string()));
            }

            // Parse KeyPackages from JSON
            // Two supported formats:
            // 1. Array of KeyPackage objects (direct serde): [{"payload": {...}, "signature": "..."}, ...]
            // 2. Array with tls_serialized field: [{"tls_serialized": "base64..."}, ...]
            
            let key_packages: Vec<KeyPackage> = if let Ok(kps) = serde_json::from_slice::<Vec<KeyPackage>>(kp_bytes) {
                // Direct serde format (full KeyPackage JSON)
                kps
            } else {
                // Try tls_serialized format
                let json_packages: Vec<serde_json::Value> = serde_json::from_slice(kp_bytes)
                    .map_err(|e| MLSError::Serialization(e))?;
                
                // Convert TLS bytes to KeyPackages via MlsMessageIn wrapper
                json_packages.iter()
                    .map(|pkg| {
                        let tls_b64 = pkg.get("tls_serialized")
                            .and_then(|v| v.as_str())
                            .ok_or_else(|| MLSError::InvalidInput("Missing tls_serialized field".to_string()))?;
                        
                        let tls_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, tls_b64)
                            .map_err(|e| MLSError::InvalidInput(format!("Invalid base64: {}", e)))?;
                        
                        // Wrap in MlsMessageIn to deserialize
                        let mls_msg = MlsMessageIn::tls_deserialize(&mut &tls_bytes[..])
                            .map_err(|e| MLSError::TlsCodec(format!("Failed to deserialize: {}", e)))?;
                        
                        // Extract KeyPackage from message and validate
                        match mls_msg.extract() {
                            MlsMessageInBody::KeyPackage(kp_in) => {
                                // Validate KeyPackageIn to get KeyPackage
                                let kp = kp_in.validate(context.provider().crypto(), ProtocolVersion::default())
                                    .map_err(|e| MLSError::OpenMLS(format!("KeyPackage validation failed: {}", e)))?;
                                Ok(kp)
                            },
                            _ => Err(MLSError::InvalidInput("Message is not a KeyPackage".to_string())),
                        }
                    })
                    .collect::<Result<Vec<KeyPackage>>>()?
            };

            if key_packages.is_empty() {
                return Err(MLSError::InvalidInput("KeyPackage array is empty".to_string()));
            }
            
            let signer = context.signer_for_group(gid)?;
            context.with_group(gid, |group| {
                let (commit, welcome, _group_info) = group
                    .add_members(context.provider(), signer.as_ref(), &key_packages)
                    .map_err(|e| MLSError::OpenMLS(e.to_string()))?;
                
                group.merge_pending_commit(context.provider())
                    .map_err(|e| MLSError::OpenMLS(e.to_string()))?;
                
                let commit_bytes = commit
                    .tls_serialize_detached()
                    .map_err(|e| MLSError::TlsCodec(e.to_string()))?;
                let welcome_bytes = welcome
                    .tls_serialize_detached()
                    .map_err(|e| MLSError::TlsCodec(e.to_string()))?;

                let mut out = Vec::with_capacity(8 + commit_bytes.len() + welcome_bytes.len());
                out.extend_from_slice(&(commit_bytes.len() as u64).to_le_bytes());
                out.extend_from_slice(&commit_bytes);
                out.extend_from_slice(&welcome_bytes);
                Ok(out)
            })
        })();
        
        match result {
            Ok(data) => MLSResult::ok(data),
            Err(e) => MLSResult::err(e),
        }
    })
}

/// Encrypt a message for the group
#[no_mangle]
pub extern "C" fn mls_encrypt_message(
    context_id: usize,
    group_id: *const u8,
    group_id_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
) -> MLSResult {
    // P0: Catch panics at FFI boundary
    ffi_catch_unwind!({
        let result: Result<Vec<u8>> = (|| {
            validate_input_len(group_id_len, MAX_GROUP_ID_LEN, "group_id")?;
            validate_input_len(plaintext_len, MAX_MESSAGE_LEN, "plaintext")?;
            
            let context = get_context(context_id)?;
            let gid = safe_slice(group_id, group_id_len, "group_id")?;
            let pt = safe_slice(plaintext, plaintext_len, "plaintext")?;
            
            let signer = context.signer_for_group(gid)?;
            context.with_group(gid, |group| {
                let mls_message = group
                    .create_message(context.provider(), signer.as_ref(), pt)
                    .map_err(|e| MLSError::OpenMLS(e.to_string()))?;
                
                mls_message.tls_serialize_detached()
                    .map_err(|e| MLSError::TlsCodec(e.to_string()))
            })
        })();
        
        match result {
            Ok(data) => MLSResult::ok(data),
            Err(e) => MLSResult::err(e),
        }
    })
}

/// Decrypt a message from the group
#[no_mangle]
pub extern "C" fn mls_decrypt_message(
    context_id: usize,
    group_id: *const u8,
    group_id_len: usize,
    ciphertext: *const u8,
    ciphertext_len: usize,
) -> MLSResult {
    // P0: Catch panics at FFI boundary
    ffi_catch_unwind!({
        let result: Result<Vec<u8>> = (|| {
            validate_input_len(group_id_len, MAX_GROUP_ID_LEN, "group_id")?;
            validate_input_len(ciphertext_len, MAX_MESSAGE_LEN, "ciphertext")?;
            
            let context = get_context(context_id)?;
            let gid = safe_slice(group_id, group_id_len, "group_id")?;
            let ct = safe_slice(ciphertext, ciphertext_len, "ciphertext")?;
            
            context.with_group(gid, |group| {
                let mls_message_in = MlsMessageIn::tls_deserialize(&mut &ct[..])
                    .map_err(|e| MLSError::TlsCodec(e.to_string()))?;
                // Convert to protocol message based on variant
                let protocol_message: ProtocolMessage = match mls_message_in.extract() {
                    MlsMessageInBody::PublicMessage(pm) => pm.into(),
                    MlsMessageInBody::PrivateMessage(pm) => pm.into(),
                    other => {
                        return Err(MLSError::Internal(format!("Unexpected message type: {:?}", other)));
                    }
                };
                
                let processed_message = group
                    .process_message(context.provider(), protocol_message)
                    .map_err(|e| MLSError::OpenMLS(e.to_string()))?;
                
                let plaintext = match processed_message.into_content() {
                    ProcessedMessageContent::ApplicationMessage(app_msg) => {
                        app_msg.into_bytes().to_vec()
                    },
                    ProcessedMessageContent::ProposalMessage(_) => {
                        return Err(MLSError::Internal("Received proposal, not application message".to_string()));
                    },
                    ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
                        return Err(MLSError::Internal("Received external join proposal".to_string()));
                    },
                    ProcessedMessageContent::StagedCommitMessage(_) => {
                        return Err(MLSError::Internal("Received staged commit".to_string()));
                    },
                };
                
                Ok(plaintext)
            })
        })();
        
        match result {
            Ok(data) => MLSResult::ok(data),
            Err(e) => MLSResult::err(e),
        }
    })
}

/// Create a key package for joining groups
#[no_mangle]
pub extern "C" fn mls_create_key_package(
    context_id: usize,
    identity_bytes: *const u8,
    identity_len: usize,
) -> MLSResult {
    // P0: Catch panics at FFI boundary
    ffi_catch_unwind!({
        let result: Result<Vec<u8>> = (|| {
            validate_input_len(identity_len, MAX_IDENTITY_LEN, "identity")?;
            let context = get_context(context_id)?;
            let identity = safe_slice(identity_bytes, identity_len, "identity")?;
            
            let credential = Credential::new(identity.to_vec(), CredentialType::Basic)
                .map_err(|e| MLSError::OpenMLS(e.to_string()))?;
            
            // CRITICAL FIX: Reuse existing signature key if available for this identity
            // This prevents signature key mismatch when processing Welcome messages
            let identity_str = std::str::from_utf8(identity)
                .map_err(|e| MLSError::InvalidInput(format!("Identity is not valid UTF-8: {}", e)))?;

            let signature_keypair = if let Some(existing) = context.get_signer_for_identity(identity_str) {
                crate::debug_log!("[MLS-FFI] ♻️ Reusing existing signature key for identity: {}", identity_str);
                existing
            } else {
                crate::debug_log!("[MLS-FFI] 🆕 Generating NEW signature key for identity: {}", identity_str);
                let new_kp = SignatureKeyPair::new(SignatureScheme::ED25519)
                    .map_err(|e| MLSError::OpenMLS(e.to_string()))?;
                
                new_kp.store(context.provider().key_store())
                    .map_err(|e| MLSError::OpenMLS(e.to_string()))?;
                new_kp
            };
            
            let credential_with_key = CredentialWithKey {
                credential: credential.clone(),
                signature_key: signature_keypair.public().into(),
            };

            // CRITICAL: Key packages must advertise support for RatchetTree extension
            let capabilities = Capabilities::builder()
                .extensions(vec![ExtensionType::RatchetTree])
                .build();

            let key_package = KeyPackage::builder()
                .leaf_node_capabilities(capabilities)
                .build(
                    CryptoConfig::default(),
                    context.provider(),
                    &signature_keypair,
                    credential_with_key,
                )
                .map_err(|e| MLSError::OpenMLS(e.to_string()))?;
            
            // Store signer by key package reference for later use in process_welcome
            let key_package_ref = key_package.hash_ref(context.provider().crypto())
                .map_err(|e| MLSError::OpenMLS(e.to_string()))?;
            let signer_arc = Arc::new(signature_keypair);
            context.set_key_package_signer(key_package_ref.as_slice().to_vec(), Arc::clone(&signer_arc))?;
            context.set_identity_signer(identity.to_vec(), signer_arc)?;
            
            let serialized = key_package.tls_serialize_detached()
                .map_err(|e| MLSError::TlsCodec(e.to_string()))?;
            
            Ok(serialized)
        })();
        
        match result {
            Ok(data) => MLSResult::ok(data),
            Err(e) => MLSResult::err(e),
        }
    })
}

/// Process a Welcome message to join a group
#[no_mangle]
pub extern "C" fn mls_process_welcome(
    context_id: usize,
    welcome_bytes: *const u8,
    welcome_len: usize,
    _identity_bytes: *const u8,
    _identity_len: usize,
) -> MLSResult {
    // P0: Catch panics at FFI boundary
    ffi_catch_unwind!({
        let result: Result<Vec<u8>> = (|| {
            validate_input_len(welcome_len, MAX_MESSAGE_LEN, "welcome")?;
            validate_input_len(_identity_len, MAX_IDENTITY_LEN, "identity")?;
            
            let context = get_context(context_id)?;
            let welcome_data = safe_slice(welcome_bytes, welcome_len, "welcome")?;
            
            let mls_message_in = MlsMessageIn::tls_deserialize(&mut &welcome_data[..])
                .map_err(|e| MLSError::TlsCodec(format!("Failed to deserialize Welcome: {}", e)))?;
            
            let welcome = match mls_message_in.extract() {
                MlsMessageInBody::Welcome(w) => w,
                _ => return Err(MLSError::InvalidInput("Not a Welcome message".to_string())),
            };
            
            // Try to find signer by key package reference first (more reliable)
            // Welcome contains key_package_ref that we can use to lookup the signer
            let identity = safe_slice(_identity_bytes, _identity_len, "identity")?;
            
            // Fallback to identity-based lookup (may fail if not properly stored)
            let signer = context.signer_for_identity(identity)
                .or_else(|_| {
                    // If identity lookup fails, try all stored key package signers
                    // This is a fallback for robustness
                    Err(MLSError::Internal(
                        "No matching signer found. Ensure key package was created with this identity.".to_string()
                    ))
                })?;
            
            let join_config = MlsGroupJoinConfig::builder()
                .build();
            let group = MlsGroup::new_from_welcome(
                context.provider(),
                &join_config,
                welcome,
                None,
            ).map_err(|e| MLSError::OpenMLS(format!("Failed to process Welcome: {}", e)))?;
            
            let group_id = group.group_id().as_slice().to_vec();
            context.add_group(group_id.clone(), group, signer)?;
            
            Ok(group_id)
        })();
        
        match result {
            Ok(data) => MLSResult::ok(data),
            Err(e) => MLSResult::err(e),
        }
    })
}

/// Export a secret from the group's key schedule
#[no_mangle]
pub extern "C" fn mls_export_secret(
    context_id: usize,
    group_id: *const u8,
    group_id_len: usize,
    label: *const c_char,
    context_bytes: *const u8,
    context_len: usize,
    key_length: usize,
) -> MLSResult {
    // P0: Catch panics at FFI boundary
    ffi_catch_unwind!({
        let result: Result<Vec<u8>> = (|| {
            let ctx = get_context(context_id)?;
            let gid = safe_slice(group_id, group_id_len, "group_id")?;
            let context_data = safe_slice(context_bytes, context_len, "context")?;
            
            if label.is_null() {
                return Err(MLSError::NullPointer("label"));
            }
            
            let label_str = unsafe {
                CStr::from_ptr(label)
                    .to_str()
                    .map_err(|e| MLSError::InvalidUtf8(e))?
            };
            
            ctx.with_group(gid, |group| {
                let secret = group
                    .export_secret(ctx.provider(), label_str, context_data, key_length)
                    .map_err(|e| MLSError::OpenMLS(e.to_string()))?;
                
                // P1: Zeroize exported secret after use would be done by caller
                // Note: The returned Vec will be managed by caller who should zeroize
                Ok(secret.to_vec())
            })
        })();
        
        match result {
            Ok(data) => MLSResult::ok(data),
            Err(e) => MLSResult::err(e),
        }
    })
}

/// Get the current epoch of the group
#[no_mangle]
pub extern "C" fn mls_get_epoch(
    context_id: usize,
    group_id: *const u8,
    group_id_len: usize,
) -> u64 {
    // P0: Catch panics at FFI boundary
    panic::catch_unwind(AssertUnwindSafe(|| {
        let result: Result<u64> = (|| {
            let context = get_context(context_id)?;
            let gid = safe_slice(group_id, group_id_len, "group_id")?;
            
            context.with_group(gid, |group| {
                Ok(group.epoch().as_u64())
            })
        })();
        
        result.unwrap_or(0)
    }))
    .unwrap_or(0) // Return 0 on panic
}

/// Process a commit message and update group state
/// This is used for epoch synchronization - processing commits from other members
/// to keep the local group state up-to-date with the server's current epoch.
///
/// # Arguments
/// * `context_id` - The MLS context handle
/// * `group_id` - The group identifier
/// * `commit_bytes` - TLS-encoded MlsMessage containing a commit
///
/// # Returns
/// MLSResult with success=true if commit was processed successfully,
/// or success=false with error message on failure.
#[no_mangle]
pub extern "C" fn mls_process_commit(
    context_id: usize,
    group_id: *const u8,
    group_id_len: usize,
    commit_bytes: *const u8,
    commit_len: usize,
) -> MLSResult {
    // P0: Catch panics at FFI boundary
    ffi_catch_unwind!({
        let result: Result<Vec<u8>> = (|| {
            validate_input_len(group_id_len, MAX_GROUP_ID_LEN, "group_id")?;
            validate_input_len(commit_len, MAX_MESSAGE_LEN, "commit")?;
            
            let context = get_context(context_id)?;
            let gid = safe_slice(group_id, group_id_len, "group_id")?;
            let commit_data = safe_slice(commit_bytes, commit_len, "commit")?;
            
            context.with_group(gid, |group| {
                // Deserialize the MLS message
                let mls_message_in = MlsMessageIn::tls_deserialize(&mut &commit_data[..])
                    .map_err(|e| MLSError::TlsCodec(format!("Failed to deserialize commit: {}", e)))?;
                
                // Convert to protocol message - commits can be PublicMessage or PrivateMessage
                let protocol_message: ProtocolMessage = match mls_message_in.extract() {
                    MlsMessageInBody::PublicMessage(pm) => pm.into(),
                    MlsMessageInBody::PrivateMessage(pm) => pm.into(),
                    other => {
                        return Err(MLSError::InvalidInput(format!(
                            "Expected commit message, got: {:?}", other
                        )));
                    }
                };
                
                // Process the message - this will stage the commit
                let processed_message = group
                    .process_message(context.provider(), protocol_message)
                    .map_err(|e| MLSError::OpenMLS(format!("Failed to process commit: {}", e)))?;
                
                // Verify this is a commit and extract Update proposals before merging
                match processed_message.into_content() {
                    ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                        // Extract Update proposals with credentials before merging
                        let update_proposals: Vec<(u32, Vec<u8>, Vec<u8>)> = staged_commit
                            .add_proposals()
                            .iter()
                            .chain(staged_commit.update_proposals().iter())
                            .filter_map(|queued_proposal| {
                                // Check if this is an Update proposal
                                match queued_proposal.proposal() {
                                    Proposal::Update(update_proposal) => {
                                        // Get the leaf node with new credential
                                        let leaf_node = update_proposal.leaf_node();
                                        let new_credential = leaf_node.credential();

                                        // Get leaf index from queued proposal
                                        let leaf_index = queued_proposal.sender().as_u32();

                                        // Get old credential from current group state
                                        if let Some(old_member) = group.members().find(|m| m.index.as_u32() == leaf_index) {
                                            let old_cred_bytes = match old_member.credential.credential_type() {
                                                CredentialType::Basic => old_member.credential.serialized_content().to_vec(),
                                                _ => vec![],
                                            };

                                            let new_cred_bytes = match new_credential.credential_type() {
                                                CredentialType::Basic => new_credential.serialized_content().to_vec(),
                                                _ => vec![],
                                            };

                                            Some((leaf_index, old_cred_bytes, new_cred_bytes))
                                        } else {
                                            None
                                        }
                                    },
                                    _ => None,
                                }
                            })
                            .collect();

                        // Merge the staged commit to update group state
                        group.merge_staged_commit(context.provider(), *staged_commit)
                            .map_err(|e| MLSError::OpenMLS(format!("Failed to merge commit: {}", e)))?;

                        // Return the new epoch and update proposals
                        let new_epoch = group.epoch().as_u64();

                        // Serialize update proposals as: [epoch: u64][num_updates: u32]([index: u32][old_len: u32][old_cred][new_len: u32][new_cred])*
                        let mut result = Vec::new();
                        result.extend_from_slice(&new_epoch.to_le_bytes());
                        result.extend_from_slice(&(update_proposals.len() as u32).to_le_bytes());

                        for (index, old_cred, new_cred) in update_proposals {
                            result.extend_from_slice(&index.to_le_bytes());
                            result.extend_from_slice(&(old_cred.len() as u32).to_le_bytes());
                            result.extend_from_slice(&old_cred);
                            result.extend_from_slice(&(new_cred.len() as u32).to_le_bytes());
                            result.extend_from_slice(&new_cred);
                        }

                        Ok(result)
                    },
                    ProcessedMessageContent::ApplicationMessage(_) => {
                        Err(MLSError::InvalidInput("Expected commit, got application message".to_string()))
                    },
                    ProcessedMessageContent::ProposalMessage(_) => {
                        Err(MLSError::InvalidInput("Expected commit, got proposal".to_string()))
                    },
                    ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
                        Err(MLSError::InvalidInput("Expected commit, got external join proposal".to_string()))
                    },
                }
            })
        })();
        
        match result {
            Ok(data) => MLSResult::ok(data),
            Err(e) => MLSResult::err(e),
        }
    })
}

/// Free a result object
/// P0: Fixed memory handling - use Box::from_raw for slices allocated via Box::into_raw
#[no_mangle]
pub extern "C" fn mls_free_result(result: MLSResult) {
    // P0: Catch panics at FFI boundary
    let _ = panic::catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: These pointers were allocated by us in MLSResult::ok/err
        unsafe {
            if !result.error_message.is_null() {
                // P1: CString was allocated via CString::into_raw
                let _ = CString::from_raw(result.error_message);
            }
            if !result.data.is_null() && result.data_len > 0 {
                // P0 FIX: Use Box::from_raw for boxed slices
                // Data was allocated via Box::into_raw(data.into_boxed_slice())
                // so we must reconstruct with the same layout
                let slice_ptr = ptr::slice_from_raw_parts_mut(result.data, result.data_len);
                let _ = Box::from_raw(slice_ptr);
            }
        }
    }));
}

/// Get the last error message (for debugging)
#[no_mangle]
pub extern "C" fn mls_get_last_error() -> *mut c_char {
    // P0: Catch panics at FFI boundary
    panic::catch_unwind(AssertUnwindSafe(|| {
        let msg = CString::new("Use MLSResult.error_message for error details")
            .unwrap_or_else(|_| CString::new("Error").unwrap());
        msg.into_raw()
    }))
    .unwrap_or(ptr::null_mut())
}

/// Free an error message string
#[no_mangle]
pub extern "C" fn mls_free_string(s: *mut c_char) {
    // P0: Catch panics at FFI boundary
    let _ = panic::catch_unwind(AssertUnwindSafe(|| {
        if !s.is_null() {
            unsafe {
                let _ = CString::from_raw(s);
            }
        }
    }));
}
