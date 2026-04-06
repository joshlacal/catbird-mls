use crate::blob_crypto::{encrypt_blob, BlobCryptoError};
use audiopus::{
    coder::{Decoder, Encoder},
    Application, Channels, MutSignals, SampleRate,
};
use ogg::reading::PacketReader;
use ogg::writing::PacketWriter;
use std::io::Cursor;

const OPUS_SAMPLE_RATE: u32 = 48_000;
const OPUS_FRAME_SIZE: usize = 960; // 20ms at 48kHz
const WAVEFORM_SAMPLES: usize = 64;
const MAX_DURATION_SECS: u64 = 300; // 5 minutes
const OPUS_BITRATE: i32 = 64_000; // 64kbps for crisp voice quality

// DSP constants
const NOISE_GATE_THRESHOLD_DB: f32 = -50.0; // Gate floor in dB
const NOISE_GATE_ATTACK_MS: f32 = 1.0; // Fast open
const NOISE_GATE_RELEASE_MS: f32 = 20.0; // Smooth close
const HIGHPASS_CUTOFF_HZ: f32 = 80.0; // Remove rumble below 80Hz
const COMPRESSOR_THRESHOLD_DB: f32 = -18.0; // Start compressing above this
const COMPRESSOR_RATIO: f32 = 4.0; // 4:1 compression ratio
const COMPRESSOR_ATTACK_MS: f32 = 5.0; // Fast attack for punch
const COMPRESSOR_RELEASE_MS: f32 = 50.0; // Moderate release
const COMPRESSOR_MAKEUP_GAIN_DB: f32 = 6.0; // Boost after compression
const TARGET_LUFS: f32 = -16.0; // Loudness target (similar to Discord/podcasts)

#[derive(Debug, Clone)]
pub struct VoicePrepareResult {
    pub opus_data: Vec<u8>,
    pub encrypted_blob: Vec<u8>,
    pub key: Vec<u8>,
    pub iv: Vec<u8>,
    pub sha256: String,
    pub duration_ms: u64,
    pub waveform: Vec<f32>,
    pub size: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum VoiceError {
    #[error("failed to read PCM file: {0}")]
    IoError(#[from] std::io::Error),
    #[error("PCM file is empty")]
    EmptyInput,
    #[error("recording exceeds maximum duration of {MAX_DURATION_SECS} seconds")]
    TooLong,
    #[error("Opus encoding failed: {0}")]
    OpusEncode(String),
    #[error("Opus decoding failed: {0}")]
    OpusDecode(String),
    #[error("OGG container error: {0}")]
    OggError(String),
    #[error("blob crypto error: {0}")]
    BlobCrypto(#[from] BlobCryptoError),
    #[error("unsupported sample rate: {0}")]
    UnsupportedSampleRate(u32),
}

// ── DSP Processing Chain ──────────────────────────────────────────────
// Applied in order: high-pass filter → noise gate → compressor → normalize
// Gives voice messages a crisp, broadcast-quality feel (similar to Discord).

/// Convert a linear amplitude to decibels.
fn amplitude_to_db(amp: f32) -> f32 {
    if amp.abs() < 1e-10 {
        -100.0
    } else {
        20.0 * amp.abs().log10()
    }
}

/// Convert decibels to linear amplitude.
fn db_to_amplitude(db: f32) -> f32 {
    10.0_f32.powf(db / 20.0)
}

/// 2nd-order Butterworth high-pass filter to remove low-frequency rumble.
/// Operates on f32 samples in [-1.0, 1.0] range.
fn highpass_filter(samples: &mut [f32], cutoff_hz: f32, sample_rate: f32) {
    if samples.is_empty() {
        return;
    }
    let omega = 2.0 * std::f32::consts::PI * cutoff_hz / sample_rate;
    let cos_omega = omega.cos();
    let alpha = omega.sin() / (2.0 * 0.7071); // Q = 0.7071 (Butterworth)

    let b0 = (1.0 + cos_omega) / 2.0;
    let b1 = -(1.0 + cos_omega);
    let b2 = (1.0 + cos_omega) / 2.0;
    let a0 = 1.0 + alpha;
    let a1 = -2.0 * cos_omega;
    let a2 = 1.0 - alpha;

    // Normalize coefficients
    let b0 = b0 / a0;
    let b1 = b1 / a0;
    let b2 = b2 / a0;
    let a1 = a1 / a0;
    let a2 = a2 / a0;

    let mut x1 = 0.0_f32;
    let mut x2 = 0.0_f32;
    let mut y1 = 0.0_f32;
    let mut y2 = 0.0_f32;

    for s in samples.iter_mut() {
        let x0 = *s;
        let y0 = b0 * x0 + b1 * x1 + b2 * x2 - a1 * y1 - a2 * y2;
        x2 = x1;
        x1 = x0;
        y2 = y1;
        y1 = y0;
        *s = y0;
    }
}

/// Noise gate with smooth attack/release envelope.
/// Silences audio below the threshold to remove background noise.
fn noise_gate(samples: &mut [f32], sample_rate: f32) {
    let threshold = db_to_amplitude(NOISE_GATE_THRESHOLD_DB);
    let attack_coeff = (-1.0 / (NOISE_GATE_ATTACK_MS * 0.001 * sample_rate)).exp();
    let release_coeff = (-1.0 / (NOISE_GATE_RELEASE_MS * 0.001 * sample_rate)).exp();

    let mut envelope = 0.0_f32;

    for s in samples.iter_mut() {
        let abs_sample = s.abs();
        // Smooth envelope follower
        if abs_sample > envelope {
            envelope = attack_coeff * envelope + (1.0 - attack_coeff) * abs_sample;
        } else {
            envelope = release_coeff * envelope + (1.0 - release_coeff) * abs_sample;
        }
        // Apply gate
        if envelope < threshold {
            *s *= envelope / threshold; // Smooth fade to silence
        }
    }
}

/// Dynamic range compressor — makes quiet parts louder, loud parts controlled.
/// This is what gives the "punchy" broadcast quality feel.
fn compress_dynamics(samples: &mut [f32], sample_rate: f32) {
    let threshold = db_to_amplitude(COMPRESSOR_THRESHOLD_DB);
    let attack_coeff = (-1.0 / (COMPRESSOR_ATTACK_MS * 0.001 * sample_rate)).exp();
    let release_coeff = (-1.0 / (COMPRESSOR_RELEASE_MS * 0.001 * sample_rate)).exp();
    let makeup = db_to_amplitude(COMPRESSOR_MAKEUP_GAIN_DB);

    let mut gain_reduction = 1.0_f32;

    for s in samples.iter_mut() {
        let abs_sample = s.abs();

        // Compute target gain reduction
        let target_gain = if abs_sample > threshold {
            let over_db = amplitude_to_db(abs_sample) - COMPRESSOR_THRESHOLD_DB;
            let compressed_over = over_db / COMPRESSOR_RATIO;
            let target_db = COMPRESSOR_THRESHOLD_DB + compressed_over;
            db_to_amplitude(target_db) / abs_sample.max(1e-10)
        } else {
            1.0
        };

        // Smooth gain changes
        if target_gain < gain_reduction {
            gain_reduction = attack_coeff * gain_reduction + (1.0 - attack_coeff) * target_gain;
        } else {
            gain_reduction = release_coeff * gain_reduction + (1.0 - release_coeff) * target_gain;
        }

        // Apply compression + makeup gain
        *s *= gain_reduction * makeup;
    }
}

/// Loudness-normalize to target LUFS with peak limiting.
fn loudness_normalize(samples: &mut [f32]) {
    if samples.is_empty() {
        return;
    }

    // Compute RMS (approximation of loudness)
    let rms = (samples.iter().map(|&s| s * s).sum::<f32>() / samples.len() as f32).sqrt();
    if rms < 1e-10 {
        return;
    }

    let current_db = amplitude_to_db(rms);
    let gain_db = TARGET_LUFS - current_db;
    let gain = db_to_amplitude(gain_db);

    // Apply gain
    for s in samples.iter_mut() {
        *s *= gain;
    }

    // Soft-clip limiter to prevent overs (tanh-based)
    let peak = samples.iter().map(|s| s.abs()).fold(0.0_f32, f32::max);
    if peak > 0.95 {
        let ceiling = 0.95;
        for s in samples.iter_mut() {
            if s.abs() > ceiling {
                *s = s.signum() * (ceiling + (1.0 - ceiling) * ((*s).abs() - ceiling).tanh());
            }
        }
    }
}

/// Full voice processing DSP chain: filter → gate → compress → normalize.
/// Transforms raw mic input into broadcast-quality voice audio.
fn process_voice_dsp(pcm_f32: &mut [f32], sample_rate: f32) {
    highpass_filter(pcm_f32, HIGHPASS_CUTOFF_HZ, sample_rate);
    noise_gate(pcm_f32, sample_rate);
    compress_dynamics(pcm_f32, sample_rate);
    loudness_normalize(pcm_f32);
}

/// Convert i16 PCM to f32 [-1.0, 1.0] range.
fn i16_to_f32(samples: &[i16]) -> Vec<f32> {
    samples
        .iter()
        .map(|&s| s as f32 / i16::MAX as f32)
        .collect()
}

/// Convert f32 [-1.0, 1.0] back to i16 with clamping.
fn f32_to_i16(samples: &[f32]) -> Vec<i16> {
    samples
        .iter()
        .map(|&s| {
            (s * i16::MAX as f32)
                .round()
                .clamp(i16::MIN as f32, i16::MAX as f32) as i16
        })
        .collect()
}

// ── End DSP ──────────────────────────────────────────────────────────

/// Extract 64 peak-normalized waveform samples from PCM data.
/// Input: 16-bit LE mono PCM samples.
fn extract_waveform(pcm_i16: &[i16]) -> Vec<f32> {
    if pcm_i16.is_empty() {
        return vec![0.0; WAVEFORM_SAMPLES];
    }

    let chunk_size = pcm_i16.len() / WAVEFORM_SAMPLES;
    if chunk_size == 0 {
        let mut waveform: Vec<f32> = pcm_i16
            .iter()
            .map(|&s| (s as f32 / i16::MAX as f32).abs())
            .collect();
        waveform.resize(WAVEFORM_SAMPLES, 0.0);
        return waveform;
    }

    let mut peaks: Vec<f32> = pcm_i16
        .chunks(chunk_size)
        .take(WAVEFORM_SAMPLES)
        .map(|chunk| {
            chunk
                .iter()
                .map(|&s| (s as f32 / i16::MAX as f32).abs())
                .fold(0.0_f32, f32::max)
        })
        .collect();

    // Normalize to 0.0–1.0
    let max_peak = peaks.iter().copied().fold(0.0_f32, f32::max);
    if max_peak > 0.0 {
        for p in &mut peaks {
            *p /= max_peak;
        }
    }

    peaks.resize(WAVEFORM_SAMPLES, 0.0);
    peaks
}

/// Resample 16-bit PCM from `from_rate` to `to_rate` using linear interpolation.
fn resample_linear(samples: &[i16], from_rate: u32, to_rate: u32) -> Vec<i16> {
    if from_rate == to_rate {
        return samples.to_vec();
    }
    let ratio = from_rate as f64 / to_rate as f64;
    let out_len = (samples.len() as f64 / ratio).ceil() as usize;
    let mut output = Vec::with_capacity(out_len);

    for i in 0..out_len {
        let src_pos = i as f64 * ratio;
        let idx = src_pos as usize;
        let frac = src_pos - idx as f64;

        let s0 = samples[idx] as f64;
        let s1 = if idx + 1 < samples.len() {
            samples[idx + 1] as f64
        } else {
            s0
        };
        let interpolated = s0 + frac * (s1 - s0);
        output.push(interpolated.round().clamp(i16::MIN as f64, i16::MAX as f64) as i16);
    }

    output
}

/// Encode 16-bit LE mono PCM samples to Opus-in-OGG.
fn encode_opus_ogg(pcm_48k: &[i16]) -> Result<Vec<u8>, VoiceError> {
    let mut encoder = Encoder::new(SampleRate::Hz48000, Channels::Mono, Application::Voip)
        .map_err(|e| VoiceError::OpusEncode(e.to_string()))?;

    // Set bitrate via CTL request (OPUS_SET_BITRATE_REQUEST = 4002)
    encoder
        .set_encoder_ctl_request(4002, OPUS_BITRATE)
        .map_err(|e| VoiceError::OpusEncode(e.to_string()))?;

    // Tell Opus this is voice (OPUS_SET_SIGNAL_REQUEST = 4024, OPUS_SIGNAL_VOICE = 3001)
    // Enables internal noise suppression and voice-optimized encoding
    encoder
        .set_encoder_ctl_request(4024, 3001)
        .map_err(|e| VoiceError::OpusEncode(e.to_string()))?;

    let mut ogg_buf = Vec::new();
    let serial = rand::random::<u32>();
    let mut writer = PacketWriter::new(Cursor::new(&mut ogg_buf));

    // OpusHead header packet
    let mut opus_head = Vec::with_capacity(19);
    opus_head.extend_from_slice(b"OpusHead");
    opus_head.push(1); // version
    opus_head.push(1); // channel count (mono)
    opus_head.extend_from_slice(&0u16.to_le_bytes()); // pre-skip
    opus_head.extend_from_slice(&48000u32.to_le_bytes()); // input sample rate
    opus_head.extend_from_slice(&0i16.to_le_bytes()); // output gain
    opus_head.push(0); // channel mapping family

    writer
        .write_packet(opus_head, serial, ogg::PacketWriteEndInfo::EndPage, 0)
        .map_err(|e| VoiceError::OggError(e.to_string()))?;

    // OpusTags header packet
    let vendor = b"catbird-mls";
    let mut opus_tags = Vec::new();
    opus_tags.extend_from_slice(b"OpusTags");
    opus_tags.extend_from_slice(&(vendor.len() as u32).to_le_bytes());
    opus_tags.extend_from_slice(vendor);
    opus_tags.extend_from_slice(&0u32.to_le_bytes()); // no user comments

    writer
        .write_packet(opus_tags, serial, ogg::PacketWriteEndInfo::EndPage, 0)
        .map_err(|e| VoiceError::OggError(e.to_string()))?;

    // Encode audio frames
    let mut output_buf = vec![0u8; 4000]; // max Opus packet
    let mut granule_pos: u64 = 0;
    let chunks: Vec<&[i16]> = pcm_48k.chunks(OPUS_FRAME_SIZE).collect();
    let total_chunks = chunks.len();

    for (i, chunk) in chunks.into_iter().enumerate() {
        let frame: Vec<i16> = if chunk.len() < OPUS_FRAME_SIZE {
            let mut padded = chunk.to_vec();
            padded.resize(OPUS_FRAME_SIZE, 0);
            padded
        } else {
            chunk.to_vec()
        };

        let encoded_len = encoder
            .encode(&frame, &mut output_buf)
            .map_err(|e| VoiceError::OpusEncode(e.to_string()))?;

        granule_pos += OPUS_FRAME_SIZE as u64;

        let is_last = i == total_chunks - 1;
        let end_info = if is_last {
            ogg::PacketWriteEndInfo::EndStream
        } else {
            ogg::PacketWriteEndInfo::NormalPacket
        };

        writer
            .write_packet(
                output_buf[..encoded_len].to_vec(),
                serial,
                end_info,
                granule_pos,
            )
            .map_err(|e| VoiceError::OggError(e.to_string()))?;
    }

    drop(writer);
    Ok(ogg_buf)
}

/// Encode PCM file to Opus, extract waveform, encrypt blob.
///
/// The platform records audio natively, decodes to 16-bit LE mono PCM,
/// writes to a temp file, and passes the path here.
pub fn prepare_voice_message(
    pcm_path: &str,
    sample_rate: u32,
) -> Result<VoicePrepareResult, VoiceError> {
    if ![8000, 16000, 24000, 44100, 48000].contains(&sample_rate) {
        return Err(VoiceError::UnsupportedSampleRate(sample_rate));
    }

    let raw_bytes = std::fs::read(pcm_path)?;
    if raw_bytes.is_empty() {
        return Err(VoiceError::EmptyInput);
    }

    // Convert bytes to i16 samples
    let pcm_i16: Vec<i16> = raw_bytes
        .chunks_exact(2)
        .map(|c| i16::from_le_bytes([c[0], c[1]]))
        .collect();

    // Check duration
    let duration_secs = pcm_i16.len() as u64 / sample_rate as u64;
    if duration_secs > MAX_DURATION_SECS {
        return Err(VoiceError::TooLong);
    }

    // Extract waveform from original PCM (before resampling)
    let waveform = extract_waveform(&pcm_i16);

    // Resample to 48kHz for Opus
    let pcm_48k_raw = resample_linear(&pcm_i16, sample_rate, OPUS_SAMPLE_RATE);

    // Apply voice processing DSP chain (filter → gate → compress → normalize)
    let mut pcm_f32 = i16_to_f32(&pcm_48k_raw);
    process_voice_dsp(&mut pcm_f32, OPUS_SAMPLE_RATE as f32);
    let pcm_48k = f32_to_i16(&pcm_f32);

    // Compute duration from resampled data
    let duration_ms = (pcm_48k.len() as u64 * 1000) / OPUS_SAMPLE_RATE as u64;

    // Encode to Opus-in-OGG
    let opus_data = encode_opus_ogg(&pcm_48k)?;

    // Encrypt blob (same AES-256-GCM as images)
    let encrypted = encrypt_blob(&opus_data)?;

    Ok(VoicePrepareResult {
        size: opus_data.len() as u64,
        opus_data,
        encrypted_blob: encrypted.ciphertext,
        key: encrypted.key,
        iv: encrypted.iv,
        sha256: encrypted.sha256,
        duration_ms,
        waveform,
    })
}

/// Decode Opus-in-OGG back to 16-bit LE mono PCM at 48kHz.
/// iOS can't play Opus OGG natively, so this decodes to PCM for AVAudioPlayer.
pub fn decode_opus_to_pcm(opus_ogg: &[u8]) -> Result<Vec<u8>, VoiceError> {
    let mut reader = PacketReader::new(Cursor::new(opus_ogg));
    let mut decoder = Decoder::new(SampleRate::Hz48000, Channels::Mono)
        .map_err(|e| VoiceError::OpusDecode(e.to_string()))?;

    let mut all_pcm: Vec<i16> = Vec::new();
    let mut skipped_headers = 0;

    while let Some(packet) = reader
        .read_packet()
        .map_err(|e| VoiceError::OggError(e.to_string()))?
    {
        // Skip OpusHead and OpusTags header packets
        if skipped_headers < 2 {
            skipped_headers += 1;
            continue;
        }

        let mut decode_buf = vec![0i16; OPUS_FRAME_SIZE];
        let output_signals: MutSignals<'_, i16> = (&mut decode_buf)
            .try_into()
            .map_err(|e: audiopus::Error| VoiceError::OpusDecode(e.to_string()))?;
        let input_packet: audiopus::packet::Packet<'_> = (&packet.data[..])
            .try_into()
            .map_err(|e: audiopus::Error| VoiceError::OpusDecode(e.to_string()))?;
        let decoded_samples = decoder
            .decode(Some(input_packet), output_signals, false)
            .map_err(|e| VoiceError::OpusDecode(e.to_string()))?;

        all_pcm.extend_from_slice(&decode_buf[..decoded_samples]);
    }

    // Convert i16 samples to LE bytes
    let mut pcm_bytes = Vec::with_capacity(all_pcm.len() * 2);
    for sample in &all_pcm {
        pcm_bytes.extend_from_slice(&sample.to_le_bytes());
    }

    Ok(pcm_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn generate_sine_pcm(freq_hz: f32, duration_secs: f32, sample_rate: u32) -> Vec<i16> {
        let num_samples = (sample_rate as f32 * duration_secs) as usize;
        (0..num_samples)
            .map(|i| {
                let t = i as f32 / sample_rate as f32;
                (f32::sin(2.0 * std::f32::consts::PI * freq_hz * t) * i16::MAX as f32 * 0.5) as i16
            })
            .collect()
    }

    fn write_pcm_file(samples: &[i16]) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        for s in samples {
            file.write_all(&s.to_le_bytes()).unwrap();
        }
        file.flush().unwrap();
        file
    }

    #[test]
    fn test_waveform_extraction() {
        let pcm = generate_sine_pcm(440.0, 1.0, 48000);
        let waveform = extract_waveform(&pcm);
        assert_eq!(waveform.len(), WAVEFORM_SAMPLES);
        assert!(waveform.iter().all(|&v| (0.0..=1.0).contains(&v)));
        assert!(waveform.iter().any(|&v| v > 0.0));
    }

    #[test]
    fn test_waveform_empty_input() {
        let waveform = extract_waveform(&[]);
        assert_eq!(waveform.len(), WAVEFORM_SAMPLES);
        assert!(waveform.iter().all(|&v| v == 0.0));
    }

    #[test]
    fn test_resample_passthrough() {
        let pcm = generate_sine_pcm(440.0, 0.1, 48000);
        let resampled = resample_linear(&pcm, 48000, 48000);
        assert_eq!(resampled.len(), pcm.len());
    }

    #[test]
    fn test_resample_44100_to_48000() {
        let pcm = generate_sine_pcm(440.0, 1.0, 44100);
        let resampled = resample_linear(&pcm, 44100, 48000);
        let expected_len = (pcm.len() as f64 * 48000.0 / 44100.0).ceil() as usize;
        assert!((resampled.len() as i64 - expected_len as i64).abs() <= 1);
    }

    #[test]
    fn test_opus_encode_decode_roundtrip() {
        let pcm = generate_sine_pcm(440.0, 0.5, 48000);
        let opus_data = encode_opus_ogg(&pcm).unwrap();
        assert!(!opus_data.is_empty());
        assert_eq!(&opus_data[..4], b"OggS");

        let decoded = decode_opus_to_pcm(&opus_data).unwrap();
        assert!(!decoded.is_empty());
        let decoded_samples = decoded.len() / 2;
        let original_duration_ms = (pcm.len() * 1000) / 48000;
        let decoded_duration_ms = (decoded_samples * 1000) / 48000;
        assert!((decoded_duration_ms as i64 - original_duration_ms as i64).abs() < 40);
    }

    #[test]
    fn test_prepare_voice_message_full_pipeline() {
        let pcm = generate_sine_pcm(440.0, 2.0, 48000);
        let file = write_pcm_file(&pcm);

        let result = prepare_voice_message(file.path().to_str().unwrap(), 48000).unwrap();

        assert!(!result.opus_data.is_empty());
        assert!(!result.encrypted_blob.is_empty());
        assert_eq!(result.key.len(), 32);
        assert_eq!(result.iv.len(), 12);
        assert!(!result.sha256.is_empty());
        assert_eq!(result.waveform.len(), WAVEFORM_SAMPLES);
        assert!((result.duration_ms as i64 - 2000).abs() < 100);
        assert!(result.size < pcm.len() as u64 * 2);
    }

    #[test]
    fn test_prepare_voice_message_44100_input() {
        let pcm = generate_sine_pcm(440.0, 1.0, 44100);
        let file = write_pcm_file(&pcm);

        let result = prepare_voice_message(file.path().to_str().unwrap(), 44100).unwrap();

        assert!(!result.opus_data.is_empty());
        assert!((result.duration_ms as i64 - 1000).abs() < 100);
    }

    #[test]
    fn test_prepare_rejects_empty() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let err = prepare_voice_message(file.path().to_str().unwrap(), 48000);
        assert!(matches!(err, Err(VoiceError::EmptyInput)));
    }

    #[test]
    fn test_encrypted_blob_decrypts_to_opus() {
        let pcm = generate_sine_pcm(440.0, 0.5, 48000);
        let file = write_pcm_file(&pcm);
        let result = prepare_voice_message(file.path().to_str().unwrap(), 48000).unwrap();

        let decrypted = crate::blob_crypto::decrypt_blob(
            &result.encrypted_blob,
            &result.key,
            &result.iv,
            &result.sha256,
        )
        .unwrap();

        assert_eq!(decrypted, result.opus_data);
    }
}
