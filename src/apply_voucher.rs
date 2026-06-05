use axum::{
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use std::env;

#[derive(Debug, Deserialize)]
pub struct VoucherRequest {
    pub code: Option<String>,
    pub total_price: Option<Value>,
}

pub async fn apply_voucher(
    headers: HeaderMap,
    Json(payload): Json<VoucherRequest>,
) -> impl IntoResponse {
    // 1. Ambil & Validasi Token Authorization (Sesi)
    let token = match headers.get("Authorization").and_then(|h| h.to_str().ok()) {
        Some(h) if h.starts_with("Bearer ") => h[7..].trim(),
        _ => return error_response(StatusCode::UNAUTHORIZED, "Sesi tidak valid"),
    };

    let code = payload.code.unwrap_or_default();
    let upper_code = code.trim().to_uppercase();

    if upper_code.is_empty() || upper_code.len() > 30 {
        return error_response(StatusCode::BAD_REQUEST, "Format kode promo tidak valid.");
    }

    // ====================================================================
    // SECURITY PATCH 1: Pencegahan Overflow & Parameter Manipulation
    // ====================================================================
    let subtotal_val = payload.total_price.unwrap_or(json!(0));
    let parsed_f64 = subtotal_val.as_f64().unwrap_or_else(|| {
        subtotal_val.as_str().and_then(|s| s.parse::<f64>().ok()).unwrap_or(0.0)
    });

    // Validasi nilai ekstrem (Tolak Infinity, NaN, atau angka minus)
    if parsed_f64.is_nan() || parsed_f64.is_infinite() || parsed_f64 < 0.0 {
        return error_response(StatusCode::BAD_REQUEST, "Manipulasi data harga terdeteksi.");
    }

    let subtotal = parsed_f64 as i64;
    
    // Tolak transaksi di atas batas rasional (Mencegah Integer Overflow ke i64)
    // Misalnya kita batasi transaksi wajar maksimal 1 Miliar
    if subtotal > 1_000_000_000 {
        return error_response(StatusCode::BAD_REQUEST, "Total belanja di luar batas wajar.");
    }
    // ====================================================================

    let supabase_url = env::var("SUPABASE_URL").unwrap_or_default();
    let supabase_key = env::var("SUPABASE_ANON_KEY").unwrap_or_default();
    let clean_url = supabase_url.trim_end_matches('/');

    if clean_url.is_empty() || supabase_key.is_empty() {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Konfigurasi server bermasalah");
    }

    let client = reqwest::Client::new();

    // 2. Verifikasi User Sesi ke Supabase Auth
    let auth_url = format!("{}/auth/v1/user", clean_url);
    let auth_res = client.get(&auth_url)
        .header("apikey", &supabase_key)
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await;

    let user_id = match auth_res {
        Ok(res) if res.status().is_success() => {
            let user_data: Value = res.json().await.unwrap_or(json!({}));
            match user_data["id"].as_str() {
                Some(id) => id.to_string(),
                None => return error_response(StatusCode::UNAUTHORIZED, "Sesi tidak valid"),
            }
        }
        _ => return error_response(StatusCode::UNAUTHORIZED, "Sesi tidak valid"),
    };

    // 3. Cek riwayat penggunaan (Mencegah Spam)
    let claim_url = format!(
        "{}/rest/v1/gg_claimed_vouchers?user_id=eq.{}&voucher_code=eq.{}&select=is_used",
        clean_url, user_id, upper_code
    );
    
    if let Ok(claim_res) = client.get(&claim_url).header("apikey", &supabase_key).header("Authorization", format!("Bearer {}", token)).send().await {
        if let Ok(claim_data) = claim_res.json::<Value>().await {
            if let Some(arr) = claim_data.as_array() {
                if arr.iter().any(|row| row["is_used"].as_bool().unwrap_or(false)) {
                    return error_response(StatusCode::BAD_REQUEST, "Kode voucher ini sudah Anda gunakan sebelumnya.");
                }
            }
        }
    }

    // 4. Tarik Aturan Voucher dari Database
    let voucher_url = format!("{}/rest/v1/gg_vouchers?code=eq.{}&select=*", clean_url, upper_code);
    let voucher_res = client.get(&voucher_url)
        .header("apikey", &supabase_key)
        .header("Authorization", format!("Bearer {}", token)) 
        .send()
        .await;

    let voucher = match voucher_res {
        Ok(res) if res.status().is_success() => {
            let data: Value = res.json().await.unwrap_or(json!([]));
            match data.as_array().and_then(|arr| arr.get(0).cloned()) {
                Some(v) => v,
                None => return error_response(StatusCode::BAD_REQUEST, "Kode promo tidak valid atau tidak ditemukan."),
            }
        }
        _ => return error_response(StatusCode::BAD_REQUEST, "Kode promo tidak valid atau tidak ditemukan."),
    };

    // 5. Cek Kadaluarsa
    if let Some(expires_str) = voucher["expires_at"].as_str() {
        let parsed_date = DateTime::parse_from_rfc3339(expires_str)
            .or_else(|_| DateTime::parse_from_rfc3339(&format!("{}Z", expires_str)));
        
        if let Ok(expires_at) = parsed_date {
            if expires_at.with_timezone(&Utc) < Utc::now() {
                return error_response(StatusCode::BAD_REQUEST, "Maaf, kode promo ini sudah kadaluarsa.");
            }
        }
    }

    // 6. Cek Syarat Minimal Belanja
    let min_purchase = voucher["min_purchase"].as_f64().unwrap_or_else(|| {
        voucher["min_purchase"].as_str().and_then(|s| s.parse::<f64>().ok()).unwrap_or(0.0)
    }) as i64;

    if subtotal < min_purchase {
        // SECURITY PATCH: Jangan gunakan variable min_purchase secara langsung untuk mencegah injeksi desimal panjang
        let msg = format!("Minimal belanja Rp {} untuk pakai kode ini.", min_purchase);
        return error_response(StatusCode::BAD_REQUEST, &msg);
    }

    // 7. Eksekusi Rumus Perhitungan Diskon
    let mut discount_amount = 0.0;
    let d_type = voucher["discount_type"].as_str().unwrap_or("").trim().to_lowercase();
    let mut d_value = voucher["discount_value"].as_f64().unwrap_or_else(|| {
        voucher["discount_value"].as_str().and_then(|s| s.parse::<f64>().ok()).unwrap_or(0.0)
    });

    if d_type == "percent" || d_type == "persen" {
        if d_value >= 1.0 && d_value <= 100.0 {
            d_value /= 100.0;
        }
        discount_amount = (subtotal as f64) * d_value;
        
        let max_disc = voucher["max_discount"].as_f64().unwrap_or_else(|| {
            voucher["max_discount"].as_str().and_then(|s| s.parse::<f64>().ok()).unwrap_or(0.0)
        });

        if max_disc > 0.0 && discount_amount > max_disc {
            discount_amount = max_disc;
        }
    } else if d_type == "fixed" || d_type == "nominal" {
        discount_amount = d_value;
    }

    // Keamanan tambahan: Diskon tidak boleh melebihi total belanja
    let mut final_discount = discount_amount as i64;
    if final_discount > subtotal {
        final_discount = subtotal;
    }
    
    // Keamanan tambahan: Diskon tidak boleh menjadi minus
    if final_discount < 0 {
        final_discount = 0;
    }
    
    let final_total = subtotal - final_discount;

    let success_response = json!({
        "message": "Promo berhasil divalidasi!",
        "discount_amount": final_discount,
        "final_total": final_total
    });

    (StatusCode::OK, Json(success_response)).into_response()
}

fn error_response(status: StatusCode, message: &str) -> Response {
    let error_json = json!({ "error": message });
    (status, Json(error_json)).into_response()
}