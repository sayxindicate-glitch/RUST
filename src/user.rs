use axum::{
    extract::Json,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{json, Value};
use std::env;

#[derive(Debug, Deserialize, Default)]
pub struct ProfileUpdate {
    pub nama_lengkap: Option<String>,
    pub nama_panggilan: Option<String>,
    pub no_wa: Option<String>,
    pub alamat_lengkap: Option<String>,
}

// ------------------------------------------------------------------
// HELPER: Validasi Token & Ambil Data Auth (ID dan Email)
// ------------------------------------------------------------------
async fn get_user_auth(headers: &HeaderMap, client: &reqwest::Client, clean_url: &str) -> Result<(String, String, String), Response> {
    let token = match headers.get("Authorization").and_then(|h| h.to_str().ok()) {
        Some(h) if h.starts_with("Bearer ") => h[7..].trim().to_string(),
        _ => return Err(error_response(StatusCode::UNAUTHORIZED, "Akses ditolak: Token hilang")),
    };

    let supabase_anon = env::var("SUPABASE_ANON_KEY").unwrap_or_default();
    let auth_url = format!("{}/auth/v1/user", clean_url);
    
    let auth_res = client.get(&auth_url)
        .header("apikey", &supabase_anon)
        .header("Authorization", format!("Bearer {}", token))
        .send().await;

    match auth_res {
        Ok(res) if res.status().is_success() => {
            let user_data: Value = res.json().await.unwrap_or(json!({}));
            let uid = user_data["id"].as_str().unwrap_or("").to_string();
            let email = user_data["email"].as_str().unwrap_or("").to_string();
            
            if uid.is_empty() {
                return Err(error_response(StatusCode::UNAUTHORIZED, "Sesi tidak valid"));
            }
            Ok((uid, email, token))
        }
        Ok(res) => {
            println!("🔥 GAGAL USER AUTH: Status {}", res.status());
            Err(error_response(StatusCode::UNAUTHORIZED, "Sesi tidak valid"))
        }
        Err(_) => Err(error_response(StatusCode::UNAUTHORIZED, "Sesi tidak valid")),
    }
}

// ==========================================
// 1. GET HANDLER: Mengambil Data Profil
// ==========================================
pub async fn get_user(headers: HeaderMap) -> impl IntoResponse {
    let supabase_url = env::var("SUPABASE_URL").unwrap_or_default();
    let clean_url = supabase_url.trim_end_matches('/');
    let supabase_anon = env::var("SUPABASE_ANON_KEY").unwrap_or_default();
    
    if clean_url.is_empty() || supabase_anon.is_empty() {
        println!("🔥 GAGAL USER (GET): Variabel lingkungan .env belum lengkap!");
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Terjadi kesalahan internal server");
    }

    let client = reqwest::Client::new();

    let (user_id, user_email, token) = match get_user_auth(&headers, &client, clean_url).await {
        Ok(data) => data,
        Err(err_resp) => return err_resp,
    };

    let profile_url = format!("{}/rest/v1/profiles?id=eq.{}&select=*", clean_url, user_id);
    match client.get(&profile_url).header("apikey", &supabase_anon).header("Authorization", format!("Bearer {}", token)).send().await {
        Ok(res) => {
            if !res.status().is_success() {
                let err_text = res.text().await.unwrap_or_default();
                // SECURITY PATCH: Menyamarkan pesan error database (PGRST116 = Not Found)
                if !err_text.contains("PGRST116") {
                    println!("🔥 GAGAL PROFIL (GET): {}", err_text);
                    return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Gagal memuat profil");
                }
            } else {
                let data: Value = res.json().await.unwrap_or(json!([]));
                if let Some(arr) = data.as_array() {
                    if !arr.is_empty() {
                        return success_response(arr[0].clone());
                    }
                }
            }
        }
        Err(e) => {
            println!("🔥 ERROR KONEKSI PROFIL (GET): {}", e);
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Gagal memuat profil");
        }
    }
    
    // Jika profil belum ada di database, kembalikan data email dari Auth (sebagai fallback)
    success_response(json!({ "email": user_email }))
}

// ==========================================
// 2. PUT HANDLER: Memperbarui Profil
// ==========================================
pub async fn update_user(headers: HeaderMap, payload_opt: Option<Json<ProfileUpdate>>) -> impl IntoResponse {
    let payload = payload_opt.map(|j| j.0).unwrap_or_default();

    let nama_lengkap = payload.nama_lengkap.unwrap_or_default();
    let nama_panggilan = payload.nama_panggilan.unwrap_or_default();
    let no_wa = payload.no_wa.unwrap_or_default();
    let alamat_lengkap = payload.alamat_lengkap.unwrap_or_default();

    // SECURITY PATCH: Batasi panjang input (Mencegah Database Overload / DoS)
    if nama_lengkap.len() > 100 { return error_response(StatusCode::BAD_REQUEST, "Nama terlalu panjang"); }
    if nama_panggilan.len() > 50 { return error_response(StatusCode::BAD_REQUEST, "Panggilan terlalu panjang"); }
    if no_wa.len() > 20 { return error_response(StatusCode::BAD_REQUEST, "Nomor WA tidak valid"); }
    if alamat_lengkap.len() > 500 { return error_response(StatusCode::BAD_REQUEST, "Alamat terlalu panjang"); }

    let supabase_url = env::var("SUPABASE_URL").unwrap_or_default();
    let clean_url = supabase_url.trim_end_matches('/');
    let supabase_anon = env::var("SUPABASE_ANON_KEY").unwrap_or_default();
    let client = reqwest::Client::new();

    let (user_id, user_email, token) = match get_user_auth(&headers, &client, clean_url).await {
        Ok(data) => data,
        Err(err_resp) => return err_resp,
    };

    let current_time = Utc::now().to_rfc3339(); // Format ISO-8601 UTC

    let upsert_url = format!("{}/rest/v1/profiles", clean_url);
    let upsert_res = client.post(&upsert_url)
        .header("apikey", &supabase_anon)
        .header("Authorization", format!("Bearer {}", token))
        .header("Prefer", "resolution=merge-duplicates,return=representation")
        .json(&json!({
            "id": user_id,
            "email": user_email,
            "nama_lengkap": nama_lengkap,
            "nama_panggilan": nama_panggilan,
            "no_wa": no_wa,
            "alamat_lengkap": alamat_lengkap,
            "updated_at": current_time // <-- PERBAIKAN: Menggunakan updated_at agar tidak merusak tanggal pendaftaran
        }))
        .send().await;

    match upsert_res {
        Ok(res) if res.status().is_success() => {
            let data: Value = res.json().await.unwrap_or(json!([]));
            let profile = if let Some(arr) = data.as_array() {
                arr.get(0).cloned().unwrap_or(json!({}))
            } else {
                data
            };
            success_response(json!({ "message": "Profil berhasil diperbarui", "profile": profile }))
        }
        Ok(res) => {
            let err_text = res.text().await.unwrap_or_default();
            if err_text.contains("23505") {
                return error_response(StatusCode::BAD_REQUEST, "Nomor WhatsApp sudah digunakan oleh akun lain.");
            }
            println!("🔥 GAGAL PROFIL (PUT): {}", err_text);
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "Gagal memperbarui profil di server")
        }
        Err(e) => {
            println!("🔥 ERROR KONEKSI PROFIL (PUT): {}", e);
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "Gagal memperbarui profil di server")
        }
    }
}

// ------------------------------------------------------------------
// HELPER FUNCTIONS
// ------------------------------------------------------------------
fn success_response(payload: Value) -> Response {
    (StatusCode::OK, Json(payload)).into_response()
}

fn error_response(status: StatusCode, message: &str) -> Response {
    let error_json = json!({ "error": message });
    (status, Json(error_json)).into_response()
}