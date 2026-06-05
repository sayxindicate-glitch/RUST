use axum::{
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};
use std::env;

pub async fn get_products() -> impl IntoResponse {
    // 1. Mengambil Environment Variables & Melacak jika hilang
    let supabase_url = match env::var("SUPABASE_URL") {
        Ok(url) => url,
        Err(e) => {
            println!("🔥 GAGAL: SUPABASE_URL tidak terbaca di .env! Error: {}", e);
            return server_error();
        }
    };
    let supabase_key = match env::var("SUPABASE_ANON_KEY") {
        Ok(key) => key,
        Err(e) => {
            println!("🔥 GAGAL: SUPABASE_ANON_KEY tidak terbaca di .env! Error: {}", e);
            return server_error();
        }
    };

    // 2. Mengamankan URL
    let clean_url = supabase_url.trim_end_matches('/');

    // =========================================================================
    // SECURITY PATCH: Memasang Limit pada Query (Menangkal Ancaman 31 & 35)
    // =========================================================================
    // Jangan pernah menarik seluruh database tanpa batas. Kita batasi maksimal 1000 produk.
    // Jika produk lebih dari 1000, idealnya menggunakan sistem paginasi (offset).
    let endpoint = format!("{}/rest/v1/gg_products?select=*&order=id.asc&limit=1000", clean_url);
    
    let client = reqwest::Client::new();
    let res = client.get(&endpoint)
        .header("apikey", &supabase_key)
        .header("Authorization", format!("Bearer {}", supabase_key))
        .send()
        .await;

    // 4. Tangani hasil (Sukses vs Gagal)
    match res {
        // --- SKENARIO SUKSES ---
        Ok(response) if response.status().is_success() => {
            let data: Value = response.json().await.unwrap_or(json!([]));
            
            // PERFORMANCE PATCH: Header Caching
            // Cache di browser selama 60 detik agar jika user bolak-balik halaman,
            // mereka tidak membebani server/database kamu berulang-ulang.
            let mut headers = HeaderMap::new();
            headers.insert(
                "Cache-Control",
                HeaderValue::from_static("public, s-maxage=60, stale-while-revalidate=300"),
            );
            
            (StatusCode::OK, headers, Json(data)).into_response()
        }
        
        // --- SKENARIO GAGAL KONEKSI KE SUPABASE (Cetak ke Terminal) ---
        Ok(response) => {
            println!("🔥 GAGAL DARI SUPABASE! Status HTTP: {}", response.status());
            let err_text = response.text().await.unwrap_or_default();
            println!("🔥 DETAIL ERROR: {}", err_text);
            server_error()
        }
        Err(e) => {
            println!("🔥 GAGAL KONEKSI REQWEST (Internet/URL)! Error: {}", e);
            server_error()
        }
    }
}

// SECURITY PATCH: Jangan ekspos detail error database ke browser pengunjung
fn server_error() -> Response {
    let error_json = json!({ "error": "Terjadi kesalahan saat memuat data katalog." });
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(error_json),
    ).into_response()
}