use axum::{
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};
use std::env;

// =========================================================================
// SECURITY PATCH 1: URL Encoder Manual untuk sanitasi nama file
// (Mencegah Broken Link dan eksploitasi URL/XSS via nama file aneh)
// =========================================================================
fn encode_uri_component(input: &str) -> String {
    let mut encoded = String::new();
    for b in input.bytes() {
        match b {
            // Hanya izinkan karakter URL-safe (Alfanumerik + Strip/Titik)
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(b as char);
            }
            // Karakter selain di atas (seperti spasi) diubah ke Hex (contoh: spasi jadi %20)
            _ => {
                encoded.push_str(&format!("%{:02X}", b));
            }
        }
    }
    encoded
}

pub async fn get_logos() -> impl IntoResponse {
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

    let clean_url = supabase_url.trim_end_matches('/');
    let client = reqwest::Client::new();

    let list_url = format!("{}/storage/v1/object/list/logos", clean_url);
    
    // Supabase mewajibkan adanya property "prefix"
    let payload = json!({
        "prefix": "", 
        "limit": 100,
        "offset": 0,
        "sortBy": {
            "column": "name",
            "order": "asc"
        }
    });

    let res = client.post(&list_url)
        .header("apikey", &supabase_key)
        .header("Authorization", format!("Bearer {}", supabase_key))
        .json(&payload)
        .send()
        .await;

    match res {
        Ok(response) if response.status().is_success() => {
            let data: Value = response.json().await.unwrap_or(json!([]));
            let mut logo_urls = Vec::new();

            if let Some(files) = data.as_array() {
                for file in files {
                    if let Some(name) = file["name"].as_str() {
                        if name != ".emptyFolderPlaceholder" {
                            // Terapkan fungsi Encoder di sini!
                            let safe_name = encode_uri_component(name);
                            let public_url = format!("{}/storage/v1/object/public/logos/{}", clean_url, safe_name);
                            
                            logo_urls.push(json!({
                                "name": name,
                                "url": public_url
                            }));
                        }
                    }
                }
            }

            // PERFORMANCE PATCH: Header Caching
            let mut headers = HeaderMap::new();
            headers.insert(
                "Cache-Control",
                HeaderValue::from_static("public, s-maxage=3600, stale-while-revalidate=86400"),
            );

            (StatusCode::OK, headers, Json(logo_urls)).into_response()
        }
        Ok(response) => {
            println!("🔥 GAGAL DARI SUPABASE (LOGOS)! Status HTTP: {}", response.status());
            let err_text = response.text().await.unwrap_or_default();
            println!("🔥 DETAIL ERROR: {}", err_text);
            server_error()
        }
        Err(e) => {
            println!("🔥 GAGAL KONEKSI REQWEST (LOGOS)! Error: {}", e);
            server_error()
        }
    }
}

// SECURITY PATCH 2: Menyembunyikan Detail Error (Mencegah Information Disclosure)
fn server_error() -> Response {
    let error_json = json!({ "error": "Terjadi kesalahan saat memuat logo." });
    (StatusCode::INTERNAL_SERVER_ERROR, Json(error_json)).into_response()
}