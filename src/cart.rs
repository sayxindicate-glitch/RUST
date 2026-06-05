use axum::{
    extract::Json,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::env;

// Tambahkan "Default" agar mudah menangani body kosong
#[derive(Debug, Deserialize, Default)]
pub struct CartPayload {
    pub product_id: Option<Value>,
    pub quantity: Option<Value>,
    pub id: Option<Value>,
}

// ------------------------------------------------------------------
// HELPER: Validasi Token & Ambil User ID 
// (Dibuat terpisah agar tidak mengulang kode di GET, POST, dan DELETE)
// ------------------------------------------------------------------
async fn get_user_id(headers: &HeaderMap, client: &reqwest::Client, clean_url: &str) -> Result<(String, String), Response> {
    let token = match headers.get("Authorization").and_then(|h| h.to_str().ok()) {
        Some(h) if h.starts_with("Bearer ") => h[7..].trim().to_string(),
        _ => return Err(error_response(StatusCode::UNAUTHORIZED, "Tidak ada akses")),
    };

    let supabase_anon = env::var("SUPABASE_ANON_KEY").unwrap_or_default();
    let auth_url = format!("{}/auth/v1/user", clean_url);
    
    let auth_res = client.get(&auth_url)
        .header("apikey", &supabase_anon)
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await;

    match auth_res {
        Ok(res) if res.status().is_success() => {
            let user_data: Value = res.json().await.unwrap_or(json!({}));
            match user_data["id"].as_str() {
                Some(id) => Ok((id.to_string(), token)),
                None => Err(error_response(StatusCode::UNAUTHORIZED, "Sesi tidak valid")),
            }
        }
        _ => Err(error_response(StatusCode::UNAUTHORIZED, "Sesi tidak valid")),
    }
}

// ==========================================
// 1. GET HANDLER: Ambil Isi Keranjang
// ==========================================
pub async fn get_cart(headers: HeaderMap) -> impl IntoResponse {
    let supabase_url = env::var("SUPABASE_URL").unwrap_or_default();
    let clean_url = supabase_url.trim_end_matches('/');
    let supabase_anon = env::var("SUPABASE_ANON_KEY").unwrap_or_default();
    let client = reqwest::Client::new();

    let (user_id, token) = match get_user_id(&headers, &client, clean_url).await {
        Ok(data) => data,
        Err(err_resp) => return err_resp,
    };

    let url = format!("{}/rest/v1/gg_cart_items?user_id=eq.{}&select=*", clean_url, user_id);
    match client.get(&url).header("apikey", &supabase_anon).header("Authorization", format!("Bearer {}", token)).send().await {
        Ok(res) if res.status().is_success() => {
            let data: Value = res.json().await.unwrap_or(json!([]));
            success_response(data)
        }
        _ => error_response(StatusCode::BAD_REQUEST, "Gagal memuat data keranjang"),
    }
}

// ==========================================
// 2. POST HANDLER: Tambah / Update Keranjang
// ==========================================
pub async fn add_to_cart(headers: HeaderMap, payload_opt: Option<Json<CartPayload>>) -> impl IntoResponse {
    let payload = payload_opt.map(|j| j.0).unwrap_or_default();
    
    let supabase_url = env::var("SUPABASE_URL").unwrap_or_default();
    let clean_url = supabase_url.trim_end_matches('/');
    let supabase_anon = env::var("SUPABASE_ANON_KEY").unwrap_or_default();
    let client = reqwest::Client::new();

    let (user_id, token) = match get_user_id(&headers, &client, clean_url).await {
        Ok(data) => data,
        Err(err_resp) => return err_resp,
    };

    let product_id_str = match &payload.product_id {
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::String(s)) if !s.is_empty() => s.to_string(),
        _ => return error_response(StatusCode::BAD_REQUEST, "ID Produk wajib diisi"),
    };

    let safe_quantity = match &payload.quantity {
        Some(Value::Number(n)) => n.as_i64().unwrap_or(1),
        Some(Value::String(s)) => s.parse::<i64>().unwrap_or(1),
        _ => 1,
    };

    if safe_quantity <= 0 {
        return error_response(StatusCode::BAD_REQUEST, "Kuantitas barang tidak valid (harus angka lebih dari 0)");
    }

    let prod_url = format!("{}/rest/v1/gg_products?id=eq.{}&select=title,img,price,promo_price,is_promo", clean_url, product_id_str);
    let real_product = match client.get(&prod_url).header("apikey", &supabase_anon).header("Authorization", format!("Bearer {}", token)).send().await {
        Ok(res) if res.status().is_success() => {
            let data: Value = res.json().await.unwrap_or(json!([]));
            match data.as_array().and_then(|arr| arr.get(0).cloned()) {
                Some(p) => p,
                None => return error_response(StatusCode::BAD_REQUEST, "Produk tidak ditemukan atau tidak valid"),
            }
        }
        _ => return error_response(StatusCode::BAD_REQUEST, "Produk tidak ditemukan atau tidak valid"),
    };

    let is_promo = real_product["is_promo"].as_bool().unwrap_or(false);
    let price = real_product["price"].as_f64().unwrap_or(0.0);
    let promo_price = real_product["promo_price"].as_f64().unwrap_or(0.0);
    let secure_price = if is_promo && promo_price > 0.0 { promo_price } else { price };

    let check_url = format!("{}/rest/v1/gg_cart_items?user_id=eq.{}&product_id=eq.{}&select=*", clean_url, user_id, product_id_str);
    let existing_item = if let Ok(res) = client.get(&check_url).header("apikey", &supabase_anon).header("Authorization", format!("Bearer {}", token)).send().await {
        res.json::<Value>().await.ok().and_then(|data| data.as_array().and_then(|arr| arr.get(0).cloned()))
    } else {
        None
    };

    if let Some(existing) = existing_item {
        // --- PERBAIKAN: Membaca ID dan Quantity secara aman ---
        let current_qty = match &existing["quantity"] {
            Value::Number(n) => n.as_i64().unwrap_or(0),
            Value::String(s) => s.parse::<i64>().unwrap_or(0),
            _ => 0,
        };
        let new_total_qty = current_qty + safe_quantity;

        if new_total_qty > 1000 {
            return error_response(StatusCode::BAD_REQUEST, "Kouta maksimal per barang tercapai");
        }

        let item_id_str = match &existing["id"] {
            Value::Number(n) => n.to_string(),
            Value::String(s) => s.to_string(),
            _ => String::new(),
        };

        let update_url = format!("{}/rest/v1/gg_cart_items?id=eq.{}", clean_url, item_id_str);
        let update_res = client.patch(&update_url)
            .header("apikey", &supabase_anon)
            .header("Authorization", format!("Bearer {}", token))
            .json(&json!({ "quantity": new_total_qty }))
            .send().await;

        match update_res {
            Ok(res) if res.status().is_success() => {
                return success_response(json!({ "message": "Jumlah barang berhasil diperbarui" }));
            }
            Ok(res) => {
                let err_text = res.text().await.unwrap_or_default();
                println!("🔥 GAGAL UPDATE KERANJANG (Supabase): {}", err_text);
                return error_response(StatusCode::BAD_REQUEST, "Gagal memperbarui jumlah barang");
            }
            Err(e) => {
                println!("🔥 GAGAL KONEKSI UPDATE KERANJANG: {}", e);
                return error_response(StatusCode::BAD_REQUEST, "Gagal memperbarui jumlah barang");
            }
        }
    } else {
        // Barang baru, Insert
        let insert_url = format!("{}/rest/v1/gg_cart_items", clean_url);
        let insert_res = client.post(&insert_url)
            .header("apikey", &supabase_anon)
            .header("Authorization", format!("Bearer {}", token))
            .json(&json!({
                "user_id": user_id,
                "product_id": product_id_str,
                "product_name": real_product["title"],
                "product_price": secure_price,
                "product_img": real_product["img"],
                "quantity": safe_quantity
            }))
            .send().await;

        match insert_res {
            Ok(res) if res.status().is_success() => {
                return success_response(json!({ "message": "Berhasil masuk keranjang, tervalidasi server" }));
            }
            Ok(res) => {
                let err_text = res.text().await.unwrap_or_default();
                println!("🔥 GAGAL INSERT KERANJANG (Supabase): {}", err_text);
                return error_response(StatusCode::BAD_REQUEST, "Gagal memasukkan barang ke keranjang");
            }
            Err(e) => {
                println!("🔥 GAGAL KONEKSI INSERT KERANJANG: {}", e);
                return error_response(StatusCode::BAD_REQUEST, "Gagal memasukkan barang ke keranjang");
            }
        }
    }
}

// ==========================================
// 3. DELETE HANDLER: Hapus Barang
// ==========================================
pub async fn remove_from_cart(headers: HeaderMap, payload_opt: Option<Json<CartPayload>>) -> impl IntoResponse {
    let payload = payload_opt.map(|j| j.0).unwrap_or_default();
    
    let supabase_url = env::var("SUPABASE_URL").unwrap_or_default();
    let clean_url = supabase_url.trim_end_matches('/');
    let supabase_anon = env::var("SUPABASE_ANON_KEY").unwrap_or_default();
    let client = reqwest::Client::new();

    let (user_id, token) = match get_user_id(&headers, &client, clean_url).await {
        Ok(data) => data,
        Err(err_resp) => return err_resp,
    };

    let item_id_str = match &payload.id {
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::String(s)) if !s.is_empty() => s.to_string(),
        _ => return error_response(StatusCode::BAD_REQUEST, "ID Barang tidak valid"),
    };

    let del_url = format!("{}/rest/v1/gg_cart_items?id=eq.{}&user_id=eq.{}", clean_url, item_id_str, user_id);
    let del_res = client.delete(&del_url)
        .header("apikey", &supabase_anon)
        .header("Authorization", format!("Bearer {}", token))
        .send().await;

    if del_res.is_err() || !del_res.unwrap().status().is_success() {
        return error_response(StatusCode::BAD_REQUEST, "Gagal menghapus barang");
    }
    success_response(json!({ "message": "Barang dihapus" }))
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