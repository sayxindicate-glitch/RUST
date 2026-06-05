use axum::{
    extract::Json,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::env;

// Struktur berlapis untuk menampung payload Checkout
#[derive(Debug, Deserialize, Default)]
pub struct CheckoutItem {
    pub product_id: Value,
    pub quantity: Value,
}

#[derive(Debug, Deserialize, Default)]
pub struct CheckoutPayload {
    pub shipping_address: Option<String>,
    pub phone_number: Option<String>,
    pub items: Option<Vec<CheckoutItem>>,
    pub used_vouchers: Option<Vec<String>>,
}

pub async fn process_checkout(
    headers: HeaderMap, 
    payload_opt: Option<Json<CheckoutPayload>>
) -> impl IntoResponse {
    // 1. Ambil & Validasi Token Authorization (Sesi)
    let token = match headers.get("Authorization").and_then(|h| h.to_str().ok()) {
        Some(h) if h.starts_with("Bearer ") => h[7..].trim(),
        _ => return error_response(StatusCode::UNAUTHORIZED, "Akses ditolak. Silakan login kembali."),
    };

    let supabase_url = env::var("SUPABASE_URL").unwrap_or_default();
    let supabase_anon = env::var("SUPABASE_ANON_KEY").unwrap_or_default();
    let clean_url = supabase_url.trim_end_matches('/');
    
    if clean_url.is_empty() || supabase_anon.is_empty() {
        println!("🔥 GAGAL CHECKOUT: Variabel lingkungan .env belum lengkap!");
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Terjadi kesalahan server");
    }

    let client = reqwest::Client::new();

    // 2. Verifikasi Sesi ke Supabase Auth
    let auth_url = format!("{}/auth/v1/user", clean_url);
    let auth_res = client.get(&auth_url)
        .header("apikey", &supabase_anon)
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
        Ok(res) => {
            println!("🔥 GAGAL CHECKOUT: Sesi ditolak Supabase. Status: {}", res.status());
            return error_response(StatusCode::UNAUTHORIZED, "Sesi tidak valid");
        }
        Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Gagal memverifikasi pengguna"),
    };

    // 3. Ekstrak Payload dengan Aman
    let payload = payload_opt.map(|j| j.0).unwrap_or_default();
    let items = match payload.items {
        Some(i) if !i.is_empty() => i,
        _ => return error_response(StatusCode::BAD_REQUEST, "Keranjang kosong"),
    };

    let shipping_address = payload.shipping_address.unwrap_or_default();
    let phone_number = payload.phone_number.unwrap_or_default();
    
    if shipping_address.is_empty() || phone_number.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "Alamat pengiriman dan Nomor Telepon wajib diisi");
    }
    
    // SECURITY PATCH: Sanitasi panjang alamat untuk mencegah Database Overflow
    if shipping_address.len() > 500 || phone_number.len() > 30 {
        return error_response(StatusCode::BAD_REQUEST, "Data pengiriman terlalu panjang");
    }

    let full_address = format!("{} (Telp: {})", shipping_address, phone_number);

    // =========================================================================
    // SECURITY 1: MENGHITUNG ULANG HARGA ASLI DARI GUDANG DATABASE
    // =========================================================================
    let mut id_list = Vec::new();
    for item in &items {
        let id_str = match &item.product_id {
            Value::Number(n) => n.to_string(),
            Value::String(s) => s.to_string(),
            _ => continue,
        };
        
        // SECURITY PATCH: Cegah PostgREST Injection (Hanya izinkan Alphanumeric & Strip UUID)
        if !id_str.is_empty() && id_str.chars().all(|c| c.is_alphanumeric() || c == '-') {
            id_list.push(id_str);
        }
    }
    
    if id_list.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "Produk tidak valid.");
    }

    let in_query = id_list.join(",");
    let prod_url = format!("{}/rest/v1/gg_products?id=in.({})&select=id,price,promo_price,is_promo", clean_url, in_query);
    
    let prod_res = client.get(&prod_url)
        .header("apikey", &supabase_anon)
        .header("Authorization", format!("Bearer {}", token))
        .send().await;

    let real_products = match prod_res {
        Ok(res) if res.status().is_success() => res.json::<Value>().await.unwrap_or(json!([])),
        _ => {
            println!("🔥 GAGAL CHECKOUT: Gagal memvalidasi harga asli ke database produk.");
            return error_response(StatusCode::BAD_REQUEST, "Data barang gagal divalidasi");
        }
    };

    let mut server_calculated_total = 0.0;
    let mut secure_order_items = Vec::new();
    let real_products_arr = real_products.as_array().cloned().unwrap_or_default();

    for item in &items {
        let req_id = match &item.product_id {
            Value::Number(n) => n.to_string(),
            Value::String(s) => s.to_string(),
            _ => continue,
        };
        
        let qty = match &item.quantity {
            Value::Number(n) => n.as_i64().unwrap_or(1),
            Value::String(s) => s.parse::<i64>().unwrap_or(1),
            _ => 1,
        };

        // SECURITY PATCH: Blokir Kuantitas Minus & Pembatasan Maksimal (Integer Overflow/Logic Attack)
        if qty <= 0 {
            return error_response(StatusCode::BAD_REQUEST, "Kuantitas barang tidak boleh kurang dari 1.");
        }
        if qty > 1000 {
            return error_response(StatusCode::BAD_REQUEST, "Pembelian melebihi batas maksimal per barang.");
        }

        let real_prod = real_products_arr.iter().find(|p| {
            let p_id = match &p["id"] {
                Value::Number(n) => n.to_string(),
                Value::String(s) => s.to_string(),
                _ => String::new(),
            };
            p_id == req_id
        });

        if let Some(prod) = real_prod {
            let is_promo = prod["is_promo"].as_bool().unwrap_or(false);
            let price = prod["price"].as_f64().unwrap_or(0.0);
            let promo_price = prod["promo_price"].as_f64().unwrap_or(0.0);
            
            let final_item_price = if is_promo && promo_price > 0.0 { promo_price } else { price };
            server_calculated_total += final_item_price * (qty as f64);

            secure_order_items.push(json!({
                "product_id": req_id,
                "quantity": qty,
                "price_at_buy": final_item_price.to_string() 
            }));
        } else {
            return error_response(StatusCode::BAD_REQUEST, &format!("Barang ID {} tidak valid atau sudah dihapus.", req_id));
        }
    }

    // =========================================================================
    // SECURITY 2: VALIDASI VOUCHER & DISKON DI SERVER
    // =========================================================================
    let used_vouchers = payload.used_vouchers.unwrap_or_default();
    
    if !used_vouchers.is_empty() {
        let code = used_vouchers[0].trim().to_uppercase();
        
        // SECURITY PATCH: Cek apakah user SUDAH pernah memakai voucher ini sebelum memotong harga
        let claim_check_url = format!(
            "{}/rest/v1/gg_claimed_vouchers?user_id=eq.{}&voucher_code=eq.{}&select=is_used",
            clean_url, user_id, code
        );
        
        if let Ok(claim_res) = client.get(&claim_check_url).header("apikey", &supabase_anon).header("Authorization", format!("Bearer {}", token)).send().await {
            if let Ok(claim_data) = claim_res.json::<Value>().await {
                if let Some(arr) = claim_data.as_array() {
                    if arr.iter().any(|row| row["is_used"].as_bool().unwrap_or(false)) {
                        return error_response(StatusCode::BAD_REQUEST, "Voucher sudah digunakan sebelumnya.");
                    }
                }
            }
        }

        let vch_url = format!("{}/rest/v1/gg_vouchers?code=eq.{}&select=*", clean_url, code);
        if let Ok(res) = client.get(&vch_url).header("apikey", &supabase_anon).header("Authorization", format!("Bearer {}", token)).send().await {
            if let Ok(vch_data) = res.json::<Value>().await {
                if let Some(voucher) = vch_data.as_array().and_then(|arr| arr.get(0)) {
                    
                    let min_purchase = voucher["min_purchase"].as_f64().unwrap_or_else(|| {
                        voucher["min_purchase"].as_str().and_then(|s| s.parse::<f64>().ok()).unwrap_or(0.0)
                    });

                    if server_calculated_total >= min_purchase {
                        let mut discount_amount = 0.0;
                        let d_type = voucher["discount_type"].as_str().unwrap_or("").trim().to_lowercase();
                        let mut d_value = voucher["discount_value"].as_f64().unwrap_or_else(|| {
                            voucher["discount_value"].as_str().and_then(|s| s.parse::<f64>().ok()).unwrap_or(0.0)
                        });

                        if d_type == "percent" || d_type == "persen" {
                            if d_value >= 1.0 && d_value <= 100.0 { d_value /= 100.0; }
                            discount_amount = server_calculated_total * d_value;
                            
                            let max_disc = voucher["max_discount"].as_f64().unwrap_or_else(|| {
                                voucher["max_discount"].as_str().and_then(|s| s.parse::<f64>().ok()).unwrap_or(0.0)
                            });
                            if max_disc > 0.0 && discount_amount > max_disc { discount_amount = max_disc; }
                        } else if d_type == "fixed" || d_type == "nominal" {
                            discount_amount = d_value;
                        }

                        if discount_amount > server_calculated_total { discount_amount = server_calculated_total; }
                        server_calculated_total -= discount_amount;
                    }
                }
            }
        }
    }

    if server_calculated_total < 0.0 { server_calculated_total = 0.0; }
    
    // SECURITY PATCH: Mencegah Integer Overflow i64 di Database PostgREST
    if server_calculated_total > 1_000_000_000.0 {
        return error_response(StatusCode::BAD_REQUEST, "Total pesanan melebihi batas maksimal transaksi.");
    }

    // =========================================================================
    // 3. EKSEKUSI PENYIMPANAN KE DATABASE (REST POSTGREST)
    // =========================================================================
    
    let order_url = format!("{}/rest/v1/gg_orders", clean_url);
    let order_insert_res = client.post(&order_url)
        .header("apikey", &supabase_anon)
        .header("Authorization", format!("Bearer {}", token))
        .header("Prefer", "return=representation")
        .json(&json!([{
            "user_id": user_id,
            "total_price": server_calculated_total as i64,
            "shipping_address": full_address,
            "status": "Diproses"
        }]))
        .send().await;

    let order_id = match order_insert_res {
        Ok(res) if res.status().is_success() => {
            let returned_data: Value = res.json().await.unwrap_or(json!([]));
            match returned_data.as_array().and_then(|arr| arr.get(0)).and_then(|obj| obj["id"].as_i64()) {
                Some(id) => id,
                None => {
                    println!("🔥 GAGAL CHECKOUT: Pesanan berhasil dikirim, tapi Supabase tidak mengembalikan ID Pesanan.");
                    return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Gagal memverifikasi pembuatan pesanan");
                }
            }
        }
        Ok(res) => {
            let err = res.text().await.unwrap_or_default();
            println!("🔥 GAGAL CHECKOUT (Insert Order): {}", err);
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Gagal membuat pesanan");
        }
        Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Gagal membuat pesanan"),
    };

    // 4. Masukkan items ke tabel gg_order_items
    let mut items_to_insert = Vec::new();
    for secure_item in secure_order_items {
        let mut new_item = secure_item.clone();
        new_item["order_id"] = json!(order_id);
        items_to_insert.push(new_item);
    }

    let items_url = format!("{}/rest/v1/gg_order_items", clean_url);
    let items_res = client.post(&items_url)
        .header("apikey", &supabase_anon)
        .header("Authorization", format!("Bearer {}", token))
        .json(&items_to_insert)
        .send().await;

    if let Ok(res) = items_res {
        if !res.status().is_success() {
            println!("🔥 PERINGATAN CHECKOUT: Gagal memasukkan rincian item ke pesanan ID {}.", order_id);
        }
    }

    // 5. Kosongkan keranjang belanja
    let clear_cart_url = format!("{}/rest/v1/gg_cart_items?user_id=eq.{}", clean_url, user_id);
    let _ = client.delete(&clear_cart_url)
        .header("apikey", &supabase_anon)
        .header("Authorization", format!("Bearer {}", token))
        .send().await;

    // 6. Kunci Voucher agar tidak bisa dipakai 2x
    if !used_vouchers.is_empty() {
        let mut claimed_data = Vec::new();
        for code in used_vouchers {
            claimed_data.push(json!({
                "user_id": user_id,
                "voucher_code": code.trim().to_uppercase(),
                "is_used": true
            }));
        }

        let lock_url = format!("{}/rest/v1/gg_claimed_vouchers", clean_url);
        let _ = client.post(&lock_url)
            .header("apikey", &supabase_anon)
            .header("Authorization", format!("Bearer {}", token))
            .header("Prefer", "resolution=merge-duplicates")
            .json(&claimed_data)
            .send().await;
    }

    let success_json = json!({
        "message": "Pesanan diverifikasi & dibuat",
        "order_id": order_id
    });
    
    (StatusCode::OK, Json(success_json)).into_response()
}

fn error_response(status: StatusCode, message: &str) -> Response {
    let error_json = json!({ "error": message });
    (status, Json(error_json)).into_response()
}