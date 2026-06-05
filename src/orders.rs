use axum::{
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};
use std::env;

pub async fn get_orders(headers: HeaderMap) -> impl IntoResponse {
    // 1. Ambil & Validasi Token
    let token = match headers.get("Authorization").and_then(|h| h.to_str().ok()) {
        Some(h) if h.starts_with("Bearer ") => h[7..].trim(),
        _ => return error_response(StatusCode::UNAUTHORIZED, "Akses ditolak"),
    };

    let supabase_url = env::var("SUPABASE_URL").unwrap_or_default();
    let supabase_anon = env::var("SUPABASE_ANON_KEY").unwrap_or_default();
    let clean_url = supabase_url.trim_end_matches('/');

    if clean_url.is_empty() || supabase_anon.is_empty() {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Terjadi kesalahan internal server");
    }

    let client = reqwest::Client::new();

    // 2. Verifikasi Identitas User ke Supabase
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
        _ => return error_response(StatusCode::UNAUTHORIZED, "Sesi tidak valid"),
    };

    // =========================================================================
    // SECURITY PATCH 1: Batasi Pengambilan Data (Limit 100) Mencegah DoS / RAM Bocor
    // =========================================================================
    let orders_url = format!("{}/rest/v1/gg_orders?user_id=eq.{}&order=created_at.desc&limit=100", clean_url, user_id);
    let orders_res = client.get(&orders_url)
        .header("apikey", &supabase_anon)
        .header("Authorization", format!("Bearer {}", token))
        .send().await;

    let orders_data = match orders_res {
        Ok(res) if res.status().is_success() => res.json::<Value>().await.unwrap_or(json!([])),
        _ => return error_response(StatusCode::BAD_REQUEST, "Gagal memuat daftar pesanan"),
    };

    let orders_arr = match orders_data.as_array() {
        Some(arr) if !arr.is_empty() => arr,
        _ => return no_cache_response(json!([])),
    };

    let mut order_ids = Vec::new();
    for order in orders_arr {
        let id_str = match &order["id"] {
            Value::Number(n) => n.to_string(),
            Value::String(s) => s.to_string(),
            _ => String::new(),
        };
        // SECURITY PATCH 2: Sanitasi ID (Hanya izinkan Huruf, Angka, dan Strip)
        if !id_str.is_empty() && id_str.chars().all(|c| c.is_alphanumeric() || c == '-') {
            order_ids.push(id_str);
        }
    }
    
    let mut items_arr: Vec<Value> = Vec::new();
    if !order_ids.is_empty() {
        let order_id_query = order_ids.join(",");
        let items_url = format!("{}/rest/v1/gg_order_items?order_id=in.({})", clean_url, order_id_query);
        let items_res = client.get(&items_url)
            .header("apikey", &supabase_anon)
            .header("Authorization", format!("Bearer {}", token))
            .send().await;
            
        let items_data = match items_res {
            Ok(res) if res.status().is_success() => res.json::<Value>().await.unwrap_or(json!([])),
            _ => json!([]),
        };
        items_arr = items_data.as_array().cloned().unwrap_or_default();
    }

    let mut product_ids = Vec::new();
    for item in &items_arr {
        let pid = match &item["product_id"] {
            Value::Number(n) => n.to_string(),
            Value::String(s) => s.to_string(),
            _ => String::new(),
        };
        // SECURITY PATCH 3: Sanitasi ID Produk
        if !pid.is_empty() && !product_ids.contains(&pid) && pid.chars().all(|c| c.is_alphanumeric() || c == '-') {
            product_ids.push(pid);
        }
    }
    
    let mut products_arr: Vec<Value> = Vec::new();
    if !product_ids.is_empty() {
        let product_id_query = product_ids.join(",");
        let products_url = format!("{}/rest/v1/gg_products?id=in.({})&select=id,title,img", clean_url, product_id_query);
        let products_res = client.get(&products_url)
            .header("apikey", &supabase_anon)
            .header("Authorization", format!("Bearer {}", token))
            .send().await;
            
        let products_data = match products_res {
            Ok(res) if res.status().is_success() => res.json::<Value>().await.unwrap_or(json!([])),
            _ => json!([]),
        };
        products_arr = products_data.as_array().cloned().unwrap_or_default();
    }

    let mut final_orders = Vec::new();
    for order in orders_arr {
        let order_id_str = match &order["id"] {
            Value::Number(n) => n.to_string(),
            Value::String(s) => s.to_string(),
            _ => String::new(),
        };
        
        let mut mapped_items = Vec::new();

        let order_items: Vec<&Value> = items_arr.iter().filter(|i| {
            let i_order_id = match &i["order_id"] {
                Value::Number(n) => n.to_string(),
                Value::String(s) => s.to_string(),
                _ => String::new(),
            };
            i_order_id == order_id_str
        }).collect();

        for item in order_items {
            let p_id = match &item["product_id"] {
                Value::Number(n) => n.to_string(),
                Value::String(s) => s.to_string(),
                _ => String::new(),
            };

            let p_detail = products_arr.iter().find(|p| {
                let id_val = match &p["id"] {
                    Value::Number(n) => n.to_string(),
                    Value::String(s) => s.to_string(),
                    _ => String::new(),
                };
                id_val == p_id
            });

            let title = p_detail.and_then(|p| p["title"].as_str()).unwrap_or("Produk Tidak Diketahui");
            let img = p_detail.and_then(|p| p["img"].as_str()).unwrap_or("https://placehold.co/100x100?text=No+Image");
            
            let fallback_price = 0.0;
            let price_at_buy = match &item["price_at_buy"] {
                Value::Number(n) => n.as_f64().unwrap_or(fallback_price),
                Value::String(s) => s.parse::<f64>().unwrap_or(fallback_price),
                _ => fallback_price,
            };

            let quantity = item["quantity"].as_i64().unwrap_or(1);

            mapped_items.push(json!({
                "product_name": title,
                "product_img": img,
                "product_price": price_at_buy,
                "quantity": quantity
            }));
        }

        let mut final_order = order.clone();
        if let Some(obj) = final_order.as_object_mut() {
            obj.insert("items".to_string(), json!(mapped_items));
        }
        final_orders.push(final_order);
    }

    no_cache_response(json!(final_orders))
}

fn no_cache_response(payload: Value) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert("Cache-Control", HeaderValue::from_static("no-store, no-cache, must-revalidate, proxy-revalidate"));
    headers.insert("Pragma", HeaderValue::from_static("no-cache"));
    headers.insert("Expires", HeaderValue::from_static("0"));

    (StatusCode::OK, headers, Json(payload)).into_response()
}

fn error_response(status: StatusCode, message: &str) -> Response {
    let error_json = json!({ "error": message });
    (status, Json(error_json)).into_response()
}