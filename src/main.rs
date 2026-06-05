use axum::{
    routing::{get, post, delete, put}, 
    Router,
    extract::DefaultBodyLimit,
    http::{HeaderValue, Method, header},
};
use tower_http::cors::CorsLayer;

mod products;
mod apply_voucher;
mod auth;
mod cart;
mod checkout;
mod logos;
mod orders;
mod user;
mod vouchers; 

#[tokio::main]
async fn main() {
    // Muat variabel lingkungan
    dotenvy::dotenv().ok();

    // =========================================================================
    // SECURITY PATCH 1: Menghapus "Wildcard CORS" (Menangkal Ancaman 10 & 11)
    // =========================================================================
    // Tentukan secara eksplisit dari alamat mana saja request boleh masuk.
    // Jika frontend kamu nanti di-deploy (misal di Vercel/Render), masukkan URL-nya ke dalam list ini.
    let origins = [
        "http://localhost:5500".parse::<HeaderValue>().unwrap(),
        "http://127.0.0.1:5500".parse::<HeaderValue>().unwrap(),
        // Contoh saat nanti online:
        // "https://bakoel-frontend-kamu.onrender.com".parse::<HeaderValue>().unwrap(),
    ];

    let cors = CorsLayer::new()
        .allow_origin(origins) // HANYA izinkan domain di atas
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::PATCH])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE, header::ACCEPT]);

    // =========================================================================
    // 2. PEMBENTUKAN ROUTER & MIDDLEWARE
    // =========================================================================
    let app = Router::new()
        .route("/", get(|| async { "Server API GudangBarang Berjalan Normal!" }))
        .route("/api/products", get(products::get_products))
        .route("/api/logos", get(logos::get_logos))
        .route("/api/auth", post(auth::auth_handler))
        .route("/api/cart", 
            get(cart::get_cart)
            .post(cart::add_to_cart)
            .delete(cart::remove_from_cart)
        )
        .route("/api/checkout", post(checkout::process_checkout))
        .route("/api/apply-voucher", post(apply_voucher::apply_voucher))
        .route("/api/orders", get(orders::get_orders))
        .route("/api/user", 
            get(user::get_user)
            .put(user::update_user)
        )
        .route("/api/vouchers", get(vouchers::get_vouchers))
        // Terapkan CORS yang sudah di-patch
        .layer(cors)
        // =========================================================================
        // SECURITY PATCH 2: Mencegah DoS / Out of Memory (Menangkal Ancaman 31 & 35)
        // =========================================================================
        // Membatasi maksimal payload request dari klien sebesar 2 MB.
        // Jika hacker mengirim data 50GB, server akan langsung menolaknya sebelum masuk ke RAM.
        .layer(DefaultBodyLimit::max(1024 * 1024 * 2));

    let port = std::env::var("PORT").unwrap_or_else(|_| "10000".to_string());
    let addr = format!("0.0.0.0:{}", port);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    println!("🚀 Server berjalan dan TERLINDUNGI di http://{}", addr);
    
    axum::serve(listener, app).await.unwrap();
}