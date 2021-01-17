use crate::error_handler::CustomError;
use actix_web::{get, web, HttpResponse};
use serde::{Deserialize, Serialize};


#[derive(Debug, Clone, Serialize, Deserialize)]
struct Empty {}


#[get("/health")]
async fn get() -> Result<HttpResponse, CustomError> {
    Ok(HttpResponse::Ok().json({}))
}

#[get("/auth_health")]
async fn get_authenticated() -> Result<HttpResponse, CustomError> {
    Ok(HttpResponse::Ok().json(Empty{}))
}

pub fn init_routes(config: &mut web::ServiceConfig) {
    config.service(get);
    config.service(get_authenticated);
}
