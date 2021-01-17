use crate::error_handler::CustomError;
use crate::users::User;
use actix_web::{HttpResponse, delete, get, post, web};
use super::{District, InsertableDistrict};
use serde::{Deserialize};


#[get("/districts/id/{id}")]
async fn get_by_id(id: web::Path<i64>) -> Result<HttpResponse, CustomError> {
    let district = District::find_by_id(id.into_inner())?;
    Ok(HttpResponse::Ok().json(district))
}

#[get("/districts/slug/{slug}")]
async fn get_by_slug(slug: web::Path<String>) -> Result<HttpResponse, CustomError> {
    let district = District::find_by_slug(slug.into_inner())?;
    Ok(HttpResponse::Ok().json(district))
}

#[get("/districts/summary")]
async fn get_summary() -> Result<HttpResponse, CustomError> {
    let district = District::get_summary()?;
    Ok(HttpResponse::Ok().json(district))
}

#[derive(Deserialize)]
struct DistrictQuery {
    sorted: Option<bool>,
}

#[get("/districts")]
async fn get_all(district_query: web::Query<DistrictQuery>) -> Result<HttpResponse, CustomError> {
    let districts = District::find(district_query.into_inner().sorted.unwrap_or_default())?;
    Ok(HttpResponse::Ok().json(districts))
}

#[derive(Debug, Deserialize)]
struct IncrementQuery {
    id: i64,
    vaccinated: Option<bool>,
    unvaccinated: Option<bool>,
    interested: Option<bool>,
}

#[post("/districts/increment")]
async fn increment(increment_query: web::Query<IncrementQuery>) -> Result<HttpResponse, CustomError> {
    let query = increment_query.into_inner();
    log::trace!("Incrementing stats with {:?}", query);
    let district = District::increment(
        query.id,
        query.vaccinated.unwrap_or_default(),
        query.unvaccinated.unwrap_or_default(),
        query.interested.unwrap_or_default())?;
    Ok(HttpResponse::Ok().json(district))
}


#[post("/districts")]
async fn create(user: User, district: web::Json<InsertableDistrict>) -> Result<HttpResponse, CustomError> {
    if user.username != "admin" {
        return Err(CustomError::new(401, String::from("Unauthorized")))
    }
    let district = District::create(district.into_inner())?;
    Ok(HttpResponse::Ok().json(district))
}

#[delete("/districts/{id}")]
async fn delete(user: User, id: web::Path<i64>) -> Result<HttpResponse, CustomError> {
    if user.username != "admin" {
        return Err(CustomError::new(401, String::from("Unauthorized")))
    }
    let district = District::delete(id.into_inner())?;
    Ok(HttpResponse::Ok().json(district))
}


pub fn init_routes(config: &mut web::ServiceConfig) {
    config.service(get_by_id);
    config.service(get_by_slug);
    config.service(get_all);
    config.service(get_summary);
    config.service(increment);
    config.service(create);
    config.service(delete);
}
