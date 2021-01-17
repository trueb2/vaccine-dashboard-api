use actix_web::{dev::ServiceRequest, Error};
use actix_web_httpauth::extractors::{
    bearer::{BearerAuth, Config},
    AuthenticationError,
};
use http::Method;
use std::convert::TryInto;

use super::users;

pub fn init() {
    users::init();

    // Bootstrap auth with an admin user if necessary
    let num_users = users::User::count().unwrap();
    if num_users == 0 {
        log::warn!("Bootstrapping auth by creating admin:admin user");
        log::warn!("Remember to update the username and password of admin:admin user");
        let user = users::User::create(users::MaybeUser {
            username: String::from("admin"),
            password: String::from("admin"),
        })
        .unwrap();
        let auth_user: users::AuthUser = user.try_into().unwrap();
        log::warn!(
            "The initial token for admin:admin with id {} is 'Bearer {}'",
            auth_user.id,
            auth_user.token
        );
    }
}

pub async fn validator(
    req: ServiceRequest,
    credentials: BearerAuth,
) -> Result<ServiceRequest, Error> {
    match credentials.token() {
        "_" => {
            if req.path() == "/health" || 
                (req.path() == "/login" && req.method() == Method::POST) ||
                (req.path() == "/create-user" && req.method() == Method::POST) {
                Ok(req)
            } else {
                let config = req
                    .app_data::<Config>()
                    .map(|data| data.clone())
                    .unwrap_or_else(Default::default);

                Err(AuthenticationError::from(config).into())
            }
        }
        token => match users::User::find_by_token(String::from(token)) {
            Ok(record) => {
                log::trace!("Allowing user: {:?}", record);
                Ok(req)
            }
            Err(_) => {
                let config = req
                    .app_data::<Config>()
                    .map(|data| data.clone())
                    .unwrap_or_else(Default::default);

                Err(AuthenticationError::from(config).into())
            }
        },
    }
}
