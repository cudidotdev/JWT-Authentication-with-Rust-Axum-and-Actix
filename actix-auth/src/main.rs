use std::future::{ready, Ready};

use actix_web::{
  dev::Payload,
  error::InternalError,
  http::header,
  web::{get, post, Json},
  App, FromRequest, HttpRequest, HttpResponse, HttpServer,
};
use jwt_lib::User;
use serde_json::json;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
  HttpServer::new(move || {
    App::new()
      .route("/public-view", get().to(public_view_handler))
      .route("/get-token", post().to(get_token_handler))
      .route("/secret-view", get().to(secret_view_handler))
  })
  .workers(4)
  .bind("127.0.0.1:2424")
  .expect("Address should be free and valid")
  .run()
  .await
}

async fn public_view_handler() -> HttpResponse {
  HttpResponse::Ok().json(json!({
    "success": true,
    "data": {
      "message": "This data is visible to all users"
    }
  }))
}

async fn get_token_handler(Json(user): Json<User>) -> HttpResponse {
  let token = jwt_lib::get_jwt(user);

  match token {
    Ok(token) => HttpResponse::Ok().json(json!({
      "success": true,
      "data": {
        "token": token
      }
    })),

    Err(error) => HttpResponse::BadRequest().json(json!({
      "success": false,
      "data": {
        "message": error
      }
    })),
  }
}

async fn secret_view_handler(Auth(user): Auth) -> HttpResponse {
  HttpResponse::Ok().json(json!({
    "success": true,
    "data": user
  }))
}

struct Auth(User);

impl FromRequest for Auth {
  type Error = InternalError<String>;

  type Future = Ready<Result<Self, Self::Error>>;

  fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
    let access_token = req
      .headers()
      .get(header::AUTHORIZATION)
      .and_then(|value| value.to_str().ok())
      .and_then(|str| str.split(" ").nth(1));

    match access_token {
      Some(token) => {
        let user = jwt_lib::decode_jwt(token);

        match user {
          Ok(user) => ready(Ok(Auth(user))),

          Err(e) => ready(Err(InternalError::from_response(
            e.clone(),
            HttpResponse::Unauthorized().json(json!({
              "success": false,
              "data": {
                "message": e
              }
            })),
          ))),
        }
      }

      None => ready(Err(InternalError::from_response(
        String::from("No token provided"),
        HttpResponse::Unauthorized().json(json!({
          "success": false,
          "data": {
            "message": "No token provided"
          }
        })),
      ))),
    }
  }
}
