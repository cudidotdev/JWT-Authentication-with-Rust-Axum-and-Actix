use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct User {
  email: String,
}

#[derive(Serialize, Deserialize)]
struct Claims {
  email: String,
  exp: i64,
}

pub fn get_jwt(user: User) -> Result<String, String> {
  let token = encode(
    &Header::default(),
    &Claims {
      email: user.email,
      exp: (Utc::now() + Duration::minutes(1)).timestamp(),
    },
    &EncodingKey::from_secret("mykey".as_bytes()),
  )
  .map_err(|e| e.to_string());

  return token;
}

pub fn decode_jwt(token: &str) -> Result<User, String> {
  let token_data = decode::<User>(
    token,
    &DecodingKey::from_secret("mykey".as_bytes()),
    &Validation::default(),
  );

  match token_data {
    Ok(token_data) => Ok(token_data.claims),

    Err(e) => Err(e.to_string()),
  }
}
