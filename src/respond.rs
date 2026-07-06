use serde::Serialize;
use worker::{Response, Result};

pub fn json_err(status: u16, code: &str) -> Result<Response> {
    let resp = Response::from_json(&serde_json::json!({"error": code}))?;
    Ok(resp.with_status(status))
}

pub fn json_err_msg(status: u16, code: &str, message: &str) -> Result<Response> {
    let resp =
        Response::from_json(&serde_json::json!({"error": code, "message": message}))?;
    Ok(resp.with_status(status))
}

#[allow(dead_code)] // util-belt: json_err/no_content kardeşi, ileride kullanılabilir
pub fn json_status<T: Serialize>(status: u16, body: &T) -> Result<Response> {
    let resp = Response::from_json(body)?;
    Ok(resp.with_status(status))
}

pub fn no_content() -> Result<Response> {
    Ok(Response::empty()?.with_status(204))
}
