use wasm_bindgen::prelude::*;

use wasm_bindgen::JsCast;
use wasm_bindgen_futures::*;
use web_sys::{Request, RequestInit, RequestCredentials, RequestMode, Response};

pub async fn request(method: String, url: String, payload: Option<String>) -> JsValue {
    let mut opts = RequestInit::new();

    opts.method(&method);
    opts.mode(RequestMode::Cors);
    opts.credentials(RequestCredentials::Include);

    if payload.is_some() {
        opts.body(Some(&payload.unwrap().into()));
    }

    let request = Request::new_with_str_and_init(&url, &opts).unwrap();

    let headers = request.headers();
    headers.set("Content-Type", "application/json").unwrap();
    headers.set("Accept", "application/json").unwrap();

    let window = web_sys::window().unwrap();
    let resp_value = JsFuture::from(window.fetch_with_request(&request)).await.unwrap();

    let resp: Response = resp_value.dyn_into().unwrap();
    let json = JsFuture::from(resp.json().unwrap()).await.unwrap();

    json
}
