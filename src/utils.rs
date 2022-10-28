use wasm_bindgen::prelude::*;

use wasm_bindgen::JsCast;
use wasm_bindgen_futures::*;
use web_sys::{Request, RequestInit, RequestCredentials, RequestMode, Response, HtmlDocument};

fn document() -> HtmlDocument {
    web_sys::window().unwrap().document().unwrap().dyn_into::<HtmlDocument>().unwrap()
}

pub fn get_cookie(name: &str) -> String {
    let cookies = document().cookie().unwrap();
    let value = cookies
        .split(';')
        .find_map(|kv|
            if kv.starts_with(name) {
                let parts = kv.split("=").collect::<Vec<&str>>();
                if parts.len() > 1 {
                    Some(parts[1].to_owned())
                } else {
                    None
                }
            } else {
                None
            }
        );

    match value {
        Some(v) => v,
        None => "".to_owned()
    }
}

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

    if method != "GET" {
        headers.set("X-CSRF-Token", get_cookie("_mycelium_csrf_token").as_str()).unwrap();
    }

    let window = web_sys::window().unwrap();
    let resp_value = JsFuture::from(window.fetch_with_request(&request)).await.unwrap();

    let resp: Response = resp_value.dyn_into().unwrap();
    let json = JsFuture::from(resp.json().unwrap()).await.unwrap();

    json
}
