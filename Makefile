version:
	rustc --version
	wasm-pack --version

build:
	$(MAKE) version

	API_BASEPATH=$(API_BASEPATH) wasm-pack build --scope pixelcities --target web
	sed -i "s|fetch(input)|fetch(input, {integrity: \"sha384-$$(cat pkg/key_x_wasm_bg.wasm | openssl dgst -sha384 -binary | openssl base64 -A)\"})|g" pkg/key_x_wasm.js
