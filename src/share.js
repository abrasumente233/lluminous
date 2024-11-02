export function generateUrlSafePassword(length = 32) {
	// URL-safe characters: a-z, A-Z, 0-9, -, _
	const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_';
	const array = new Uint8Array(length);
	window.crypto.getRandomValues(array);

	let password = '';
	for (let i = 0; i < length; i++) {
		// Use modulo to map the random bytes to our charset
		password += charset[array[i] % charset.length];
	}

	return password;
}

async function getKeyMaterial(password) {
	const enc = new TextEncoder();
	return window.crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, [
		'deriveBits',
		'deriveKey',
	]);
}

async function deriveKey(password, salt) {
	const keyMaterial = await getKeyMaterial(password);
	return window.crypto.subtle.deriveKey(
		{
			name: 'PBKDF2',
			salt: salt,
			iterations: 1000000,
			hash: 'SHA-256',
		},
		keyMaterial,
		{ name: 'AES-GCM', length: 256 },
		true,
		['encrypt', 'decrypt']
	);
}

function arrayBufferToBase64(buffer) {
	return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

function base64ToArrayBuffer(base64) {
	const binaryString = atob(base64);
	const bytes = new Uint8Array(binaryString.length);
	for (let i = 0; i < binaryString.length; i++) {
		bytes[i] = binaryString.charCodeAt(i);
	}
	return bytes.buffer;
}

async function encrypt(plaintext, password) {
	const salt = window.crypto.getRandomValues(new Uint8Array(16));
	const iv = window.crypto.getRandomValues(new Uint8Array(12));
	const key = await deriveKey(password, salt);
	return {
		salt: arrayBufferToBase64(salt),
		iv: arrayBufferToBase64(iv),
		ciphertext: arrayBufferToBase64(
			await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext)
		),
	};
}

async function decrypt(cipherobj, password) {
	const salt = base64ToArrayBuffer(cipherobj.salt);
	const iv = base64ToArrayBuffer(cipherobj.iv);
	const ciphertextBuffer = base64ToArrayBuffer(cipherobj.ciphertext);
	const key = await deriveKey(password, salt);
	return new Uint8Array(
		await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertextBuffer)
	);
}

export async function compressAndEncode(data, password) {
	const plaintext = JSON.stringify(data);
	const encoder = new TextEncoder();
	const plaintextUint8Array = encoder.encode(plaintext);

	const cipher = await encrypt(plaintextUint8Array, password);
	const cipherString = JSON.stringify(cipher);
	const cipherUint8Array = encoder.encode(cipherString);

	const compressedStream = new CompressionStream('gzip');
	const compressed = new Blob([cipherUint8Array]).stream().pipeThrough(compressedStream);
	const compressedArrayBuffer = await new Response(compressed).arrayBuffer();
	const compressedUint8Array = new Uint8Array(compressedArrayBuffer);
	let base64 = btoa(String.fromCharCode(...compressedUint8Array));
	// Make base64 URL-safe:
	base64 = base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
	return base64;
}

export async function decodeAndDecompress(encoded, password) {
	// Reverse the URL-safe transformations:
	encoded = encoded.replace(/-/g, '+').replace(/_/g, '/');
	const binaryString = atob(encoded);
	const len = binaryString.length;
	const uint8Array = new Uint8Array(new ArrayBuffer(len));
	for (let i = 0; i < len; i++) {
		uint8Array[i] = binaryString.charCodeAt(i);
	}

	const decompressedStream = new DecompressionStream('gzip');
	const decompressedBlob = new Blob([uint8Array]).stream().pipeThrough(decompressedStream);
	const decompressedArrayBuffer = await new Response(decompressedBlob).arrayBuffer();
	const decoder = new TextDecoder();
	const cipherString = decoder.decode(decompressedArrayBuffer);

	// Decrypt the decompressed data
	const cipherobj = JSON.parse(cipherString);
	const decrypted = await decrypt(cipherobj, password);

	// Convert the decrypted Uint8Array back to the original object
	return JSON.parse(decoder.decode(decrypted));
}
