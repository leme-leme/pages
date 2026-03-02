/**
 * Utility functions to encrypt and decrypt text using AES-GCM. Used to secure
 * info in the DB (e.g. GitHub tokens).
 * 
 * Requires a CRYPTO_KEY environment variable to be set.
 * Accepts base64 (32 bytes), hex (64 chars), or any string (will be hashed to 256 bits).
 */

const deriveKey = async (input: string): Promise<CryptoKey> => {
  let rawKey: Uint8Array;

  // Try base64 first (44 chars ending in = for 32 bytes)
  if (/^[A-Za-z0-9+/]{42,44}={0,2}$/.test(input)) {
    try {
      rawKey = Uint8Array.from(atob(input), c => c.charCodeAt(0));
      if (rawKey.length === 32) {
        return crypto.subtle.importKey('raw', rawKey, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
      }
    } catch {}
  }

  // Try hex (64 hex chars = 32 bytes)
  if (/^[0-9a-fA-F]{64}$/.test(input)) {
    rawKey = new Uint8Array(32);
    for (let i = 0; i < 64; i += 2) {
      rawKey[i / 2] = parseInt(input.slice(i, i + 2), 16);
    }
    return crypto.subtle.importKey('raw', rawKey, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  }

  // Fallback: SHA-256 hash of the input string to get 32 bytes
  const encoded = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest('SHA-256', encoded);
  return crypto.subtle.importKey('raw', hash, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
};

const encrypt = async (text: string) => {
  if (process.env.CRYPTO_KEY === undefined) throw new Error('Crypto key is not set.');
  const key = await deriveKey(process.env.CRYPTO_KEY);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encodedText = new TextEncoder().encode(text);

  const encryptedData = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    encodedText
  );

  return {
    ciphertext: btoa(String.fromCharCode(...Array.from(new Uint8Array(encryptedData)))),
    iv: btoa(String.fromCharCode(...Array.from(iv)))
  };
};

const decrypt = async (ciphertext: string, iv: string) => {
  if (process.env.CRYPTO_KEY === undefined) throw new Error('Crypto key is not set.');
  const key = await deriveKey(process.env.CRYPTO_KEY);
  const ivArray = Uint8Array.from(atob(iv), c => c.charCodeAt(0));
  const encryptedDataArray = Uint8Array.from(atob(ciphertext), c => c.charCodeAt(0));

  const decryptedData = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: ivArray },
    key,
    encryptedDataArray
  );

  return new TextDecoder().decode(decryptedData);
};

export { encrypt, decrypt };
