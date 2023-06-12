"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.decrypt = exports.encrypt = exports.verify = exports.sign = exports.generateKeyPair = void 0;
const node_crypto_1 = __importStar(require("node:crypto"));
const generateKeyPair = async () => new Promise((resolve, reject) => {
    (0, node_crypto_1.generateKeyPair)('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
            type: 'pkcs1',
            format: 'pem',
        },
        privateKeyEncoding: {
            type: 'pkcs1',
            format: 'pem',
        },
    }, (err, publicKey, privateKey) => {
        if (err) {
            reject(err);
        }
        resolve({ publicKey, privateKey });
    });
});
exports.generateKeyPair = generateKeyPair;
// NOTE: If used client side, provavly should
// extract the verify function to its own
// package
/**
 * Signs the payload and returns it bundled with
 * the signature in base64 encoding.
 * Expects a RSA key as the publicKey.
 * Supports strings or objects as payload.
 * NOTE: If payload is also encrypted you
 * should not use the same key pair to encrypt
 * and sign
 */
const sign = (payload, privateKey) => {
    let type;
    let payloadBuffer;
    if (typeof payload === 'object') {
        type = Buffer.from('j');
        payloadBuffer = Buffer.from(JSON.stringify(payload));
    }
    else {
        type = Buffer.from('s');
        payloadBuffer = Buffer.from(payload);
    }
    const signature = (0, node_crypto_1.sign)('RSA-SHA256', payloadBuffer, {
        key: privateKey,
        padding: node_crypto_1.constants.RSA_PKCS1_PSS_PADDING,
    });
    return Buffer.concat([signature, payloadBuffer, type]).toString('base64');
};
exports.sign = sign;
/**
 * Verifies a payload previously signed with the sign() function.
 * Will return either a string or an object if the payload signed was
 * an object.
 */
const verify = (payload, publicKey) => {
    const payloadBuffer = Buffer.from(payload, 'base64');
    const type = payloadBuffer.subarray(payloadBuffer.length - 1).toString('utf8');
    const signature = payloadBuffer.subarray(0, 256);
    const data = payloadBuffer.subarray(256, payloadBuffer.length - 1);
    if (!(0, node_crypto_1.verify)('RSA-SHA256', data, {
        key: publicKey,
        padding: node_crypto_1.constants.RSA_PKCS1_PSS_PADDING,
    }, signature)) {
        throw new Error('Verify failed');
    }
    if (type === 'j') {
        try {
            return JSON.parse(data.toString('utf8'));
        }
        catch (error) {
            throw new Error('Error decoding signed data');
        }
    }
    return data.toString('utf8');
};
exports.verify = verify;
/**
 * Encrypts a string with hybrid encryption.
 * Expects a RSA key as the publicKey
 */
const encrypt = (payload, publicKey) => {
    const key = (0, node_crypto_1.randomBytes)(32);
    const nonce = (0, node_crypto_1.randomBytes)(16);
    const cipher = (0, node_crypto_1.createCipheriv)('chacha20', key, nonce);
    const encryptedPayload = Buffer.concat([
        cipher.update(payload, 'utf8'),
        cipher.final(),
    ]);
    // console.log({ key, nonce })
    const encryptedKey = (0, node_crypto_1.publicEncrypt)(publicKey, Buffer.concat([key, nonce]));
    return encodeEncryptedKeyAndPayload(encryptedKey, encryptedPayload);
};
exports.encrypt = encrypt;
/**
 * Decrypts a cipher string generated by the encrypt method.
 * Expects the matching RSA private key.
 */
const decrypt = (payload, privateKey) => {
    const { encryptedKey, encryptedPayload } = decodeEncryptedKeyAndPayload(payload);
    let keyAndNonce;
    try {
        keyAndNonce = (0, node_crypto_1.privateDecrypt)(privateKey, encryptedKey);
    }
    catch (error) {
        throw new Error('Decrypt failed');
    }
    const key = keyAndNonce.subarray(0, 32);
    const nonce = keyAndNonce.subarray(32);
    // console.log({ key, nonce })
    const decipher = node_crypto_1.default.createDecipheriv('chacha20', key, nonce);
    let decryptedData = decipher.update(encryptedPayload, null, 'utf8');
    decryptedData += decipher.final('utf8');
    return decryptedData;
};
exports.decrypt = decrypt;
const encodeEncryptedKeyAndPayload = (encryptedKey, encryptedPayload) => {
    return Buffer.concat([encryptedKey, encryptedPayload]).toString('base64');
};
const decodeEncryptedKeyAndPayload = (payload) => {
    const payloadBuffer = Buffer.from(payload, 'base64');
    const encryptedKey = payloadBuffer.subarray(0, 256);
    const encryptedPayload = payloadBuffer.subarray(256);
    return { encryptedKey, encryptedPayload };
};
//# sourceMappingURL=index.js.map