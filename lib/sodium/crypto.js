/*!
 * Tozny e3db
 *
 * LICENSE
 *
 * Tozny dual licenses this product. For commercial use, please contact
 * info@tozny.com. For non-commercial use, the contents of this file are
 * subject to the TOZNY NON-COMMERCIAL LICENSE (the "License") which
 * permits use of the software only by government agencies, schools,
 * universities, non-profit organizations or individuals on projects that
 * do not receive external funding other than government research grants
 * and contracts.  Any other use requires a commercial license. You may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at https://tozny.com/legal/non-commercial-license.
 * Software distributed under the License is distributed on an "AS IS"
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
 * License for the specific language governing rights and limitations under
 * the License. Portions of the software are Copyright (c) TOZNY LLC, 2017.
 * All rights reserved.
 *
 * @copyright Copyright (c) 2017 Tozny, LLC (https://tozny.com)
 */

'use strict'

import crypto from 'crypto'
import fs from 'fs'
import aw from 'awaitify-stream'
import sodium from 'libsodium-wrappers'
import { Crypto as CryptoBase, types } from 'e3db-client-interface'
import base64url from 'base64url'
import md5 from 'js-md5'
import uuidv4 from 'uuid/v4'
import {
  DEFAULT_KDF_ITERATIONS,
  FILE_VERSION,
  FILE_BLOCK_SIZE as BLOCK_SIZE
} from '../utils/constants'

export default class Crypto extends CryptoBase {
  /**
   * Mode returns a string denoting which crypto library this implementation uses under the hood.
   */
  mode() {
    return 'Sodium'
  }

  /**
   * Gets the signature version currently supported by this crypto object.
   *
   * @return {string} The current signature version in UUID-v5 format.
   */
  get signatureVersion() {
    // UUIDv5 TFSP1;ED25519;BLAKE2B
    return 'e7737e7c-1637-511e-8bab-93c4f3e26fd9'
  }

  /**
   * Symmetrically encrypt and serialize a string with the given key
   *
   * @param {string} plain The plain text string to encrypt
   * @param {string} key   Base64 encoded key used to encrypt the string.
   *
   * @return {Promise<string>} The encrypted string base64URL encoded with a serialized nonce.
   */
  async encryptString(plain, key) {
    await sodium.ready
    const rawKey = await this.b64decode(key)
    const nonce = await this.randomNonce()
    const encrypted = sodium.crypto_secretbox_easy(plain, nonce, rawKey)
    return Promise.all([nonce, encrypted].map(async x => this.b64encode(x))).then(x =>
      x.join(':')
    )
  }

  /**
   * Decrypt a symmetrically encrypted string
   *
   * @param {string} encrypted Base64 encoded string in nonce:cipherText format.
   * @param {string} key       Base64 encoded key used to encrypt the string.
   *
   * @return {Promise<string>} The decrypted UTF-8 string.
   */
  async decryptString(encrypted, key) {
    await sodium.ready
    const rawKey = await this.b64decode(key)
    const components = encrypted.split(':')
    const [nonce, cipher] = await Promise.all(
      components.map(async x => this.b64decode(x))
    )
    const decrypted = sodium.crypto_secretbox_open_easy(cipher, nonce, rawKey)

    return Buffer.from(decrypted).toString('utf8')
  }

  /**
   * Encrypt a string into the standard Tozny quad format using Libsodium's secretbox.
   *
   * @param {string} field The string of data to encrypt as a data field.
   * @param {Uint8Array} accessKey The access key bytes to encrypt the field with.
   *
   * @returns {Promise<String>} The Tozny dotted quad encrypted field.
   */
  async encryptField(field, accessKey) {
    const dk = await this.randomKey()
    const efN = await this.randomNonce()
    const ef = sodium.crypto_secretbox_easy(field, efN, dk)
    const edkN = await this.randomNonce()
    const edk = sodium.crypto_secretbox_easy(dk, edkN, accessKey)
    const encryptedField = [
      await this.b64encode(edk),
      await this.b64encode(edkN),
      await this.b64encode(ef),
      await this.b64encode(efN)
    ].join('.')

    return encryptedField
  }

  /**
   * Decrypt a standard Tozny dotted quad using Libsodium's secretbox into a string.
   *
   * @param {string}     encryptedField A standard Tozny dotted quad string.
   * @param {Uint8Array} accessKey      The access key bytes to use as the decryption key.
   *
   * @return {Promise<string>} The decrypted data field as a UTF-8 string.
   */
  async decryptField(encryptedField, accessKey) {
    const components = encryptedField.split('.')
    const [edk, edkN, ef, efN] = await Promise.all(
      components.map(async x => this.b64decode(x))
    )

    const dk = sodium.crypto_secretbox_open_easy(edk, edkN, accessKey)
    const field = sodium.crypto_secretbox_open_easy(ef, efN, dk)

    return Buffer.from(field).toString('utf8')
  }

  /**
   * Sign a key value pair for use in a data object with optional object nonce.
   *
   * @param {string} key The object key which will be used for this field.
   * @param {string} value The plain text string value of the field.
   * @param {string} signingKey A base64url encoded private signing key
   * @param {string} objectSalt A determined UUID to sign the field with. If not supplied a random one is generated.
   *
   * @return {string} field prefixed with the field signature header and signature.
   */
  async signField(key, value, signingKey, objectSalt) {
    await sodium.ready
    const salt = objectSalt || uuidv4()
    const message = await this.genericHash(`${salt}${key}${value}`)
    const rawKey = await this.b64decode(signingKey)
    const rawSignature = sodium.crypto_sign_detached(message, rawKey)
    const signature = await this.b64encode(rawSignature)
    const length = signature.length
    const prefix = [this.signatureVersion, salt, length, signature].join(';')
    return `${prefix}${value}`
  }

  /**
   * Verify the key, value, and optionally salt in a field signature.
   *
   * @param {string} key The Key associated with the field.
   * @param {string} value The fully signed string to validate.
   * @param {string} verifyingKey A base64url endcoded public signing key
   * @param {string} objectSalt A UUID verified as the salt used in the signature.
   *                            If not sent, the salt contained in the value is used instead.
   *
   * @return {Promise<string>} The field plain text if validated. Throws if validation fails.
   */
  async verifyField(key, value, verifyingKey, objectSalt) {
    await sodium.ready
    const parts = value.split(';', 3)
    // If this field is not prefixed with the signature version, assume it is
    // not a signed field.
    if (parts[0] !== this.signatureVersion) {
      return value
    }
    // If a salt was sent, validate the included salt matches
    if (objectSalt && parts[1] !== objectSalt) {
      throw new Error(`Invalid salt on field signature for ${key}`)
    }
    // Header is each part, plus the three semicolons
    const headerLength = parts.reduce((acc, part) => acc + part.length, 3)
    const signatureLength = parseInt(parts[2], 10)
    const signatureIndex = headerLength
    const plainTextIndex = headerLength + signatureLength
    const signature = value.substring(signatureIndex, plainTextIndex)
    const plainText = value.substring(plainTextIndex)
    const message = await this.genericHash(`${parts[1]}${key}${plainText}`)
    const rawSignature = await this.b64decode(signature)
    const rawKey = await this.b64decode(verifyingKey)

    const valid = await sodium.crypto_sign_verify_detached(rawSignature, message, rawKey)
    if (!valid) {
      throw new Error(`Invalid field signature for "${key}"`)
    }

    return plainText
  }

  /**
   * Decrypt the access key provided for a specific reader so it can be used
   * to further decrypt a protected record.
   *
   * @param {string} readerKey   Base64url-encoded private key for the reader (current client)
   * @param {EAKInfo} encryptedAk Encrypted access key
   *
   * @return {Promise<string>} Raw binary string of the access key
   */
  async decryptEak(readerKey, encryptedAk) {
    await sodium.ready
    let encodedEak = encryptedAk.eak
    let publicKey = await this.b64decode(encryptedAk.authorizerPublicKey.curve25519)
    let privateKey = await this.b64decode(readerKey)

    let [eak, nonce] = await Promise.all(
      encodedEak.split('.').map(async x => this.b64decode(x))
    )
    return sodium.crypto_box_open_easy(eak, nonce, publicKey, privateKey)
  }

  async decryptNoteEak(readerKey, encryptedAk, writerKey) {
    await sodium.ready
    let encodedEak = encryptedAk.eak
    let publicKey = await this.b64decode(writerKey)
    let privateKey = await this.b64decode(readerKey)

    let [eak, nonce] = await Promise.all(
      encodedEak.split('.').map(async x => this.b64decode(x))
    )
    return sodium.crypto_box_open_easy(eak, nonce, publicKey, privateKey)
  }

  /**
   * Encrypt an access key for a given reader.
   *
   * @param {string} writerKey Base64url-encoded private key of the writer
   * @param {string} ak        Raw binary string of the access key
   * @param {string} readerKey Base64url-encoded public key of the reader
   *
   * @return {Promise<string>} Encrypted and encoded access key.
   */
  async encryptAk(writerKey, ak, readerKey) {
    await sodium.ready
    let publicKey = await this.b64decode(readerKey)
    let privateKey = await this.b64decode(writerKey)

    let nonce = await this.randomNonce()
    let eak = sodium.crypto_box_easy(ak, nonce, publicKey, privateKey)

    return (await this.b64encode(eak)) + '.' + (await this.b64encode(nonce))
  }

  /**
   * Create a clone of a given record, but decrypting each field in turn based on
   * the provided access key.
   *
   * @param {Record} encrypted Record to be unwrapped
   * @param {string} accessKey Access key to use for decrypting each data key.
   *
   * @return {Promise<Record>}
   */
  async decryptRecord(encrypted, accessKey) {
    await sodium.ready
    // Clone the record meta
    let meta = new types.Meta(
      encrypted.meta.writerId,
      encrypted.meta.userId,
      encrypted.meta.type,
      encrypted.meta.plain
    )
    meta.recordId = encrypted.meta.recordId
    meta.created = encrypted.meta.created
    meta.lastModified = encrypted.meta.lastModified
    meta.version = encrypted.meta.version
    let decrypted = new types.Record(meta, {}, encrypted.signature)

    // Decrypt the record data
    for (let key in encrypted.data) {
      if (encrypted.data.hasOwnProperty(key)) {
        decrypted.data[key] = await this.decryptField(encrypted.data[key], accessKey)
      }
    }

    return decrypted
  }

  /**
   * Create a clone of a plaintext record, encrypting each field in turn with a random
   * data key and protecting the data key with a set access key.
   *
   * @param {Record} record    Record to be encrypted.
   * @param {string} accessKey Access key to use for decrypting each data key.
   *
   * @return {Promise<Record>}
   */
  async encryptRecord(record, accessKey) {
    await sodium.ready
    // Clone the record meta
    let meta = new types.Meta(
      record.meta.writerId,
      record.meta.userId,
      record.meta.type,
      record.meta.plain
    )
    let encrypted = new types.Record(meta, {}, record.signature)

    // Encrypt the record data
    for (let key in record.data) {
      if (record.data.hasOwnProperty(key)) {
        encrypted.data[key] = await this.encryptField(record.data[key], accessKey)
      }
    }

    return encrypted
  }

  /**
   * Verify the signature on a given JSON document, given a specific public signing key.
   *
   * @param {Serializable} document     Document to be verified
   * @param {string}       signature    Base64URL-encoded signature
   * @param {string}       verifyingKey Base64URL-encoded signing key
   *
   * @returns {Promise<bool>}
   */
  async verifyDocumentSignature(document, signature, verifyingKey) {
    await sodium.ready
    let message = document.stringify()
    let rawSignature = await this.b64decode(signature)
    let rawKey = await this.b64decode(verifyingKey)

    return sodium.crypto_sign_verify_detached(rawSignature, message, rawKey)
  }

  /**
   * Sign a document and return the signature
   *
   * @param {Signable} document   Serializable object to be signed
   * @param {string}   signingKey Key to use to sign the document
   *
   * @returns {Promise<string>}
   */
  async signDocument(document, signingKey) {
    await sodium.ready
    let message = document.stringify()
    let rawKey = await this.b64decode(signingKey)

    let signature = sodium.crypto_sign_detached(message, rawKey)
    return this.b64encode(signature)
  }

  /**
   * Base64 encode a string in a URL safe manner with no padding
   *
   * @param {string} raw Raw data to be encoded
   *
   * @returns {string}
   */
  async b64encode(raw) {
    return base64url(raw)
  }

  /**
   * Decode a Base64URL-encoded string
   *
   * @param {string} encoded Base64URL-encoded string
   *
   * @returns {string}
   */
  async b64decode(encoded) {
    const b64Dec = base64url.toBuffer(encoded)
    const u8 = new Uint8Array(b64Dec.length)
    for (let i = 0; i < b64Dec.length; i++) {
      u8[i] = b64Dec[i]
    }
    return u8
  }

  /**
   * Generate a random key for use with Libsodium's secretbox interface
   *
   * @returns {Uint8Array} An array of random bytes the default key length
   */
  async randomKey() {
    await sodium.ready
    return sodium.crypto_secretbox_keygen()
  }

  /**
   * Generate a random nonce for use with Libsodium's secretbox interface
   *
   * @returns {Uint8Array} An array of random bytes the default nonce length
   */
  async randomNonce() {
    return this.randomBytes(sodium.crypto_secretbox_NONCEBYTES)
  }

  /**
   * Generate random bytes `length` long.
   *
   * @param {number} length The number of random bytes to generate
   *
   * @returns {Uint8Array} An array of random bytes
   */
  async randomBytes(length) {
    await sodium.ready
    return sodium.randombytes_buf(length)
  }

  /**
   * Use PBKDF2 to derive a key of a given length using a specified password
   * and salt.
   *
   * @param {string} password     User-specified password
   * @param {string} salt         User-specified salt (should be random)
   * @param {number} length       Length of the key to generate
   * @param {number} [iterations] Option number of hash iterations to create the seed.
   *
   * @returns {Promise<ArrayBuffer>}
   */
  async deriveKey(password, salt, length, iterations = DEFAULT_KDF_ITERATIONS) {
    return new Promise((resolve, reject) => {
      crypto.pbkdf2(password, salt, iterations, length, 'sha512', (err, val) =>
        err ? reject(err) : resolve(val)
      )
    })
  }

  /**
   * Derive an Ed25519 keypair from a password and a random salt
   *
   * @param {string} password     User-specified password
   * @param {string} salt         User-specified salt (should be random)
   * @param {number} [iterations] Option number of hash iterations to create the seed.
   *
   * @returns {KeyPair} Object containing publicKey and privateKey fields
   */
  async deriveSigningKey(password, salt, iterations = DEFAULT_KDF_ITERATIONS) {
    await sodium.ready
    let seed = await this.deriveKey(
      password,
      salt,
      sodium.crypto_sign_SEEDBYTES,
      iterations
    )

    let keypair = sodium.crypto_sign_seed_keypair(new Uint8Array(seed))

    return new types.KeyPair(
      await this.b64encode(keypair.publicKey),
      await this.b64encode(keypair.privateKey)
    )
  }

  /**
   * Derive a Curve25519 keypair from a password and a random salt
   *
   * @param {string} password     User-specified password
   * @param {string} salt         User-specified salt (should be random)
   * @param {number} [iterations] Option number of hash iterations to create the seed.
   *
   * @returns {KeyPair} Object containing publicKey and privateKey fields
   */
  async deriveCryptoKey(password, salt, iterations = DEFAULT_KDF_ITERATIONS) {
    await sodium.ready
    let seed = await this.deriveKey(
      password,
      salt,
      sodium.crypto_sign_SEEDBYTES,
      iterations
    )

    let keypair = sodium.crypto_box_seed_keypair(new Uint8Array(seed))

    return new types.KeyPair(
      await this.b64encode(keypair.publicKey),
      await this.b64encode(keypair.privateKey)
    )
  }

  /**
   * Derive a symmetric encryption key from a password and a random salt
   *
   * @param {string} password User-specified password
   * @param {string} salt     User-specified salt (should be random)
   * @param {number} [iterations] Option number of hash iterations to create the seed.
   *
   * @returns {string} base64Url encoded string
   */
  async deriveSymmetricKey(password, salt, iterations = DEFAULT_KDF_ITERATIONS) {
    const buffer = await this.deriveKey(
      password,
      salt,
      sodium.crypto_secretbox_KEYBYTES,
      iterations
    )
    const b64String = await this.b64encode(buffer)
    return b64String
  }

  /**
   * Dynamically generate a Curve25519 keypair for use with registration and cryptographic operations
   *
   * @returns {KeyPair} Base64URL-encoded representation of the new keypair
   */
  async generateKeypair() {
    await sodium.ready
    const keypair = sodium.crypto_box_keypair()
    const kp = new types.KeyPair(
      await this.b64encode(keypair.publicKey),
      await this.b64encode(keypair.privateKey)
    )
    return kp
  }

  /**
   * Dynamically generate an Ed25519 keypair for use with registration and signing operations
   *
   * @returns {KeyPair} Base64URL-encoded representation of the new keypair
   */
  async generateSigningKeypair() {
    await sodium.ready
    const keypair = sodium.crypto_sign_keypair()

    return new types.KeyPair(
      await this.b64encode(keypair.publicKey),
      await this.b64encode(keypair.privateKey)
    )
  }

  str2ab(str) {
    var buf = new ArrayBuffer(str.length)
    var bufView = new Uint8Array(buf)
    for (var i = 0, strLen = str.length; i < strLen; i++) {
      bufView[i] = str.charCodeAt(i)
    }
    return buf
  }

  async encryptLargeFile(fileName, ak) {
    await sodium.ready

    if (!fs.existsSync(fileName)) {
      const msg = "ERROR: file '" + fileName + "' does not exist."
      throw msg
    }

    const nonces = fileName.split('.')
    const names = nonces[0].split('/')
    const title = names[names.length - 1]

    const encryptedFileName = `e2e-${title}.bin`
    fs.open(encryptedFileName, 'w', err => {
      if (err) {
        const msg = 'ERROR: cannot create new file.'
        throw msg
      }
    })

    const TAG_FINAL = sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
    const TAG_MESSAGE = sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE

    const dk = await this.randomKey()
    const edkN = await this.randomNonce()
    const edk = sodium.crypto_secretbox_easy(dk, edkN, ak)

    const header1 = FILE_VERSION
    const header2 = await this.b64encode(edk)
    const header3 = await this.b64encode(edkN)
    const header = `${header1}.${header2}.${header3}.`
    const headerAB = this.str2ab(header)
    const headerUint8 = new Uint8Array(headerAB)

    let outstream = fs.createWriteStream(encryptedFileName)
    let writer = aw.createWriter(outstream)

    let encryptedLength = 0
    let hash = md5.create()
    await writer.writeAsync(header)

    hash.update(headerUint8)
    encryptedLength += headerUint8.length

    const res = sodium.crypto_secretstream_xchacha20poly1305_init_push(dk)
    const state = res.state

    const sodiumHeader = res.header
    hash.update(sodiumHeader)
    await writer.writeAsync(sodiumHeader)

    encryptedLength += sodiumHeader.length

    let instream = fs.createReadStream(fileName)
    let reader = aw.createReader(instream)

    let chunk = 0
    while ((chunk = await reader.readAsync(BLOCK_SIZE)) !== null) {
      if (chunk !== null && chunk.length === BLOCK_SIZE) {
        let encryptedFileBlock = sodium.crypto_secretstream_xchacha20poly1305_push(
          state,
          chunk,
          null,
          TAG_MESSAGE
        )
        hash.update(encryptedFileBlock)
        await writer.writeAsync(encryptedFileBlock)
        encryptedLength += encryptedFileBlock.length
      } else if (chunk !== null) {
        let encryptedFileBlock = sodium.crypto_secretstream_xchacha20poly1305_push(
          state,
          chunk,
          null,
          TAG_FINAL
        )
        hash.update(encryptedFileBlock)
        await writer.writeAsync(encryptedFileBlock)
        encryptedLength += encryptedFileBlock.length
      }
    }
    const checkSum = hash.base64('')

    return [encryptedFileName, checkSum, encryptedLength]
  }

  async decryptFile(destFileName, ak, sourceFileName) {
    await sodium.ready

    let instreamHeader = fs.createReadStream(sourceFileName)
    let reader = aw.createReader(instreamHeader)

    const chunk = await reader.readAsync()
    const separated = chunk.toString().split('.')
    const fileVersion = 3
    const fileEdk = await this.b64decode(separated[1])
    const fileEdkN = await this.b64decode(separated[2])
    if (parseInt(fileVersion, 10) !== FILE_VERSION) {
      const msg = `File version: ${fileVersion} does not match supported version: ${FILE_VERSION}`
      throw msg
    }
    const headerLength =
      separated[0].length + separated[1].length + separated[2].length + 3

    const extraLength = sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES
    const libsodiumHeader = chunk.slice(headerLength, headerLength + extraLength)

    const totalHeaderLength = headerLength + libsodiumHeader.length

    instreamHeader.destroy()

    const dk = sodium.crypto_secretbox_open_easy(fileEdk, fileEdkN, ak)

    const stateIn = sodium.crypto_secretstream_xchacha20poly1305_init_pull(
      libsodiumHeader,
      dk
    )

    const ABYTES = sodium.crypto_secretstream_xchacha20poly1305_ABYTES

    let chunkBody = 0
    let instreamBody = fs.createReadStream(sourceFileName, { start: totalHeaderLength })
    let readBody = aw.createReader(instreamBody)
    let outstream = fs.createWriteStream(destFileName)

    while ((chunkBody = await readBody.readAsync(BLOCK_SIZE + ABYTES)) !== null) {
      if (chunkBody !== null) {
        let decryptedChunk = await sodium.crypto_secretstream_xchacha20poly1305_pull(
          stateIn,
          chunkBody
        )
        await outstream.write(decryptedChunk.message)
      }
    }

    return destFileName
  }

  /**
   * Encrypt and sign all of the data fields in a note object.
   *
   * @param {Note} note The note object that has un-encrypted data.
   * @param {Uint8Array} accessKey The raw access key to use in encryption
   * @param {string} signingKey The base64url encoded singing key used to sign each field.
   *
   * @return {Note} a new note object with all the data fields encrypted and signed.
   */
  async encryptNote(note, accessKey, signingKey) {
    await sodium.ready

    const encryptedNote = types.Note.clone(note)
    const encryptedData = {}
    const signatureSalt = uuidv4()
    const noteSignature = await this.signField('signature', signatureSalt, signingKey)
    encryptedNote.signature = noteSignature
    for (let key in note.data) {
      if (note.data.hasOwnProperty(key)) {
        const signedField = await this.signField(
          key,
          note.data[key],
          signingKey,
          signatureSalt
        )
        encryptedData[key] = await this.encryptField(signedField, accessKey)
      }
    }
    encryptedNote.data = encryptedData
    return encryptedNote
  }

  /**
   * Decrypt and validate all fields in a note object.
   *
   * @param {Note} encyrpted The note object with encrypted and signed data.
   * @param {Uint8Array} accessKey The raw access key to use in decrypting the data.
   * @param {string} verifyingKey The base64url encoded public signing key used to verify field signatures
   *
   * @return {Promise<Note>} A new note object with plain text data.
   */
  async decryptNote(encrypted, accessKey, verifyingKey) {
    await sodium.ready

    const verifiedSalt = await this.verifyField(
      'signature',
      encrypted.signature,
      verifyingKey
    )
    const signatureSalt = verifiedSalt === encrypted.signature ? undefined : verifiedSalt
    const decrypted = types.Note.clone(encrypted)
    const decryptedData = {}
    for (let key in encrypted.data) {
      if (encrypted.data.hasOwnProperty(key)) {
        const rawField = await this.decryptField(encrypted.data[key], accessKey)
        decryptedData[key] = await this.verifyField(
          key,
          rawField,
          verifyingKey,
          signatureSalt
        )
      }
    }
    decrypted.data = decryptedData
    return decrypted
  }

  /**
   * Function for tsv1 which wraps sodium's crypto_generichash function, uses BLAKE2b. https://libsodium.gitbook.io/doc/hashing/generic_hashing
   *
   * @returns {string} base64 encoded genericHash
   */
  async genericHash(message) {
    await sodium.ready
    let genericHash = sodium.crypto_generichash(sodium.crypto_generichash_BYTES, message)
    return this.b64encode(genericHash)
  }

  /**
   * Function for tsv1 which wraps sodium's crypto_sign_detached function, https://libsodium.gitbook.io/doc/public-key_cryptography/public-key_signatures.
   * Creates signature without attaching a copy of the original message.
   *
   * @returns {string} base64 encoded signature
   */
  async signDetached(stringToSign, privateKey) {
    await sodium.ready
    let rawKey = await this.b64decode(privateKey)
    let rawString = await this.b64decode(stringToSign)
    let signature = sodium.crypto_sign_detached(rawString, rawKey)
    return this.b64encode(signature)
  }
}
