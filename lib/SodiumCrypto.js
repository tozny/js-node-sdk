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

// console.log("sodiumcrypto.js")

'use strict'

import 'es6-promise/auto'
import crypto from 'crypto'
import sodium from 'libsodium-wrappers'
import { default as ClientInterface, types } from 'e3db-client-interface'
// Import crypto from 'e3db-client-interface'
import base64url from 'base64url'
// Import md5 from 'md5'
// import { fstat } from 'fs'
// import { file } from '@babel/types'

const KeyPair = types.KeyPair
const Meta = types.Meta
const Record = types.Record
const { Crypto } = ClientInterface
const fs = require('fs')
const FILE_VERSION = 3
const BLOCK_SIZE = 65536
// Const BLOCK_SIZE = 13
// const readline = require('readline')
// const stream = require('stream')

// Console.log("sodiumcrypto.js too")

// Import { default as Crypto } from './Crypto'
// import { default as KeyPair } from './types/keyPair'
// import { default as Meta } from './types/meta'
// import { default as Record } from './types/record'

export default class SodiumCrypto extends Crypto {
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
    // Console.log("decryptEak")
    // console.log("read", readerKey)
    // console.log("eak", encryptedAk)
    await sodium.ready
    let encodedEak = encryptedAk.eak
    let publicKey = await this.b64decode(encryptedAk.authorizerPublicKey.curve25519)
    let privateKey = await this.b64decode(readerKey)

    let [eak, nonce] = await Promise.all(
      encodedEak.split('.').map(async x => this.b64decode(x))
    )
    // Console.log("eak", eak)
    // console.log("nonce", nonce)
    // console.log("leaving decrypt eak")
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
    // Console.log("encrypt eak")
    await sodium.ready
    let publicKey = await this.b64decode(readerKey)
    let privateKey = await this.b64decode(writerKey)

    let nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES)
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
    // Console.log("decrypt record")
    await sodium.ready
    // Clone the record meta
    let meta = new Meta(
      encrypted.meta.writerId,
      encrypted.meta.userId,
      encrypted.meta.type,
      encrypted.meta.plain
    )
    meta.recordId = encrypted.meta.recordId
    meta.created = encrypted.meta.created
    meta.lastModified = encrypted.meta.lastModified
    meta.version = encrypted.meta.version
    let decrypted = new Record(meta, {}, encrypted.signature)

    // Decrypt the record data
    for (let key in encrypted.data) {
      if (encrypted.data.hasOwnProperty(key)) {
        let components = encrypted.data[key].split('.')
        let [edk, edkN, ef, efN] = await Promise.all(
          components.map(async x => this.b64decode(x))
        )

        let dk = sodium.crypto_secretbox_open_easy(edk, edkN, accessKey)
        let field = sodium.crypto_secretbox_open_easy(ef, efN, dk)

        decrypted.data[key] = Buffer.from(field).toString('utf8')
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
    // Console.log("encrypt record")
    await sodium.ready
    // Clone the record meta
    let meta = new Meta(
      record.meta.writerId,
      record.meta.userId,
      record.meta.type,
      record.meta.plain
    )
    let encrypted = new Record(meta, {}, record.signature)

    // Encrypt the record data
    for (let key in record.data) {
      if (record.data.hasOwnProperty(key)) {
        let field = record.data[key]

        let dk = sodium.crypto_secretbox_keygen()
        let efN = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES)
        let ef = sodium.crypto_secretbox_easy(field, efN, dk)
        let edkN = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES)
        let edk = sodium.crypto_secretbox_easy(dk, edkN, accessKey)

        encrypted.data[key] = [
          await this.b64encode(edk),
          await this.b64encode(edkN),
          await this.b64encode(ef),
          await this.b64encode(efN)
        ].join('.')
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
    // Console.log("verify document signature")
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
    // Console.log("sign document")
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
    // Console.log("b64encode")
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
    // Console.log("b64decode")
    // console.log("encoded", encoded)
    const b64Dec = base64url.toBuffer(encoded)
    const u8 = new Uint8Array(b64Dec.length)
    for (let i = 0; i < b64Dec.length; i++) {
      u8[i] = b64Dec[i]
    }
    // Console.log("u8", u8)
    return u8
  }

  /**
   * Generate a random key for use with Libsodium's secretbox interface
   *
   * @returns {string}
   */
  async randomKey() {
    // Console.log("random key")
    await sodium.ready
    return sodium.crypto_secretbox_keygen()
  }

  /**
   * Use PBKDF2 to derive a key of a given length using a specified password
   * and salt.
   *
   * @param {string} password User-specified password
   * @param {string} salt     User-specified salt (should be random)
   * @param {number} length   Length of the key to generate
   *
   * @returns {Promise<string>}
   */

  async deriveKey(password, salt, length) {
    // Console.log("derive key")
    return new Promise((resolve, reject) => {
      crypto.pbkdf2(password, salt, 1000, length, 'sha512', (err, val) =>
        err ? reject(err) : resolve(val)
      )
    })
  }

  /**
   * Derive an Ed25519 keypair from a password and a random salt
   *
   * @param {string} password User-specified password
   * @param {string} salt     User-specified salt (should be random)
   *
   * @returns {KeyPair} Object containing publicKey and privateKey fields
   */
  async deriveSigningKey(password, salt) {
    // Console.log("derive signing key")
    await sodium.ready
    let seed = await this.deriveKey(password, salt, sodium.crypto_sign_SEEDBYTES)

    let keypair = sodium.crypto_sign_seed_keypair(new Uint8Array(seed))

    return new KeyPair(
      await this.b64encode(keypair.publicKey),
      await this.b64encode(keypair.privateKey)
    )
  }

  /**
   * Derive a Curve25519 keypair from a password and a random salt
   *
   * @param {string} password User-specified password
   * @param {string} salt     User-specified salt (should be random)
   *
   * @returns {KeyPair} Object containing publicKey and privateKey fields
   */
  async deriveCryptoKey(password, salt) {
    // Console.log("derive crypto key")
    await sodium.ready
    let seed = await this.deriveKey(password, salt, sodium.crypto_sign_SEEDBYTES)

    let keypair = sodium.crypto_box_seed_keypair(new Uint8Array(seed))

    return new KeyPair(
      await this.b64encode(keypair.publicKey),
      await this.b64encode(keypair.privateKey)
    )
  }

  /**
   * Derive a symmetric encryption key from a password and a random salt
   *
   * @param {string} password User-specified password
   * @param {string} salt     User-specified salt (should be random)
   *
   * @returns {string} base64Url encoded string
   */
  async deriveSymmetricKey(password, salt) {
    // Console.log("derive symmetric key")
    const buffer = await this.deriveKey(password, salt, sodium.crypto_secretbox_KEYBYTES)
    const b64String = await this.b64encode(buffer)
    return b64String
  }

  /**
   * Dynamically generate a Curve25519 keypair for use with registration and cryptographic operations
   *
   * @returns {KeyPair} Base64URL-encoded representation of the new keypair
   */
  async generateKeypair() {
    // Console.log("generate keypair")
    await sodium.ready
    let keypair = sodium.crypto_box_keypair()

    return new KeyPair(
      await this.b64encode(keypair.publicKey),
      await this.b64encode(keypair.privateKey)
    )
  }

  /**
   * Dynamically generate an Ed25519 keypair for use with registration and signing operations
   *
   * @returns {KeyPair} Base64URL-encoded representation of the new keypair
   */
  async generateSigningKeypair() {
    // Console.log("generate signing key pair")
    await sodium.ready
    let keypair = sodium.crypto_sign_keypair()

    return new KeyPair(
      await this.b64encode(keypair.publicKey),
      await this.b64encode(keypair.privateKey)
    )
  }

  str2ab(str) {
    var buf = new ArrayBuffer(str.length) // 2 bytes for each char
    var bufView = new Uint8Array(buf)
    for (var i = 0, strLen = str.length; i < strLen; i++) {
      bufView[i] = str.charCodeAt(i)
    }
    return buf
  }

  // Ab2str(buf) {
  //   return String.fromCharCode.apply(null, new Uint8Array(buf))
  // }

  // async readUploadedFileAsAB(fileName) {}

  async encryptLargeFile(fileName, ak, key) {
    await sodium.ready

    // Check if file with fileName exists, otherwise throw error
    if (!fs.existsSync(fileName)) {
      const err = "ERROR: file '" + fileName + "' does not exist."
      throw err
    }

    // Try to open file, if it fails throw error
    fs.open(fileName, 'r', (err, file) => {
      if (err) {
        const msg = "ERROR: file '" + file + "' could not be opened."
        throw msg
      }
    })

    const nonces = fileName.split('.')
    const names = nonces[0].split('/')
    const title = names[names.length - 1]

    console.log(key)

    // Create temporary filename and file for encrypted data
    const encryptedFileName = `e2e-${title}.bin`
    /* Const encryptedFileHandle = */ fs.open(encryptedFileName, 'w', err => {
      if (err) {
        const msg = 'ERROR: cannot create new file.'
        throw msg
      }
    })

    // Read file as an array buffer
    // const plainAB = await this.readUploadedFileAsAB(fileName)
    // const plainUint8 = new Uint8Array(plainAB)

    // update when possible
    // const bigHash = crypto.createHash('md5')
    // BigHash.update(plainUint8)

    const TAG_FINAL = sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
    const TAG_MESSAGE = sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE

    // Make header information and keys for encrypted file
    // const dk = crypto.getRandomValues(new Uint8Array(sodium.crypto_secretbox_KEYBYTES))
    const dk = crypto.randomBytes(sodium.crypto_secretbox_KEYBYTES)
    // Const edkN = crypto.getRandomValues(new Uint8Array(sodium.crypto_secretbox_NONCEBYTES))
    const edkN = crypto.randomBytes(sodium.crypto_secretbox_NONCEBYTES)
    const edk = sodium.crypto_secretbox_easy(dk, edkN, ak)

    const header1 = FILE_VERSION
    const header2 = await this.b64encode(edk)
    const header3 = await this.b64encode(edkN)
    const header = `${header1}.${header2}.${header3}.`
    const headerAB = this.str2ab(header)
    const headerUint8 = new Uint8Array(headerAB)

    // Let encryptedFile = new Uint8Array()
    let encryptedLength = 0
    let hash = crypto.createHash('md5')
    // Console.log("hash: " + hash)

    // fs.writeFile(encryptedFileName, 'e2e-prac.bin\n', (err) => {
    //   if (err) throw err
    //   console.log("Successful")
    // })

    fs.appendFile(encryptedFileName, header, 'binary', err => {
      if (err) throw err
    })

    hash.update(headerUint8)
    encryptedLength += headerUint8.length

    const res = sodium.crypto_secretstream_xchacha20poly1305_init_push(dk)
    const state = res.state

    const sodiumHeader = res.header
    hash.update(sodiumHeader)

    fs.appendFile(encryptedFileName, sodiumHeader, 'binary', err => {
      if (err) throw err
    })

    encryptedLength += sodiumHeader.length

    let instream = fs.createReadStream(fileName)
    // Let outstream = new stream
    // let rl = readline.createInterface(instream, outstream)

    instream
      .on('readable', () => {
        let chunk = instream.read(BLOCK_SIZE)
        console.log('chunk: ' + chunk)

        if (chunk !== null && chunk.length === BLOCK_SIZE) {
          let fileBlockUnint8 = new Uint8Array(chunk)
          // Console.log("fileBlock: " + fileBlockUnint8)
          let encryptedFileBlock = sodium.crypto_secretstream_xchacha20poly1305_push(
            state,
            fileBlockUnint8,
            null,
            TAG_MESSAGE
          )
          // Console.log("encrypted file block: " + encryptedFileBlock)
          hash.update(encryptedFileBlock)
          fs.appendFile(encryptedFileName, encryptedFileBlock, 'binary', err => {
            if (err) throw err
          })
          encryptedLength += encryptedFileBlock.length
        } else if (chunk !== null) {
          let fileBlockUnint8 = new Uint8Array(chunk)
          // Console.log("fileBlock: " + fileBlockUnint8)
          let encryptedFileBlock = sodium.crypto_secretstream_xchacha20poly1305_push(
            state,
            fileBlockUnint8,
            null,
            TAG_FINAL
          )
          // Console.log("encrypted file block: " + encryptedFileBlock)
          hash.update(encryptedFileBlock)
          fs.appendFile(encryptedFileName, encryptedFileBlock, 'binary', err => {
            if (err) throw err
          })
          encryptedLength += encryptedFileBlock.length
        }
      })
      .on('end', () => {
        console.log('not readable')
      })

    // Rl.on('line', function(line) {
    //   console.log(line)
    // })
    // rl.on('close', function() {
    //   console.log("finished")
    // })

    const checkSum = hash.toString('base64')
    // Const encryptedFileBlob = new Blob([new Uint8Array(encryptedFile)])
    // encryptedFileBlob.lastModifiedDate = new Date()
    // encryptedFileBlob.fileName = encryptedFileName

    return [/* encryptedFileBlob */ encryptedFileName, checkSum, encryptedLength]
  }
}
