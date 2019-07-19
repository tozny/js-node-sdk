// Console.log("client.js")

import { default as init } from './init'

// Option to overwrite default (Crypto)Type mode.
const mode = process.env.E3DB_MODE || 'Sodium'

/* eslint-disable-next-line new-cap */
let Client
let crypto

try {
  console.log('client try')
  const withCrypto = init(mode)
  Client = withCrypto.Client
  crypto = withCrypto.crypto
} catch (err) {
  throw new Error('Environment variable `E3DB_MODE` not an available crypto type. ')
}

export default { Client, crypto }
