// Console.log("init.js")

import ClientInterface from 'e3db-client-interface'
import SodiumCrypto from './SodiumCrypto'

// Takes param of crypto type string
// Returns a client constructor

const init = typeCrypto => {
  let crypto
  if (typeCrypto === 'Sodium') {
    crypto = new SodiumCrypto()
    // Else if Other available (Type)Crypto classes.
  } else {
    throw new Error('Init method requires a supported crypto type.')
  }
  /* eslint-disable-next-line new-cap */
  const Client = ClientInterface.Client(crypto)
  Client.crypto = crypto
  return Client
}

// Console.log("leave init.js")

export default init
