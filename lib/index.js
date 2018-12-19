import ClientInterface from 'e3db-client-interface'
import SodiumCrypto from './SodiumCrypto'

const crypto = new SodiumCrypto()
/* eslint-disable-next-line new-cap */
const Client = ClientInterface.Client(crypto)
const Config = ClientInterface.Config

export default { Client, Config, SodiumCrypto }
