import { default as init } from './init'

// Option to overwrite default (Crypto)Type mode.
const mode = process.env.E3DB_MODE || 'Sodium'

/* eslint-disable-next-line new-cap */
const Client = init(mode)

export default Client
