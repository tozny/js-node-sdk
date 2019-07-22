const fs = require('fs')
require('dotenv').config()

const tozStore = require('../dist/index.js')
const Config = tozStore.Config
// console.log(process.env.TEST)
// console.log(process.env.CLIENT_CREDENTIALS_JSON)
const config = Config.fromObject({ "version": 2, "client_id": "048abe4d-ecd0-4fbd-be28-e651c9d12cdc", "client_email": "", "api_url": "https://dev.e3db.com", "api_key_id": "c5a18c4fb67856a7bdf498c736f1405a7b80ae5354ad9f3454d0751b72d55f1d", "api_secret": "40d6788e353333fe0114684982e3d4ab0dd07ce146462e734d87a50b43722241", "public_key": "XzTaOe0lTtuLxtS2BmvaSkdbMYIdw-ZVjC2xFt4hDHc", "private_key": "JUyIF-nQETtK0tNmGVfoxKK1UV2wJWAEVi9Tt23LWbM", "public_signing_key": "Ew9ugXeYG9cF4w1yqUoETCxhSDAqg7c6pHLMVMYWtz4", "private_signing_key": "N2tgPdPG7NIzR6oWZu_KzcS-O1KW4SvO6xGhtlUKBmwTD26Bd5gb1wXjDXKpSgRMLGFIMCqDtzqkcsxUxha3Pg" })
const Client = tozStore.init('Sodium')
const client = new Client(config)

// const readline = require('readline');
// const stream = require('stream');

const writeFile = async client => {
  let writtenFile = []
  const plainMeta = {
    key1: 'val1',
    key2: 'val2'
  }

  // const path = 'examples/prac.txt'
  // fs.appendFile(path, ' write something.', function(err) {
  //   if (err) throw err
  //   console.log("saved!")
  // })

  try {
    writtenFile = await client.writeLargeFile(
      "janeEyre",
      "examples/prac.txt" /*'examples/janeEyre.txt'*/,
      plainMeta
    )
  } catch (err) {
    // console.log(err)
  }

  // console.log(writtenFile)
}

writeFile(client)
