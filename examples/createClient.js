require('dotenv').config()

const tozStore = require("../dist/index.js")
const Config = tozStore.Config
const config = Config.fromObject(process.env.CLIENT_CREDENTIALS_JSON)
const Client = tozStore.init('Sodium')
const client = new Client(config)

const writeFile = async client => {
  let writtenFile = []
  const plainMeta = {
    key1: "val1",
    key2: "val2"
  }

  const fileType = "jane-eyre-test"
  const fileName = 'examples/janeEyre.txt'

  try {
    writtenFile = await client.writeLargeFile(
      fileType,
      fileName,
      plainMeta
    )
  } catch (err) {
    console.log(err)
  }

  console.log(writtenFile)
}

const readFile = async client => {
  const recordID = '5d98c2f4-22e8-484a-be8d-94ad50940ae8'
  const destFile = 'jane.txt'
  try {
    let decryptedFile = await client.readLargeFile(
      recordID,
      destFile
    )
  } catch (err) {
    console.log(err)
  }
}

// readFile(client)
writeFile(client)
