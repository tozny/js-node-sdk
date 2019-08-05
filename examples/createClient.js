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
  const recordID = 'cc6e324d-91d0-4328-a536-3402ae6d6f24'
  const destFile = 'diana.png'
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
