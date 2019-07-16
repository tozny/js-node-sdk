require("dotenv").config()
const fs = require("fs")

const tozStore = require("../dist/index.js")
const Config = tozStore.Config
const config = Config.fromObject(process.env.CLIENT_CREDENTIALS_JSON)
const Client = tozStore.init("Sodium")
const client = new Client(config)

const writeFile = async client => {
  const exampleFile = fs.appendFile(
    "mynewfile1.txt",
    "Hello content!",
    function(err) {
      if (err) throw err
      console.log("Saved!")
    }
  )
  //   const exampleFile = new File(
  //     [
  //       "A first line of text.  And a second line of text.  Lastly, a third line of text."
  //     ],
  //     "filename.txt",
  //     { type: "text/plain" }
  //   )
  const plainMeta = {
    key1: "val1",
    key2: "val2"
  }

  const writtenFile = await client.writeLargeFile(
    "testFileType",
    exampleFile,
    plainMeta
  )
  console.log(writtenFile)
}

writeFile(client)
