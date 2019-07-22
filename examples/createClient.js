require("dotenv").config()
const fs = require("fs")

const tozStore = require("../dist/index.js")
const Config = tozStore.Config
const config = Config.fromObject(process.env.CLIENT_CREDENTIALS_JSON)
const Client = tozStore.init("Sodium")
const client = new Client(config)

// const readline = require('readline');
// const stream = require('stream');

const writeFile = async client => {
  let writtenFile = []
  const plainMeta = {
    key1: "val1",
    key2: "val2"
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
    console.log(err)
  }

  // console.log(writtenFile)
}

writeFile(client)
