const tozStore = require("../dist/index.js")

console.log(tozStore)

// console.log(tozStore.default)

// console.log(tozStore.default.Client)
// console.log(tozStore.default.Config)
// console.log(tozStore.default.init)

console.log("CORRECT VALUES")
console.log(tozStore.Client)
console.log(tozStore.Config)
const Client = tozStore.init("Sodium")
console.log(Client)
const client = new Client()