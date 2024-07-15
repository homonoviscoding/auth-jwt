const jwt = require('jsonwebtoken')

function createToken (payload, secret) {
    const myPayload = payload
    const mySecret = secret
    const token = jwt.sign((myPayload), mySecret, { algorithm: 'HS256' })
    return token
}

const payload = {
    id: 153,
    username: "sanchez",
    email: "rick@sanchez.com",
    role: "ADMIN"
}

const secret = '87764d1a-92dc-4ced-a758-9c898c31d525'
const tokenize = createToken(payload, secret)
console.log(tokenize)