const jwt = require('jsonwebtoken');

/**
 * Implement this function to accept a payload and a secret key and return a JWT without an expiry time
 * 
 * Documentation: https://www.npmjs.com/package/jsonwebtoken#jwtsignpayload-secretorprivatekey-options-callback
 */
function createToken(payload, secret) {
    const token = jwt.sign((payload), secret, { algorithm: 'HS256' })
    return token
}
const payload = {
    id: 1,
    username: "nathank",
    iat: 1643987414
}
const secret = 'mysecretkey'
const createdToken = createToken(payload, secret)
console.log(createdToken)

/**
 * Implement this function to accept a payload, secret key and an expiry time, and return a JWT with an expiry
 * 
 * Documentation: https://www.npmjs.com/package/jsonwebtoken#token-expiration-exp-claim
 */
function createTokenWithExpiry(payload, secret, exp) {
    const expiration = { expiresIn: exp }
    const token = jwt.sign((payload), secret, expiration, { algorithm: 'HS256' })
    return token
}


const token = createTokenWithExpiry(payload, secret, '1h')
console.log(token)

/**
 * Implement this function to accept a JWT and a secret key. Return the decoded token (the payload) if verification is successful, and false if it fails
 * 
 * Documentation: https://www.npmjs.com/package/jsonwebtoken#jwtverifytoken-secretorpublickey-options-callback
 */
function verifyToken(token, secret) {
    const tokenToVerify = token
    const secretToVerify = secret
    try {
        const decoded = jwt.verify(tokenToVerify, secretToVerify)
        return decoded
    } catch (error) {
        return false
    }
}

const decoded = verifyToken(createdToken, secret)
console.log(decoded)

module.exports = {
    createToken,
    createTokenWithExpiry,
    verifyToken
}
