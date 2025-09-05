const BaseError = require('../errors/base.error')
const jwt = require('jsonwebtoken')
const userModel = require('../models/user.model')

module.exports = async function (req, res, next) {
  try {
    const authorization = req.headers.authorization
    if (!authorization) {
      console.warn("⚠️ No authorization header")
      return next(BaseError.Unauthorized())
    }

    const token = authorization.split(' ')[1]
    if (!token) {
      console.warn("⚠️ No token found in Authorization header")
      return next(BaseError.Unauthorized())
    }

    console.log("🔑 Token received in middleware:", token)
    console.log("🔐 JWT_SECRET in server:", process.env.JWT_SECRET)

    const decoded = jwt.verify(token, process.env.JWT_SECRET)
    console.log("📝 Decoded token:", decoded)

    if (!decoded.userId) {
      console.warn("⚠️ Token does not contain userId")
      return next(BaseError.Unauthorized())
    }

    const user = await userModel.findById(decoded.userId)
    if (!user) {
      console.warn("⚠️ No user found for ID:", decoded.userId)
      return next(BaseError.Unauthorized())
    }

    req.user = user
    next()
  } catch (err) {
    console.error("❌ JWT verification failed:", err.message)
    return next(BaseError.Unauthorized())
  }
}
