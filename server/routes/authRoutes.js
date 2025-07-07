import express from 'express'
import { isAuthenticated, login, logout, register, sendVerifyOtp, senResetOtp, verifyEmail, verifyPassOtp } from '../config/controllers/authController.js'
import userAuth from '../middleware/userAuth.js'

export const authRouter = express.Router()

authRouter.post('/register',register)
authRouter.post('/login',login)
authRouter.post('/logout',logout)
authRouter.post('/send-verify-otp',userAuth,sendVerifyOtp)
authRouter.post('/verify-account',userAuth,verifyEmail)
authRouter.post('/is-auth',userAuth,isAuthenticated)
authRouter.post('/send-reset-otp',senResetOtp)
authRouter.post('/reset-password',verifyPassOtp)