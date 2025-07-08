import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import userModel from '../models/userModel.js'
import transporter from '../nodemailer.js'

export const register = async (req,res) => {
    const {name,email,password} = req.body

    if(!name || !email || !password){
        return res.json({success:false,message:"Missing Details!"})
    }
    try {
        const existingUser = await userModel.findOne({email})

        if(existingUser){
            return res.json({success:false,message:"User Already exist!"})
        }

        const hashedPassword = await bcrypt.hash(password,10)

        const user = new userModel({name,email,password:hashedPassword})
        await user.save()

        const token = jwt.sign({id:user._id},process.env.JWT_SECRET, {expiresIn:'7d'})

        res.cookie('token',token, {
            httpOnly:true,
            secure:process.env.NODE_ENV === 'production',
            sameSite:process.env.NODE_ENV === 'production'?'none':'strict',
            maxAge:7*24*60*60*1000
        })

        //Sending welcome email
        const mailOptions={
            from:process.env.SENDER_EMAIL,
            to:email,
            subject:'Welcome to AuthCheck',
            text:`Welcome to AuthCheck website. Your account has created with id: ${email}`
        }

        await transporter.sendMail(mailOptions)

        return res.json({sucess:true})
    } catch (error) {
        res.json({success:false,message:error.message})
    }
}

export const login = async (req,res) => {
    const {email,password} = req.body
    if(!email || !password){
        return res.json({success:false,message:"Email and Password are required!"})
    }
    try {
        const user = await userModel.findOne({email})
        if(!user){
           return res.json({success:false,message:"Invalid email!"})
        }
        const isMatch = await bcrypt.compare(password,user.password)
        if(!isMatch){
           return res.json({success:false,message:"Invalid password!"})
        }
        const token = jwt.sign({id:user._id},process.env.JWT_SECRET, {expiresIn:'7d'})
        res.cookie('token',token, {
            httpOnly:true,
            secure:process.env.NODE_ENV === 'production',
            sameSite:process.env.NODE_ENV === 'production'?'none':'strict',
            maxAge:7*24*60*60*1000
        })
        return res.json({success:true})
    } catch (error) {
        return res.json({success:false,message:error.message})
    }
}

export const logout = async (req,res) => {
    try {
        res.clearCookie('token',{
            httpOnly:true,
            secure:process.env.NODE_ENV === 'production',
            sameSite:process.env.NODE_ENV === 'production'?'none':'strict'
        })
        return res.json({success:true,message:"Logged Out!"})
    } catch (error) {
        res.json({success:false,message:error.message})
    }
}

//send Verification OTP
export const sendVerifyOtp = async (req, res) => {
    try {
        const userId = req.user.id  // Get userId from req.user instead of req.body

        const user = await userModel.findById(userId)

        if (user.isVerified) {
            return res.json({ success: false, message: "Account Already verified!" })
        }
        
        const otp = String(Math.floor(100000 + Math.random() * 900000))

        user.verifyOtp = otp
        user.verifyOtpExpireArt = Date.now() + 24 * 60 * 60 * 1000 // 24 hours

        await user.save()

        const mailOption = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Account Verification OTP',
            text: `Your OTP is ${otp}. Verify your account using this code`
        }
        
        await transporter.sendMail(mailOption)
        res.json({ success: true, message: "Verification OTP sent on Email" })
    } catch (error) {
        res.json({ success: false, message: error.message })
    }
}
//verify email using OTP
export const verifyEmail = async (req,res) => {
    const userId = req.user.id 
    const { otp } = req.body

    if(!userId || !otp){
        return res.json({success:false,message:"Missing Details!"})
    }
    try {
        const user = await userModel.findById(userId)

        if(!user){
            return res.json({success:false,message:"User not found"})
        }
        if(user.verifyOtp === '' || user.verifyOtp !== otp){
            return res.json({success:false,message:"Invalid OTP"})
        }
        if(user.verifyOtpExpireArt < Date.now()){
            return res.json({success:false,message:"OTP expired"})
        }
        user.isVerified = true
        user.verifyOtp = ""
        user.verifyOtpExpireArt = 0

        await user.save()
        return res.json({success:true,message:"Email verified Successfully"})
    } catch (error) {
          return res.json({success:false,message:error.message})
    }
}
//check if user is authenticated
export const isAuthenticated = async (req,res) => {
    try {
        const token = req.cookies.token
        
        if (!token) {
            return res.json({success: false, message: 'No token found'})
        }
        
        const decoded = jwt.verify(token, process.env.JWT_SECRET)
        const user = await userModel.findById(decoded.id)
        
        if (!user) {
            return res.json({success: false, message: 'User not found'})
        }
        
        return res.json({success: true, message: 'User is authenticated'})
    } catch (error) {
        return res.json({success: false, message: error.message})
    }
}
//Send password reset OTP
export const senResetOtp = async (req,res) => {
    const {email} = req.body
    if(!email){
        return res.json({success:false,message:"Email is required!"})
    }
    try {
        const user = await userModel.findOne({email})
        if(!user){
            return res.json({success:false,message:"User not found!"})
        }
        const otp = String(Math.floor(100000 + Math.random() * 900000))
        user.resetOtp = otp
        user.resetOtpExprieArt = Date.now() + 15 * 60 * 1000 // 15 Minutes

        await user.save()

        const mailOption = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Password Reset OTP',
            text: `Your OTP for resetting your Account password  is ${otp}. USer this OTP to reset your password`
        }
            await transporter.sendMail(mailOption)
        res.json({ success: true, message: "OTP sent to email" })
    } catch (error) {
        return res.json({success:false,message:error.message})
    }
}
//check password reset OTP
export const verifyPassOtp = async (req,res) => {
    const {email,otp,newPassword} = req.body

    if(!email || !otp || !newPassword){
        return res.json({success:false,message:"Email,OTP, and news Password are required!"})
    }
    try {
        const user = await userModel.findOne({email})
        if(!user){
            return res.json({success:false,message:"User not found!"})
        }
        
        if(user.resetOtp === "" || user.resetOtp !== otp){
            return res.json({success:false,message:"Invalid OTP!"})
        }

        if(user.resetOtpExprieArt < Date.now()){
            return res.json({success:false,message:"OTP expired!"})
        }

        const haschedPassword = await bcrypt.hash(newPassword,10)
        user.password = haschedPassword
        user.resetOtp = ''
        user.resetOtpExprieArt = 0

        await user.save()

        return res.json({success:true,message:"Password has been reset successfully!"})
    } catch (error) {
        return res.json({success:false,message:error.message})
    }
}