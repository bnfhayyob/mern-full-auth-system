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
            res.json({success:false,message:"Invalid email!"})
        }
        const isMatch = await bcrypt.compare(password,user.password)
        if(!isMatch){
            res.json({success:false,message:"Invalid password!"})
        }
        const token = jwt.sign({id:user._id},process.env.JWT_SECRET, {expiresIn:'7d'})
        res.cookie('token',token, {
            httpOnly:true,
            secure:process.env.NODE_ENV === 'production',
            sameSite:process.env.NODE_ENV === 'production'?'none':'strict',
            maxAge:7*24*60*60*1000
        })
        return res.json({sucess:true})
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

export const verifyEmail = async (req,res) => {
    const userId = req.user.id 
    const { otp } = req.body
    console.log(userId)

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
        console.log(user.verifyOtpExpireArt)
        if(user.verifyOtpExpireArt < Date.now()){
            return res.json({success:false,message:"OTP expired"})
        }
        user.isVerified = true
        user.verifyOtp = ""
        user.verifyOtpExpireArt = 0

        await user.save()
        return res.json({success:true,message:"Email cerified Successfully"})
    } catch (error) {
          return res.json({success:false,message:error.message})
    }
}