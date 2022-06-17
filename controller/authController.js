
const {hash} = require ('bcrypt')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const {User} = require ('../models/User')

const { sendEmail } = require('../config/utils')

//register user

const register = async(req,res) =>{
        if(!req.body.name){
            res.status(400).send({
                status : 0,
                message : "name is required"
            })
        }
        else if(!req.body.email){
            res.status(400).send({
                status : 0,
                message : "email is required"
            })
        }
        else if(!req.body.password){
            res.status(400).send({
                status : 0,
                message : "password is required"
            })
        }
        else{
            User.find({email : req.body.email})
            .exec()
            .then(user =>{
                if(user.length >= 1){
                    res.status(400).send({
                        status:0,
                        message : "email already exist"
                    })
                }
                else{
                    bcrypt.hash(req.body.password, 10, (err, hash) => {
                        if(err){
                            res.status(400).send({
                                status: 0, 
                                message: err
                            });
                        }
                        else{
                            if (req.file) {
                                profilePicture = req.file.path
                            }
    
                            const verificationCode = Math.floor(100000 + Math.random() * 900000);
    
                            const user = new User;
                            user.name = req.body.name;
                            user.email = req.body.email;
                            user.password = hash; 
                            user.profilePicture =  (req.file ? req.file.path : req.body.profilePicture);
                            user.code = verificationCode; 
                            user.save()
    
                            .then(result => {
                                sendEmail(user.email, verificationCode, "Email verification");
    
                                return res.status(400).send({
                                    status: 1, 
                                    message: 'User verification code successfully sent to email.',
                                    data: {
                                        user_id: result._id
                                    }
                                });
                            })
                            .catch(errr => {
                                res.status(400).send({
                                    status: 0, 
                                    message: errr 
                                });
                            });
                        }
                    });
                }
            })
            .catch(err => {
                res.status(400).send({
                    status: 0, 
                    message: err 
                });
            });
        }   
    }   

//login User

const login = async (req , res )=>{
    if(!req.body.email){
        return res.status(400).send({
            status : 0,
            message: "email field is required"
        })
    }
    else if(!req.body.password){
        return res.status(400).send({
            status : 0,
            message : "Password field is required"
        })

    }
    else {
        User.find({email : req.body.email}).select("+password")
        .exec()
        .then(user =>{
            if(user.length<1){
                return res.status(400).send({
                    status: 0,
                    message : "email not found"
                })                                                 
            }
            else{
               // console.log(req.body);
                bcrypt.compare(req.body.password, user[0].password, (err , result) => {
                    // console.log("auth erre", err);
                    if(err){
                        return res.status(400).send({
                            status : 0,
                            message: "Authentication failed"
                        })
                    }
                    // console.log(err);
                    if(result){
                        const token = jwt.sign(
                        {
                            email : user[0].email,
                            userId : user[0]._id
                        },
                        process.env.JWT_KEY,
                        {
                            expiresIn: "24hr"
                        })
                        User.findOneAndUpdate({ user_authentication: token})
            
                        user[0].user_authentication = token

                        user[0].save()
                                return res.status(200).send({
                                    status: 1,
                                    message: 'User logged in successfully!',
                                   // token: token,
                                    data: user[0]
                                });


                    }
                    return res.status(400).send({
                        status: 0, 
                        message: 'Incorrect password.'
                    })
                 
                });
                
            }
        
        })
        .catch(err => {
            res.status(400).send({
                status : 0,
                message : err
            })
        })
    }
}
const socialLogin = async (req, res) => {
    try {
        const alreadyUserAsSocialToke = await User.findOne({ user_social_token: req.body.user_social_token })
        if (alreadyUserAsSocialToke) {
            if (alreadyUserAsSocialToke.user_type !== req.body.user_type) {
                return res.status(400).send({ status: 0, message: "Invalid User Type!" });
            }
        }
        if (!req.body.user_social_token) {
            return res.status(400).send({ status: 0, message: 'User Social Token field is required' });
        }
        else if (!req.body.user_social_type) {
            return res.status(400).send({ status: 0, message: 'User Social Type field is required' });
        }
        else if (!req.body.user_device_type) {
            return res.status(400).send({ status: 0, message: 'User Device Type field is required' });
        }
        else if (!req.body.user_device_token) {
            return res.status(400).send({ status: 0, message: 'User Device Token field is required' });
        }
        else {
            const checkUser = await User.findOne({ user_social_token: req.body.user_social_token });
            if (!checkUser) {
                const newRecord = new User();
                // if(req.file){
                //     newRecord.user_image    = req.file.path
                //  }
                // const customer = await stripe.customers.create({
                //     description: 'New Customer Created',
                // });
                // newRecord.stripe_id = customer.id;
                // newRecord.user_image = req.body.user_image ? req.body.user_image : ""
                // newRecord.user_image = req.body.user_image
                // newRecord.user_image = req.file ? req.file.path : req.body.user_image,
                    newRecord.user_social_token = req.body.user_social_token,///
                    newRecord.user_social_type = req.body.user_social_type,
                    newRecord.user_device_type = req.body.user_device_type,
                    newRecord.user_device_token = req.body.user_device_token
                // newRecord.user_name = req.body.user_name,////
                    newRecord.email = req.body.email,
                    //newRecord.user_type = req.body.user_type,
                    newRecord.verified = 1
                await newRecord.generateAuthToken();
                const saveLogin = await newRecord.save();
                return res.status(200).send({ status: 1, message: 'Login Successfully', data: saveLogin });
            } else {
                const token = await checkUser.generateAuthToken();
                const upatedRecord = await User.findOneAndUpdate({ _id: checkUser._id },
                    { user_device_type: req.body.user_device_type, user_device_token: req.body.user_device_token, verified: 1 }
                    , { new: true });
                return res.status(200).send({ status: 1, message: 'Login Successfully', token: token,      data: upatedRecord });
            }
        }
        // console.log("here 3 ")
    }
    catch (error) {
        console.log('error *** ', error);
        res.status(500).json({
            status: 0,
            message: error.message
        });
    }
}


const updateProfile = async(req, res) =>{
    try{
        const user = await User.findById ( req.user._id ) ;
        const { name , email , profilePicture } = req.body ;
        if ( name ) {
        user.name = name ;
        }
        if ( email ) {
        user.email = email ;
        }
        if (profilePicture){
            user.profilePicture = req.file
        }
        // User Avatar : TODO
        await user.save ( ) ;

        return res.status(200).send({
            status : 1,
            message: "profile updated"
        })
    }
    catch (error) {
    return res.status(500).json({
    status : 0 ,
    message : error.message ,
    } ) ;
    }
}



// forget password

// const forgetPassword = async(req, res) =>{
//     const user = await User.findOne({email : req.body.email})

//     if(!user){
//         return res.status(400).json({
//             status : 0,
//             message : "User not found"
//         })
//     }
    
//     const resetPasswordToken =user.getResetPasswordToken()
// }

/** Forgot password */
const forgotPassword = async (req, res) => {
    if(!req.body.email){
        res.status(400).send({
            status: 0, 
            message: 'Email filed is required' 
        });
    }
    else{
        User.find({ email: req.body.email })
        .exec()
        .then(user => {
            if(user.length < 1){
                return res.status(404).send({
                    status: 0, 
                    message: 'Email not found!' 
                });
            }
            else{
                const verificationCode = Math.floor(100000 + Math.random() * 900000);

                User.findByIdAndUpdate(user[0]._id, { code: verificationCode }, (err, _result) => {
                    if(err){
                        res.status(400).send({
                            status: 0, 
                            message: 'Something went wrong.' 
                        });
                    }
                    if(_result){
                        sendEmail(user[0].email, verificationCode, 'Forgot Password');
                        res.status(200).send({
                            status: 1, 
                            message: 'Code successfully send to email.',
                            data: {
                                user_id: user[0]._id
                            }
                        });
                    }
                });
            }
        })
        .catch(err => {
            res.status(400).send({
                status: 0, 
                message: 'User not found' 
            });
        });
    }
}

/** Verify user */
const verifyUser = async (req, res) => {
    if(!req.body.user_id){
        res.status(400).send({
            status: 0, 
            message: 'User id filed is required' 
        });
    }
    else if(!req.body.verification_code){
        res.status(400).send({
            status: 0, 
            message: 'Verification code filed is required' 
        });
    }
    else{
        User.find({ _id: req.body.user_id })
        .exec()
        .then(result => {
            if(!req.body.verification_code){
                res.status(400).send({
                    status: 0, 
                    message: 'Verification code is required.' 
                });
            }

            if(req.body.verification_code == result[0].code){

                User.findByIdAndUpdate(req.body.user_id, { verified: 1, code: null }, (err, _result) => {
                    if(err){
                        res.status(400).send({
                            status: 0, 
                            message: 'Something went wrong.' 
                        });
                    }
                    if(_result){
                        res.status(200).send({
                            status: 1, 
                            message: 'Otp matched successfully.' 
                        });
                    }
                });
            }
            else{
                res.status(200).send({
                    status: 0, 
                    message: 'Verification code did not matched.' 
                });
            }
        })
        .catch(err => {
            res.status(400).send({
                status: 0, 
                message: 'User not found' 
            });
        });
    }
}

/** Resend code */
const resendCode = async (req, res) => {
    if(!req.body.user_id){
        res.status(400).send({
            status: 0, 
            message: 'User id failed is required.' 
        });
    }
    else{
        User.find({ _id: req.body.user_id })
        .exec()
        .then(result => {
            const verificationCode = Math.floor(100000 + Math.random() * 900000);
    
            User.findByIdAndUpdate(req.body.user_id, { verified: 0, code: verificationCode }, (err, _result) => {
                if(err){
                    res.status(400).send({
                        status: 0, 
                        message: 'Something went wrong.' 
                    });
                }
                if(_result){
                    sendEmail(result[0].email, verificationCode, "Verification Code Resend");
                    res.status(200).send({
                        status: 1, 
                        message: 'Verification code resend successfully.' 
                    });
                }
            });
        })
        .catch(err => {
            res.status(400).send({
                status: 0, 
                message: 'User not found' 
            });
        });
    }
}

const updatePassword = async (req, res) => {
    if(!req.body.user_id){
        res.status(400).send({
            status: 0, 
            message: 'User id filed is required.' 
        });
    }
    else if(!req.body.new_password){
        res.status(400).send({
            status: 0, 
            message: 'New password filed is required.' 
        });
    }
    else{
        User.find({ _id: req.body.user_id })
        .exec()
        .then(user => {

            bcrypt.hash(req.body.new_password, 10, (error, hash) => {
                if(error){
                    return res.status(400).send({
                        status: 0, 
                        message: error
                    });
                }
                else{
                    User.findByIdAndUpdate(req.body.user_id, { password: hash }, (err, _result) => {
                        if(err){
                            res.status(400).send({
                                status: 0, 
                                message: 'Something went wrong.' 
                            });
                        }
                        if(_result){
                            res.status(200).send({
                                status: 1, 
                                message: 'Password updated successfully.' 
                            });
                        }
                    });
                }
            });
        })
        .catch(err => {
            res.status(400).send({
                status: 0, 
                message: 'User not found.'
            });
        });
    }
}



// logout


const logout = async (req , res) =>{
    try {

        // if (!req.body._id) {
        //     res.status(400).send({ status: 0, message: 'User ID field is required' });
        // }
        // else if (!req.headers.authorization) {
        //     res.status(400).send({ status: 0, message: 'Authentication Field is required' });
        // }
        
            const updateUser = await User.findOneAndUpdate({ _id: req.user._id }, {
                user_authentication: null,
                user_device_type: null,
                user_device_token: null
            });
            res.status(200).send({ status: 1, message: 'User logout Successfully.' });

        
    } catch (e) {
        res.status(400).send(e.message);
    }
}



module.exports = {register, login , socialLogin , updatePassword ,  updateProfile ,  forgotPassword , verifyUser , resendCode , logout}
