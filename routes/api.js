const router = require('express').Router()
const { User } = require('../models/User')
const {register, login, verifyUser, resendCode, forgotPassword, updatePassword , socialLogin , updateProfile , logout} = require('../controller/authController')
const { verifyToken } = require('../middleware/authenticate')
const { upload } = require('../middleware/multer')

router.post('/register', upload.single('profilePicture'), register)
router.post('/login', login)
router.post('/forgot-password', forgotPassword);
router.post('/verify-user', verifyUser);
router.post('/resend-code', resendCode);
router.post('/update-password', verifyToken, updatePassword);
router.post('/social-login', socialLogin)
router.put('/update-profile', verifyToken, updateProfile)
router.post('/logout', verifyToken , logout)


module.exports = router;