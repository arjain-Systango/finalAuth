import express from 'express';

import authController from '../controller/auth.controller';
import { jwtValidator } from '../middlewares/jwtValidator';
import { refreshTokenValidator } from '../middlewares/refreshTokenValidator';
import { requestValidator } from '../middlewares/requestValidator';
import userValidator from '../validation/user.validator';
const router = express.Router();
/**
 * @swagger
 * tags:
 *   - name: Auth
 *     description: API endpoints for auth
 */
/**
 * @swagger
 * /auth/register:
 *   post:
 *     summary: User register
 *     description: |
 *                  - register api have mobile number optional.
 *                  - otp will sent to provided email
 *                  - otp verification for mobile through sms is not added yet.
 *                  - user will be able to login with unverified email
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 format: string
 *                 example: john@example.com
 *               mobile:
 *                 type: string
 *                 format: string
 *                 example: '8880001231'
 *               firstName:
 *                 type: string
 *                 format: string
 *                 example: john
 *               lastName:
 *                 type: string
 *                 format: string
 *                 example: doe
 *               password:
 *                 type: string
 *                 format: string
 *                 example: john@123D
 *     responses:
 *       '201':
 *         description: registration successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: registration successful
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 201
 *       '400':
 *         description: Bad request
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: email must be a valid email
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 400
 *       '409':
 *         description: Conflict
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Already exists
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 409
 *
 *       '500':
 *         description: Internal server error
 */
router.post(
  '/register',
  requestValidator(userValidator.registerUserSchema, 'body'),
  authController.register,
);

/**
 * @swagger
 * /auth/login:
 *   post:
 *     summary: User login
 *     description: if user have two factor enabled, then token will not generate in response until 2fa is not verified.
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 format: string
 *                 example: john@example.com
 *               password:
 *                 type: string
 *                 format: string
 *                 example: john@123D
 *     responses:
 *       '200':
 *         description: login successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: login successful
 *                 data:
 *                   type: object
 *                   format: object
 *                   properties:
 *                     id:
 *                       type: number
 *                       format: number
 *                       example: 12
 *                     email:
 *                       type: string
 *                       format: string
 *                       example: john@example.com
 *                     mobile:
 *                       type: string
 *                       format: string
 *                       example: '8880001231'
 *                     role:
 *                       type: string
 *                       format: string
 *                       example: user
 *                     authType:
 *                       type: string
 *                       format: string
 *                       example: email
 *                     isActive:
 *                       type: boolean
 *                       format: boolean
 *                       example: true
 *                     firstName:
 *                       type: string
 *                       format: string
 *                       example: john
 *                     lastName:
 *                       type: string
 *                       format: string
 *                       example: doe
 *                     isEmailVerified:
 *                       type: boolean
 *                       format: boolean
 *                       example: true
 *                     isMobileVerified:
 *                       type: boolean
 *                       format: boolean
 *                       example: false
 *                     token:
 *                       type: string
 *                       format: string
 *                       example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MTYsInJvbGUiOiJ1c2VyIiwiaXNBY3RpdmUiOnRydWUsImVtYWlsIjoiam9obkBleGFtcGxlLmNvbSIsImZpcnN0TmFtZSI6ImpvaG4iLCJsYXN0TmFtZSI6ImRvZSIsImlzRGVsZXRlZCI6ZmFsc2UsImlhdCI6MTY5ODIxNDg4MywiZXhwIjoxNzI5NzcyNDgzfQ.DRZefS8kzhOYWW_gOLBn66UswSdgwxnRNQE7gVNWK1c
 *                     refreshToken:
 *                       type: string
 *                       format: string
 *                       example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MTYsInJvbGUiOiJ1c2VyIiwiaXNBY3RpdmUiOnRydWUsImVtYWlsIjoiam9obkBleGFtcGxlLmNvbSIsImZpcnN0TmFtZSI6ImpvaG4iLCJsYXN0TmFtZSI6ImRvZSIsImlzRGVsZXRlZCI6ZmFsc2UsImlhdCI6MTY5ODIxNDg4MywiZXhwIjoxNzI5NzcyNDgzfQ.DRZefS8kzhOYWW_gOLBn66UswSdgwxnRNQE7gVNWK1c
 *                     timeToLive:
 *                       type: number
 *                       format: number
 *                       example: 1516239022
 *                     isTwoFAEnabled:
 *                       type: boolean
 *                       format: boolean
 *                       example: true
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 200
 *       '400':
 *         description: Bad request
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Email must be a valid email
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 400
 *       '401':
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Invalid Email Or Password
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 401
 *       '500':
 *         description: Internal server error
 */
router.post(
  '/login',
  requestValidator(userValidator.userLoginSchema, 'body'),
  authController.login,
);

/**
 * @swagger
 * /auth/refresh-token:
 *   post:
 *     security:
 *       - bearerAuth: []
 *     summary: generate new jwt token for user
 *     description: |
 *                  - this api requires refresh token in header.
 *                  - api will be used to generate new token when jwt token expires.
 *     tags: [Auth]
 *     responses:
 *       '200':
 *         description: generated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: generated successfully
 *                 data:
 *                   type: object
 *                   format: object
 *                   properties:
 *                     token:
 *                       type: string
 *                       format: string
 *                       example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MTYsInJvbGUiOiJ1c2VyIiwiaXNBY3RpdmUiOnRydWUsImVtYWlsIjoiam9obkBleGFtcGxlLmNvbSIsImZpcnN0TmFtZSI6ImpvaG4iLCJsYXN0TmFtZSI6ImRvZSIsImlzRGVsZXRlZCI6ZmFsc2UsImlhdCI6MTY5ODIxNDg4MywiZXhwIjoxNzI5NzcyNDgzfQ.DRZefS8kzhOYWW_gOLBn66UswSdgwxnRNQE7gVNWK1c
 *                     refreshToken:
 *                       type: string
 *                       format: string
 *                       example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MTYsInJvbGUiOiJ1c2VyIiwiaXNBY3RpdmUiOnRydWUsImVtYWlsIjoiam9obkBleGFtcGxlLmNvbSIsImZpcnN0TmFtZSI6ImpvaG4iLCJsYXN0TmFtZSI6ImRvZSIsImlzRGVsZXRlZCI6ZmFsc2UsImlhdCI6MTY5ODIxNDg4MywiZXhwIjoxNzI5NzcyNDgzfQ.DRZefS8kzhOYWW_gOLBn66UswSdgwxnRNQE7gVNWK1c
 *                     timeToLive:
 *                       type: number
 *                       format: number
 *                       example: 1516239022
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 200
 *       '401':
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Invalid Token
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 401
 *       404:
 *         description: data not found
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: data not found
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 404
 *       '500':
 *         description: Internal server error
 */
router.post(
  '/refresh-token',
  refreshTokenValidator,
  authController.regenerateAccessToken,
);
/**
 * @swagger
 * /auth/reset-password:
 *   post:
 *     security:
 *       - bearerAuth: []
 *     summary: reset password
 *     description: logged in user can reset their password using this api
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               oldPassword:
 *                 type: string
 *                 format: string
 *                 example: john@123D
 *               newPassword:
 *                  type: string
 *                  format: string
 *                  example: bob@123D'
 *     responses:
 *       '200':
 *         description: updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: updated successfully
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 200
 *       '400':
 *         description: Bad request
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: oldPassword is required
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 400
 *
 *       '401':
 *         description: Invalid Token
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Invalid Token
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 401
 *       '422':
 *         description: Same Password
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: New password can't be same as old password
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 422
 *       500:
 *         description: Internal server error
 */
router.post(
  '/reset-password',
  jwtValidator,
  requestValidator(userValidator.resetpasswordSchema, 'body'),
  authController.resetPassword,
);

/**
 * @swagger
 * /auth/forgot-password:
 *   post:
 *     summary: forgot password
 *     description: |
 *                  - send the otp to user's email if user forgot their password.
 *                  - this api can be also be used to re-generate 3 otp's in one hour.
 *
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 example: john@example.com
 *             example:
 *              email: john@example.com
 *     responses:
 *       '200':
 *         description: Otp sent successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Otp sent successfully
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 200
 *       '401':
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Invalid Email
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 401
 *       '403':
 *         description: Forbidden request
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Max limit 3 to send verification code reached please try after 1 hour
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 403
 *       500:
 *         description: Internal server error
 */
router.post(
  '/forgot-password',
  requestValidator(userValidator.forgotPasswordSchema, 'body'),
  authController.forgotPassword,
);
/**
 * @swagger
 * /auth/forgot-password-verify:
 *   post:
 *     summary: forgot password verify
 *     description: |
 *                  - user's new password must be different from old password.
 *                  - otp is there in user's email.
 *
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 format: string
 *                 example: john@example.com
 *               newPassword:
 *                 type: string
 *                 format: string
 *                 example: 1234567@a
 *               otp:
 *                 type: number
 *                 format: number
 *                 example: 1234
 *     responses:
 *       '200':
 *         description: Updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Updated successfully
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 200
 *       '400':
 *         description: Bad request
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Password must be a valid Password
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 400
 *       '401':
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Invalid Email
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 401
 *       '422':
 *         description: Same Password
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: New password can't be same as old password
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 422
 *       500:
 *         description: Internal server error
 */
router.post(
  '/forgot-password-verify',
  requestValidator(userValidator.verifyForgotPasswordSchema, 'body'),
  authController.forgotPasswordVerify,
);
/**
 * @swagger
 * /auth/generate-reset-password:
 *   post:
 *     summary: send the reset password link
 *     description: |
 *                  - send the password link to user's email if user forgot their password.
 *                  - this api can be also be used to re-generate 3 link's in one hour.
 *
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 example: john@example.com
 *             example:
 *              email: john@example.com
 *     responses:
 *       '200':
 *         description: email sent successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Reset password email sent successfully
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 200
 *       '401':
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Invalid Email
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 401
 *       '403':
 *         description: Forbidden request
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Max limit 3 to send verification code reached please try after 1 hour
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 403
 *       500:
 *         description: Internal server error
 */
router.post(
  '/generate-reset-password',
  requestValidator(userValidator.sendResetPasswordMailSchema, 'body'),
  authController.sendResetPasswordMail,
);
/**
 * @swagger
 * /auth/reset-password-verify:
 *   post:
 *     summary: verify the password using token
 *     description: |
 *                  - user's new password must be different from old password.
 *                  - token also required with user's email.
 *
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 format: string
 *                 example: john@example.com
 *               newPassword:
 *                 type: string
 *                 format: string
 *                 example: 1234567@a
 *               token:
 *                 type: string
 *                 format: string
 *                 example: asdfdsafdsafdsafdsa
 *     responses:
 *       '200':
 *         description: Updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Updated successfully
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 200
 *       '400':
 *         description: Bad request
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Password must be a valid Password
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 400
 *       '401':
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Invalid Email
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 401
 *       '410':
 *         description: Gone
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: The password reset token you are trying to use has expired or is no longer valid.
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 410
 *       '422':
 *         description: Same Password
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: New password can't be same as old password
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 422
 *       500:
 *         description: Internal server error
 */
router.post(
  '/reset-password-verify',
  requestValidator(userValidator.verifyPasswordResetSchema, 'body'),
  authController.verifyResetPassword,
);
/**
 * @swagger
 * /auth/verify-otp:
 *   post:
 *     security:
 *       - bearerAuth: []
 *     summary: verify otp
 *     description: |
 *                  - accepts otp from mobile or email according to specified type.
 *                  - user can verify their otp sent to email or mobile.
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 format: string
 *               mobile:
 *                 type: string
 *                 format: string
 *               otp:
 *                 type: number
 *                 format: number
 *               type:
 *                 type: string
 *                 format: string
 *                 enum:
 *                   - email_verification
 *                   - sms_verification
 *           examples:
 *              email_verification:
 *                value:
 *                  email: 'john@example.com'
 *                  otp: 1234
 *                  type: 'email_verification'
 *              sms_verification:
 *                value:
 *                  mobile: '8880001231'
 *                  otp: 1234
 *                  type: 'sms_verification'
 *
 *     responses:
 *       '200':
 *         description: Otp verification successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Otp verification successful
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 200
 *       '400':
 *         description: Bad request
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: email must be a valid email
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 400
 *       '401':
 *         description: Invalid Otp
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Invalid otp
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 401
 *       '403':
 *         description: Forbidden request
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Email Already Verified
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 403
 *       '422':
 *         description: Invalid Type
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Invalid Type
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 422
 *       '500':
 *         description: Internal server error
 */

router.post(
  '/verify-otp',
  jwtValidator,
  requestValidator(userValidator.verifyOtpSchema, 'body'),
  authController.verifyOtp,
);

/**
 * @swagger
 * /auth/regenerate-otp:
 *   patch:
 *     security:
 *       - bearerAuth: []
 *     summary: regenerate otp
 *     description: |
 *                  - used to regenerate the otp if user didn't got it.
 *                  - maximum 3 otp's can be sent in 1 hour.
 *                  - type of otp must be valid.
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 format: string
 *               mobile:
 *                 type: string
 *                 format: string
 *               type:
 *                 type: string
 *                 format: string
 *                 enum:
 *                   - email_verification
 *                   - sms_verification
 *           examples:
 *              email_verification:
 *                value:
 *                  email: 'john@example.com'
 *                  type: 'email_verification'
 *              sms_verification:
 *                value:
 *                  mobile: '8880001231'
 *                  type: 'sms_verification'
 *     responses:
 *       '200':
 *         description: Otp sent successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Otp sent successfully
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 200
 *       '400':
 *         description: Bad request
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Email must be a valid email
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 400
 *       '401':
 *         description: Invalid Token or Invalid Email
 *         content:
 *           application/json:
 *             examples:
 *               'Invalid Token':
 *                 value:
 *                   message: Invalid Token
 *                   data: {}
 *                   status: 401
 *               'Invalid Email':
 *                 value:
 *                   message: Invalid Email
 *                   data: {}
 *                   status: 401
 *       '403':
 *         description: Forbidden request
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Max limit 3 to send verification code reached please try after 1 hour
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 403
 *       '422':
 *         description: Invalid Type
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Invalid Type
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 422
 *       '500':
 *         description: Internal server error
 */
router.patch(
  '/regenerate-otp',
  jwtValidator,
  requestValidator(userValidator.regenerateOtpSchema, 'body'),
  authController.regenerateOtp,
);

/**
 * @swagger
 * /auth/2fa:
 *   post:
 *     security:
 *       - bearerAuth: []
 *     summary: 2FA enable or disable
 *     description: |
 *                  - Enable 2FA or Disable 2FA api if user is logged in.
 *                  - Google Authenticator app must be used to scan the qr code.
 *                  - 6 digit otp(generated in google authenticator app) requires in verify 2FA api, after that user can login.
 *                  - user token will not generate if 2FA is not verified.
 *                  - disable two-factor for logged in user
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 format: string
 *               enable:
 *                 type: boolean
 *                 format: boolean
 *           examples:
 *              enable:
 *                value:
 *                  email: 'john@example.com'
 *                  enable: true
 *              disable:
 *                value:
 *                  email: 'john@example.com'
 *                  enable: false
 *     responses:
 *       '200':
 *         description: 2FA Enabled Successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: 2FA Enabled Successfully
 *                 data:
 *                   type: object
 *                   format: object
 *                   properties:
 *                     qrCode:
 *                       type: string
 *                       format: string
 *                       example: data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAALQAAAC0CAYAAAA9zQYyAAAAAklEQVR4AewaftIAAAeTSURBVO3BQY4cy5LAQDLQ978yR0tfJZCoaj39GDezP1jrEoe1LnJY6yKHtS5yWOsih7UucljrIoe1LnJY6yKHtS5yWOsih7UucljrIoe1LnJY6yKHtS7yw4dU/qaKJypTxd+kMlU8UZkqJpWp4hMqTyomlb+p4hOHtS5yWOsih7Uu8sOXVXyTyhsVk8pUMalMFZPKVDGpTBWTylTxROU3VXyi4ptUvumw1kUOa13ksNZFfvhlKm9UfFPFpDJVvKEyVXyi4jepTBWTylTxhsobFb/psNZFDmtd5LDWRX74f07ljYonKk9U3qj4RMX/J4e1LnJY6yKHtS7yw2VUPlExqXyiYlJ5UvFE5UnFE5Wp4iaHtS5yWOsih7Uu8sMvq/hNKk8qJpWpYlKZKiaVN1SeVEwqU8VUMalMKlPFE5Wp4o2Kf8lhrYsc1rrIYa2L/PBlKv+likllqphUpopJZaqYVKaKSWWqmFSmikllqnhSMalMFZPKGyr/ssNaFzmsdZHDWhexP7iYylTxTSpTxROVqWJSmSomlTcq/j85rHWRw1oXOax1kR8+pDJVPFGZKiaVJxWTyhsqTyqeqEwVk8pU8UbFpDJVTCpvqLxRMalMFf+Sw1oXOax1kcNaF/nhl6k8UZkqvqniicqk8jepvKEyVTxRmSreUHmi8qTiicpU8YnDWhc5rHWRw1oXsT/4D6l8omJSeVIxqUwVb6i8UTGpTBWTylQxqUwVT1SmikllqphUflPFJw5rXeSw1kUOa13E/uADKlPFpPKkYlKZKp6oTBWfUHmj4onKVPFEZap4Q2WqeKLyRsWkMlX8lw5rXeSw1kUOa13khy9TmSo+oTJVTBVvqEwVTyqeqDypmFSmiqniN6k8qZhUnlQ8UXmj4hOHtS5yWOsih7UuYn/wRSpPKiaVqeKJypOKJypTxROVqeKJylTxCZWp4onKk4pJ5Y2KJypvVHzTYa2LHNa6yGGti/zwj1N5UvFE5YnKVPGGyhOVT1RMKk8qvqniicpUMan8TYe1LnJY6yKHtS7yw5dVTCpPKiaVqWJSeaIyVUwqT1TeqJhUnlRMKlPFN6k8qXhD5Y2Kv+mw1kUOa13ksNZF7A8+oDJVfJPKVPFE5RMV36QyVbyhMlVMKlPFpDJVTCpTxTepTBWTylTxicNaFzmsdZHDWhf54UMVk8obFZPKVDGpTBVPKiaVN1S+SeVJxVTxpGJSmSomlaliUvmmiknlNx3WushhrYsc1rrID19WMalMFZPKVDGpvFExqUwVk8qTiknlScWkMlU8UZkqJpWp4onKVPFGxaQyVUwq/6XDWhc5rHWRw1oXsT/4gMqTit+k8qRiUpkqvkllqnhDZap4ojJVTCpvVEwqU8UbKlPFpDJVfOKw1kUOa13ksNZF7A/+QypTxaTypGJSmSomlScVT1Q+UTGpfKJiUnmj4onKN1X8psNaFzmsdZHDWhf54UMqb1Q8UZkqJpUnFZ9Q+UTFpPKkYlJ5UjGpTBVvqEwVb1RMKlPFpPKk4hOHtS5yWOsih7UuYn/wAZUnFZPKJyreUHlSMal8U8WkMlX8JpWp4hMqb1Q8UZkqPnFY6yKHtS5yWOsiP3xZxaTyiYpJ5Y2KJypPKt5QeUPljYpJ5Q2VNyqeVPxLDmtd5LDWRQ5rXeSHD1VMKlPFpDJVPFF5o+ITFU9Upoqp4knFpDJVTCpPKiaVJxXfpPKk4m86rHWRw1oXOax1kR++rGJS+UTFpDJVfJPKVPFE5UnFJyreqJhUnqhMFZPKVPFE5YnKbzqsdZHDWhc5rHWRHz6kMlVMFZPKpPJGxaQyVTxRmSomlUllqnhD5UnFpDJVfJPKb6p4UjGpfNNhrYsc1rrIYa2L/PChikllqnij4jdVTCpTxROVqeKNikllqphUpoonKk8qnqhMFZPKk4pJ5UnFNx3WushhrYsc1rrIDx9SeaIyVbyhMlVMFU9Upoqp4o2Kv6niicpU8YbKE5VvqvhNh7UucljrIoe1LmJ/8D9MZaqYVJ5UTCpTxb9E5RMVk8pU8YbKVPFfOqx1kcNaFzmsdRH7gw+o/E0VT1SmiicqU8Wk8kbFpPKkYlKZKp6oTBWTyhsVk8pUMal8U8UnDmtd5LDWRQ5rXeSHL6v4JpUnKr+p4onKpPKkYlKZKiaVqWKqmFSmiicqTyreqJhUpopJ5ZsOa13ksNZFDmtd5IdfpvJGxRsVT1Smiqniicp/qWJSmSq+SeUTKlPFk4pvOqx1kcNaFzmsdZEf/sepPKmYVJ5UTBWTypOKSWVSmSomlaliqnhDZap4UvFE5Q2VqeI3Hda6yGGtixzWusgP/+MqJpVJZaqYVD5R8S+pmFQmlU9UTCpTxaTyRGWq+MRhrYsc1rrIYa2L2B98QGWq+CaVqeI3qTypmFT+ZRVPVKaKSeUTFX/TYa2LHNa6yGGti/zwZSp/k8qTiicqU8WkMql8omJSmSo+ofJGxZOKSeVJxaTyRsUnDmtd5LDWRQ5rXcT+YK1LHNa6yGGtixzWushhrYsc1rrIYa2LHNa6yGGtixzWushhrYsc1rrIYa2LHNa6yGGtixzWusj/Ae54BHcwrq1LAAAAAElFTkSuQmCC
 *                     backupCode:
 *                       type: string
 *                       format: string
 *                       example: YlKyDYzfXZorEuMwVWjvcTjO
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 200
 *       '400':
 *         description: Bad request
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: email must be a valid email
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 400
 *       '401':
 *         description: Invalid Email Or Token
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Invalid Email
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 401
 *       '403':
 *         description: 2FA Not Enabled
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: 2FA Not Enabled
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 403
 *       '500':
 *         description: Internal server error
 */
router.post(
  '/2fa',
  jwtValidator,
  requestValidator(userValidator.twoFASchema, 'body'),
  authController.twoFA,
);

/**
 * @swagger
 * /auth/2fa-verify:
 *   post:
 *     summary: verify 2FA
 *     description: |
 *                  - verify 2fa, using the code generated in google authenticator app.
 *                  - updates the session variable to true default for 1 min.
 *                  - after login one time the session variable will be false.
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 format: string
 *                 example: john@example.com
 *               code:
 *                 type: string
 *                 format: string
 *                 example: '123456'
 *     responses:
 *       '200':
 *         description: 2FA verification Successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: 2FA verification Successful
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 200
 *       '400':
 *         description: Bad request
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Email must be valid email
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: integer
 *                   format: integer
 *                   example: 400
 *       '401':
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: 2FA Verification Failed
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 401
 *       '403':
 *         description: 2FA Not Enabled
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: 2FA Not Enabled
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 403
 *       '500':
 *         description: Internal server error
 */
router.post(
  '/2fa-verify',
  requestValidator(userValidator.verify2FASchema, 'body'),
  authController.verify2FA,
);

/**
 * @swagger
 * /auth/2fa-disable:
 *   patch:
 *     summary: 2FA disable using back-up code
 *     description: |
 *                  - this api is used in case user lost their device or removed their authenticator code from application.
 *                  - user can disable two-factor using back-up code generated at the time of enabling two-factor authentication.
 *                  - backup code is 24 character long.
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 format: string
 *                 example: john@example.com
 *               backupCode:
 *                 type: string
 *                 format: string
 *                 example: PA4EY6KYIFLT4LZ2KQ2ESYJZ
 *     responses:
 *       '200':
 *         description: 2FA disabled Successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: 2FA disabled Successfully
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 200
 *       '400':
 *         description: Bad request
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: email must be a valid email
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 400
 *       '401':
 *         description: Invalid Email Or Token Or Backup Code
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Invalid Email
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 401
 *       '403':
 *         description: 2FA Not Enabled
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: 2FA Not Enabled
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 403
 *       '500':
 *         description: Internal server error
 */
router.patch(
  '/2fa-disable',
  requestValidator(userValidator.disable2FASchema, 'body'),
  authController.disable2FA,
);

/**
 * @swagger
 * /auth/facebook:
 *   post:
 *     summary: Authenticate with Facebook
 *     description: Authenticate a user using a Facebook access token.
 *     tags: [Auth]
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               accessToken:
 *                 type: string
 *                 example: EAANjS4TYZA8wBOwtzElWkA71tzkRy0NX2ZADkUJlhJMHnEYRZB2NL9eikgEFZB2XADZAzd6zClyQB6ErkaIWbvc4ZBAYcAiGV6YVnhyEiSNodokytPAhC7jSBAaup41JJSZCLa5NiNw9dOFuhfEu7CpjJKrWEv2CjfdNaLq4j3ZAkacQpZBwiwXzgZAkHriqqo54gd1wZDZD
 *               email:
 *                 type: string
 *                 example: john@example.com
 *     responses:
 *       '200':
 *         description: Facebook authentication successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Facebook authentication successful
 *                 data:
 *                   type: object
 *                   format: object
 *                   properties:
 *                     id:
 *                       type: string
 *                       format: string
 *                       example: 12
 *                     email:
 *                       type: string
 *                       format: email
 *                       example: user00@yopmail1.com
 *                     role:
 *                       type: string
 *                       format: string
 *                       example: user
 *                     firstName:
 *                       type: string
 *                       format: string
 *                       example: john
 *                     lastName:
 *                       type: string
 *                       format: string
 *                       example: doe
 *                     authType:
 *                       type: string
 *                       format: string
 *                       example: facebook
 *                     token:
 *                       type: string
 *                       format: string
 *                       example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjUwMDAxIiwicm9sZSI6ImNvbGxlY3RvciIsImNyZWF0ZWRfYXQiOiIyMDIzLTA2LTA1VDA4OjA0OjI3LjI2MloiLCJpYXQiOjE2ODY4MzcxODUsImV4cCI6MTY4Njg0MDE4NX0.I1nPBNwiyi--dOcaEcSOCqvi2WqjO2Av-68HaXlaeOw
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 200
 *       '400':
 *         description: Invalid request or missing access token
 *       '401':
 *         description: Unauthorized access or invalid access token
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Unauthorized
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 401
 *       '500':
 *         description: Internal server error
 */
router.post(
  '/facebook',
  requestValidator(userValidator.facebookLoginSchema, 'body'),
  authController.facebookLogin,
);

/**
 * @swagger
 * /auth/google:
 *   post:
 *     summary: Authenticate with google
 *     description: Authenticate a user using a google access token.
 *     tags: [Auth]
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               accessToken:
 *                 type: string
 *                 example: ya29.a0AfB_byB8jdA1qqnY4ZMGVVTAmU3I5X57Vjj7hK5EfbqXL9nmM_igBY6cajBwXz-K1tCp6wy_zkeW1SkIXWQVJMIG_fZSg2zJRlj9YwynnZEiAGCKbrlj6w7fgFKJIt_YbnAxbDgF-WyNf9e_u_NlVpuWXdsv2oyB2dg9aCgYKAZISARMSFQGOcNnCEcqm8__BalLrMcncpR2Maw0171
 *     responses:
 *       '200':
 *         description: Google authentication successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Google Authentication successful
 *                 data:
 *                   type: object
 *                   format: object
 *                   properties:
 *                     id:
 *                       type: number
 *                       format: number
 *                       example: 12
 *                     email:
 *                       type: string
 *                       format: string
 *                       example: john@example.com
 *                     role:
 *                       type: string
 *                       format: string
 *                       example: user
 *                     authType:
 *                       type: string
 *                       format: string
 *                       example: google
 *                     isActive:
 *                       type: boolean
 *                       format: boolean
 *                       example: true
 *                     firstName:
 *                       type: string
 *                       format: string
 *                       example: john
 *                     lastName:
 *                       type: string
 *                       format: string
 *                       example: doe
 *                     isVerified:
 *                       type: boolean
 *                       format: boolean
 *                       example: true
 *                     token:
 *                       type: string
 *                       format: string
 *                       example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MTYsInJvbGUiOiJ1c2VyIiwiaXNBY3RpdmUiOnRydWUsImVtYWlsIjoiam9obkBleGFtcGxlLmNvbSIsImZpcnN0TmFtZSI6ImpvaG4iLCJsYXN0TmFtZSI6ImRvZSIsImlzRGVsZXRlZCI6ZmFsc2UsImlhdCI6MTY5ODIxNDg4MywiZXhwIjoxNzI5NzcyNDgzfQ.DRZefS8kzhOYWW_gOLBn66UswSdgwxnRNQE7gVNWK1c
 *                     isTwoFAEnabled:
 *                       type: boolean
 *                       format: boolean
 *                       example: true
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 200
 *       '400':
 *         description: Invalid request or missing access token
 *       '401':
 *         description: Unauthorized access or invalid access token
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Unauthorized
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 401
 *       '500':
 *         description: Internal server error
 */
router.post(
  '/google',
  requestValidator(userValidator.googleLoginSchema, 'body'),
  authController.googleLogin,
);

/**
 * @swagger
 * /auth/apple:
 *   post:
 *     summary: Authenticate with apple
 *     description: Authenticate a user using a apple id token.
 *     tags: [Auth]
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               accessToken:
 *                 type: string
 *                 example: eyJraWQiOiJZdXlYb1kiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoiVlJTaWduSW4iLCJleHAiOjE2OTg0OTEyOTYsImlhdCI6MTY5ODQwNDg5Niwic3ViIjoiMDAwMjUwLjk3OWIyZjNjY2YzZTQ5ZmRhOWE3YTY2YzE4YzJlYWYyLjEwMjAiLCJub25jZSI6InRlc3QiLCJjX2hhc2giOiJLYWJGZjNnbnhQS29EODJybHptS19nIiwiZW1haWwiOiJqYXJqaXQwM0BnbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6InRydWUiLCJhdXRoX3RpbWUiOjE2OTg0MDQ4OTYsIm5vbmNlX3N1cHBvcnRlZCI6dHJ1ZX0.tKlYTgtB06oChs3okcPWpyh8g5FdbYMv7AR5lMZL4ljc6jFEblBVSGXTDxHHef2HEVQnepxT4F5swG8IVTzKPU7jGH5Mzgb1oHXSw9h5PDcm_l7TaQ8NkHIJ-8cJh_CN_hPnOLDWGT0IiKpQBfR18_3YG-xWBm8vRMbvMQmdt5zLYkLkLojYo_LTCDYFJ7hHCB2DIn0aXHKoOY5ot94gPILF0v4rSLU0uIY0kdHM40VnXDNj37Z7PXV75i1VTbO6moz8428PPiBhRVPZlL4fD92UbOzhynppbq-Cc0dCn59qfBSJqaWm0lhwb2oPEdXOKAagd5KvxpHtDamGvOO7eg
 *     responses:
 *       '200':
 *         description: Apple authentication successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Apple Authentication successful
 *                 data:
 *                   type: object
 *                   format: object
 *                   properties:
 *                     id:
 *                       type: number
 *                       format: number
 *                       example: 12
 *                     email:
 *                       type: string
 *                       format: string
 *                       example: john@example.com
 *                     role:
 *                       type: string
 *                       format: string
 *                       example: user
 *                     authType:
 *                       type: string
 *                       format: string
 *                       example: apple
 *                     isActive:
 *                       type: boolean
 *                       format: boolean
 *                       example: true
 *                     firstName:
 *                       type: string
 *                       format: string
 *                       example: john
 *                     lastName:
 *                       type: string
 *                       format: string
 *                       example: doe
 *                     isVerified:
 *                       type: boolean
 *                       format: boolean
 *                       example: true
 *                     token:
 *                       type: string
 *                       format: string
 *                       example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MTYsInJvbGUiOiJ1c2VyIiwiaXNBY3RpdmUiOnRydWUsImVtYWlsIjoiam9obkBleGFtcGxlLmNvbSIsImZpcnN0TmFtZSI6ImpvaG4iLCJsYXN0TmFtZSI6ImRvZSIsImlzRGVsZXRlZCI6ZmFsc2UsImlhdCI6MTY5ODIxNDg4MywiZXhwIjoxNzI5NzcyNDgzfQ.DRZefS8kzhOYWW_gOLBn66UswSdgwxnRNQE7gVNWK1c
 *                     isTwoFAEnabled:
 *                       type: boolean
 *                       format: boolean
 *                       example: true
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 200
 *       '400':
 *         description: Invalid request or missing access token
 *       '401':
 *         description: Unauthorized access or invalid access token
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Unauthorized
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 401
 *       '500':
 *         description: Internal server error
 */
router.post(
  '/apple',
  requestValidator(userValidator.appleLoginSchema, 'body'),
  authController.appleLogin,
);

/**
 * @swagger
 * /auth/linkedin:
 *   post:
 *     summary: Authenticate with linkedin
 *     description: Authenticate a user using a linkedin access token.
 *     tags: [Auth]
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               accessToken:
 *                 type: string
 *                 example: AQVTmkG0MKDi6XTAgsK4LhL8M79fdmVX6l4ReyIdNLzFS8NU9TH4YmaTUb8YmbMGBkhYIqaqaDxR8_OaJlEPOELUpAA1tXTJtvwxQwi49lYw2zxu0IuOw8wtoieLeB4QvgYIdqEVoyPr3v0PPXIPhqW4OXWTJinU0NL52H9FkwjwA3kFtxAzd83Ju4ukZ2eO1wzn8nVcBCGXh4dWtq5p0crr71RtzWlIMzMtn8tOKDeUThkMlmX99TGgIopwyld0v7YNUuQcykhVtpYveHU4H6hffzup-Vb0feeA2ptuKgjIybd49hEIP_pXY9b4O42e08cNVDRCl8vdVzIm6B8kJ1g0cgLI7w
 *     responses:
 *       '200':
 *         description: Linkedin authentication successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Linkedin authentication successful
 *                 data:
 *                   type: object
 *                   format: object
 *                   properties:
 *                     id:
 *                       type: number
 *                       format: number
 *                       example: 12
 *                     email:
 *                       type: string
 *                       format: string
 *                       example: john@example.com
 *                     role:
 *                       type: string
 *                       format: string
 *                       example: user
 *                     authType:
 *                       type: string
 *                       format: string
 *                       example: linkedin
 *                     isActive:
 *                       type: boolean
 *                       format: boolean
 *                       example: true
 *                     firstName:
 *                       type: string
 *                       format: string
 *                       example: john
 *                     lastName:
 *                       type: string
 *                       format: string
 *                       example: doe
 *                     isVerified:
 *                       type: boolean
 *                       format: boolean
 *                       example: true
 *                     token:
 *                       type: string
 *                       format: string
 *                       example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MTYsInJvbGUiOiJ1c2VyIiwiaXNBY3RpdmUiOnRydWUsImVtYWlsIjoiam9obkBleGFtcGxlLmNvbSIsImZpcnN0TmFtZSI6ImpvaG4iLCJsYXN0TmFtZSI6ImRvZSIsImlzRGVsZXRlZCI6ZmFsc2UsImlhdCI6MTY5ODIxNDg4MywiZXhwIjoxNzI5NzcyNDgzfQ.DRZefS8kzhOYWW_gOLBn66UswSdgwxnRNQE7gVNWK1c
 *                     isTwoFAEnabled:
 *                       type: boolean
 *                       format: boolean
 *                       example: true
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 200
 *       '400':
 *         description: Invalid request or missing access token
 *       '401':
 *         description: Unauthorized access or invalid access token
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Unauthorized
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 401
 *       '500':
 *         description: Internal server error
 */
router.post(
  '/linkedin',
  requestValidator(userValidator.linkedinLoginSchema, 'body'),
  authController.linkedinLogin,
);

/**
 * @swagger
 * /auth/github:
 *   post:
 *     summary: Authenticate with github
 *     description: Authenticate a user using a github access token.
 *     tags: [Auth]
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               accessToken:
 *                 type: string
 *                 example: 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
 *     responses:
 *       '200':
 *         description: Github authentication successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Github authentication successful
 *                 data:
 *                   type: object
 *                   format: object
 *                   properties:
 *                     id:
 *                       type: number
 *                       format: number
 *                       example: 12
 *                     email:
 *                       type: string
 *                       format: string
 *                       example: john@example.com
 *                     role:
 *                       type: string
 *                       format: string
 *                       example: user
 *                     authType:
 *                       type: string
 *                       format: string
 *                       example: github
 *                     isActive:
 *                       type: boolean
 *                       format: boolean
 *                       example: true
 *                     firstName:
 *                       type: string
 *                       format: string
 *                       example: john
 *                     lastName:
 *                       type: string
 *                       format: string
 *                       example: doe
 *                     isVerified:
 *                       type: boolean
 *                       format: boolean
 *                       example: true
 *                     token:
 *                       type: string
 *                       format: string
 *                       example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MTYsInJvbGUiOiJ1c2VyIiwiaXNBY3RpdmUiOnRydWUsImVtYWlsIjoiam9obkBleGFtcGxlLmNvbSIsImZpcnN0TmFtZSI6ImpvaG4iLCJsYXN0TmFtZSI6ImRvZSIsImlzRGVsZXRlZCI6ZmFsc2UsImlhdCI6MTY5ODIxNDg4MywiZXhwIjoxNzI5NzcyNDgzfQ.DRZefS8kzhOYWW_gOLBn66UswSdgwxnRNQE7gVNWK1c
 *                     isTwoFAEnabled:
 *                       type: boolean
 *                       format: boolean
 *                       example: true
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 200
 *       '400':
 *         description: Invalid request or missing access token
 *       '401':
 *         description: Unauthorized access or invalid access token
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Unauthorized
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 401
 *       '500':
 *         description: Internal server error
 */
router.post(
  '/github',
  requestValidator(userValidator.githubLoginSchema, 'body'),
  authController.githubLogin,
);

/**
 * @swagger
 * /auth/twitter:
 *   post:
 *     summary: Authenticate with twitter
 *     description: Authenticate a user using a twitter access token.
 *     tags: [Auth]
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               accessToken:
 *                 type: string
 *                 example: SVQxbHFwc29KUzN2d0plTGZmVFYtbkxlZHhJb1RFMFk4M3U4dzN0MkNGMjN0OjE2OTg5OTIzMzk2ODU6MTowOmF0OjE
 *               email:
 *                 type: string
 *                 example: john@example.com
 *     responses:
 *       '200':
 *         description: Twitter authentication successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Twitter authentication successful
 *                 data:
 *                   type: object
 *                   format: object
 *                   properties:
 *                     id:
 *                       type: number
 *                       format: number
 *                       example: 12
 *                     email:
 *                       type: string
 *                       format: string
 *                       example: john@example.com
 *                     role:
 *                       type: string
 *                       format: string
 *                       example: user
 *                     authType:
 *                       type: string
 *                       format: string
 *                       example: twitter
 *                     isActive:
 *                       type: boolean
 *                       format: boolean
 *                       example: true
 *                     firstName:
 *                       type: string
 *                       format: string
 *                       example: john
 *                     lastName:
 *                       type: string
 *                       format: string
 *                       example: doe
 *                     isVerified:
 *                       type: boolean
 *                       format: boolean
 *                       example: true
 *                     token:
 *                       type: string
 *                       format: string
 *                       example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MTYsInJvbGUiOiJ1c2VyIiwiaXNBY3RpdmUiOnRydWUsImVtYWlsIjoiam9obkBleGFtcGxlLmNvbSIsImZpcnN0TmFtZSI6ImpvaG4iLCJsYXN0TmFtZSI6ImRvZSIsImlzRGVsZXRlZCI6ZmFsc2UsImlhdCI6MTY5ODIxNDg4MywiZXhwIjoxNzI5NzcyNDgzfQ.DRZefS8kzhOYWW_gOLBn66UswSdgwxnRNQE7gVNWK1c
 *                     isTwoFAEnabled:
 *                       type: boolean
 *                       format: boolean
 *                       example: true
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 200
 *       '400':
 *         description: Invalid request or missing access token
 *       '401':
 *         description: Unauthorized access or invalid access token
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Unauthorized
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 401
 *       '429':
 *         description: Too many request
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Too many request
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 429
 *       '500':
 *         description: Internal server error
 */
router.post(
  '/twitter',
  requestValidator(userValidator.twitterLoginSchema, 'body'),
  authController.twitterLogin,
);

/**
 * @swagger
 * /auth/reddit:
 *   post:
 *     summary: Authenticate with reddit
 *     description: Authenticate a user using a reddit access token.
 *     tags: [Auth]
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               accessToken:
 *                 type: string
 *                 format: string
 *                 example: eyJhbGciOiJSUzI1NiIsImtpZCI6IlNIQTI1NjpzS3dsMnlsV0VtMjVmcXhwTU40cWY4MXE2OWFFdWFyMnpLMUdhVGxjdWNZIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1c2VyIiwiZXhwIjoxNjk5MDIxMTQ1Ljk1MTAyNywiaWF0IjoxNjk4OTM0NzQ1Ljk1MTAyNywianRpIjoibTdVdlF4eEtVZDVDVTF4SDNQQ2ZRY2w2QkpqVGZnIiwiY2lkIjoiYk8wQ3o4bWx3TjhQNk9wUkpVNWZTdyIsImxpZCI6InQyX2ZxajJvd215cCIsImFpZCI6InQyX2ZxajJvd215cCIsImxjYSI6MTY4OTY5OTIxOTAwMCwic2NwIjoiZUp5S1ZrcE1UczR2elN0UjBsRXFMazNLelFReE1sTlM4MG95U3lxVllnRUJBQURfXzZvLUNzZyIsInJjaWQiOiJpeThXb2pBTzlFTjdhMEZnWmx4bXFZWTVWUThGRjBiWWVOcUE0ZGpZbk0wIiwiZmxvIjo4fQ.a1sc46geG5eVFdMBPnuGlRIymgeuQPAcjY4QEHGD1vR_7iywdjQkv86IVWvT1Dz-NY-nh6bs-dkD34OwmcVcykhCrBxd3nj5v8B-XHLuK2Sf9kPy7DQsifpnDaXT4k6yTWePYnIc_CVxZiB9dae8NuzR7Urbfw5j_JcOG_zRmne0QVM2FUnhIh1Ui3UUWrEnuayFleDVmvbRxmx4FPGwQWZ7EH_uhW9SprdjQnEkXyAOF5YRxLoHRSo0BjsWAgxbqPP7GxEzdyVzgOuRg3PWXyxsgrD2YNjkzGN2wMXAeGGVNcZDx9Sq4C5BQZQIbDwoyC2mmWQXQ9HJHYAsbDbyyQ
 *               email:
 *                 type: string
 *                 format: string
 *                 example: john@example.com
 *     responses:
 *       '200':
 *         description: Reddit authentication successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Reddit authentication successful
 *                 data:
 *                   type: object
 *                   format: object
 *                   properties:
 *                     id:
 *                       type: number
 *                       format: number
 *                       example: 12
 *                     email:
 *                       type: string
 *                       format: string
 *                       example: john@example.com
 *                     role:
 *                       type: string
 *                       format: string
 *                       example: user
 *                     authType:
 *                       type: string
 *                       format: string
 *                       example: reddit
 *                     isActive:
 *                       type: boolean
 *                       format: boolean
 *                       example: true
 *                     firstName:
 *                       type: string
 *                       format: string
 *                       example: john
 *                     lastName:
 *                       type: string
 *                       format: string
 *                       example: doe
 *                     isVerified:
 *                       type: boolean
 *                       format: boolean
 *                       example: true
 *                     token:
 *                       type: string
 *                       format: string
 *                       example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MTYsInJvbGUiOiJ1c2VyIiwiaXNBY3RpdmUiOnRydWUsImVtYWlsIjoiam9obkBleGFtcGxlLmNvbSIsImZpcnN0TmFtZSI6ImpvaG4iLCJsYXN0TmFtZSI6ImRvZSIsImlzRGVsZXRlZCI6ZmFsc2UsImlhdCI6MTY5ODIxNDg4MywiZXhwIjoxNzI5NzcyNDgzfQ.DRZefS8kzhOYWW_gOLBn66UswSdgwxnRNQE7gVNWK1c
 *                     isTwoFAEnabled:
 *                       type: boolean
 *                       format: boolean
 *                       example: true
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 200
 *       '400':
 *         description: Invalid request or missing access token
 *       '401':
 *         description: Unauthorized access or invalid access token
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Unauthorized
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 401
 *       '500':
 *         description: Internal server error
 */
router.post(
  '/reddit',
  requestValidator(userValidator.redditLoginSchema, 'body'),
  authController.redditLogin,
);

/**
 * @swagger
 * /auth/yahoo:
 *   post:
 *     summary: Authenticate with yahoo
 *     description: Authenticate a user using a yahoo access token.
 *     tags: [Auth]
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               accessToken:
 *                 type: string
 *                 format: string
 *                 example: _hxWU.Of4h1Zoa.Edl..Y6fzaIztwHIiHAmQnbzKeqGW_YJDrwMlJ.2_utCfAfAOd3FrFqaIX.CS6j0VVeKisXQVGyacy0yq0Qb5qxowp1v8NgiwlBj4pc_tL7sS0pQBqMft0Q6JzIBtA4syFLP4DxPu.49MaW9G3Lb1DZH.x6Q0D368bwlW4qQRd2RoTvOv.f5AZO5OspqLiH655YBXC9gofUPq2br6YizhxAsFHC7d9t7Fr3TMRx5QaeBHQdLmPdirc1zSOO3eAEac9qeIDfNp0hgcyI.1xDPhTEd42dZDFvs1X2jlB_gSjGWWemF6PWB57tCek7yDV8fvHTr_CFCslq70FAoBHn5yel7MrW8kZgMBOGeuiM3vaW5qxioOO04YQDIHb7dMrd93s6tKse3xpw6ozz1R7VVfivIk6v1UGizt3dYPavj8w1bLp9T1Czr74xpvienKZ429OmIgGKT1GGFud7BObl668cIA2soububcswaQ2EiS6AkcM5QdsJAShc7jW54bLIMKZ_VUDlvE92fAC6Um8ikcqSKNyuaiKlkhvLQ_fnvV2dC_yz7KE5mMePQP8me7hIKAQ2MhzH25UgdFFbHaaJfZHhfbx1x7x88U3cBjc9VNvg5GZSVGJlru6q0Hx0H713H0Avwzezed_dNDj2aNJLNJdVeu.5.E2Pn99OnLa3TwJHrxO42jMguDtExwj8UfpMPvLmNDz0fO90C8EJRA7fTnbpY1cuAbMNtydv50NkrSjzEUyFEPvdM8geGGhodtK7gF314Zc7qXTd6kgY066VPrTw5BNM29WpKddXS0eqEZZ04BBlopRzPzhMhT6id7BPRj6SMSFQQcjkjxoN0E7N4YchUqrg0wfEkQBwPKo0BYlL.tp3VP7ei.GAMG6QK4p8KVVsPrqM2Eh3U8vLnn9xG74WmwyExcPvA8pHcfgPhrbl2_iAbUVCIQHlf.cAokKwOiVETJ..mg5ke2olojYuGz0qPzLQjg9u4Vl8pzMaaeFPBm6vo49JhetrHRIkS.
 *     responses:
 *       '200':
 *         description: Yahoo authentication successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Yahoo authentication successful
 *                 data:
 *                   type: object
 *                   format: object
 *                   properties:
 *                     id:
 *                       type: number
 *                       format: number
 *                       example: 12
 *                     email:
 *                       type: string
 *                       format: string
 *                       example: john@example.com
 *                     role:
 *                       type: string
 *                       format: string
 *                       example: user
 *                     authType:
 *                       type: string
 *                       format: string
 *                       example: yahoo
 *                     isActive:
 *                       type: boolean
 *                       format: boolean
 *                       example: true
 *                     firstName:
 *                       type: string
 *                       format: string
 *                       example: john
 *                     lastName:
 *                       type: string
 *                       format: string
 *                       example: doe
 *                     isVerified:
 *                       type: boolean
 *                       format: boolean
 *                       example: true
 *                     token:
 *                       type: string
 *                       format: string
 *                       example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MTYsInJvbGUiOiJ1c2VyIiwiaXNBY3RpdmUiOnRydWUsImVtYWlsIjoiam9obkBleGFtcGxlLmNvbSIsImZpcnN0TmFtZSI6ImpvaG4iLCJsYXN0TmFtZSI6ImRvZSIsImlzRGVsZXRlZCI6ZmFsc2UsImlhdCI6MTY5ODIxNDg4MywiZXhwIjoxNzI5NzcyNDgzfQ.DRZefS8kzhOYWW_gOLBn66UswSdgwxnRNQE7gVNWK1c
 *                     isTwoFAEnabled:
 *                       type: boolean
 *                       format: boolean
 *                       example: true
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 200
 *       '400':
 *         description: Invalid request or missing access token
 *       '401':
 *         description: Unauthorized access or invalid access token
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Unauthorized
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 401
 *       '500':
 *         description: Internal server error
 */
router.post(
  '/yahoo',
  requestValidator(userValidator.yahooLoginSchema, 'body'),
  authController.yahooLogin,
);

/**
 * @swagger
 * /auth/amazon:
 *   post:
 *     summary: Authenticate with amazon
 *     description: Authenticate a user using a amazon access token.
 *     tags: [Auth]
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               accessToken:
 *                 type: string
 *                 format: string
 *                 example: Atza|IwEBIFiu9tVxGHYQ5so10W9vHZLYJm-5qoYw0uOoCoaZ5ciPiOrDbetvliW9yDa65oGPlDNYuBoqNIdMI-C2M5psjOcGJWPl842paH_X1xKi4kccxfHrWWg95RkasQvRB16bW1j6JRj1YknX7aaHxa0KIRbiF0ErZQasb-JI22wZn9u3VM7AjUkzjsGBVP5hctO6yryeu3-SPJG6oZmvOZCHNcRZRpHhMXyOxNj7xgsS-MoM0JfEQU3eERPR7q3JPtACukS2f7w5vOq3YBoxXpXAcnw19CggiJoIKg_IeHxZxaUA6v2nd1LESPVl6MpQuAJWqtq68xiXe91fISzauDZzcVsysCiwfA0cC7txsez9N0XtymPGOVQZ-aDZdxmHl-5JGkJ4HlJo6_amYzjtAGAOjQKx8cN-kFuVewutiLVr1Zcseg
 *     responses:
 *       '200':
 *         description: Amazon authentication successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Amazon authentication successful
 *                 data:
 *                   type: object
 *                   format: object
 *                   properties:
 *                     id:
 *                       type: number
 *                       format: number
 *                       example: 12
 *                     email:
 *                       type: string
 *                       format: string
 *                       example: john@example.com
 *                     role:
 *                       type: string
 *                       format: string
 *                       example: user
 *                     authType:
 *                       type: string
 *                       format: string
 *                       example: amazon
 *                     isActive:
 *                       type: boolean
 *                       format: boolean
 *                       example: true
 *                     firstName:
 *                       type: string
 *                       format: string
 *                       example: john
 *                     lastName:
 *                       type: string
 *                       format: string
 *                       example: doe
 *                     isVerified:
 *                       type: boolean
 *                       format: boolean
 *                       example: true
 *                     token:
 *                       type: string
 *                       format: string
 *                       example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MTYsInJvbGUiOiJ1c2VyIiwiaXNBY3RpdmUiOnRydWUsImVtYWlsIjoiam9obkBleGFtcGxlLmNvbSIsImZpcnN0TmFtZSI6ImpvaG4iLCJsYXN0TmFtZSI6ImRvZSIsImlzRGVsZXRlZCI6ZmFsc2UsImlhdCI6MTY5ODIxNDg4MywiZXhwIjoxNzI5NzcyNDgzfQ.DRZefS8kzhOYWW_gOLBn66UswSdgwxnRNQE7gVNWK1c
 *                     isTwoFAEnabled:
 *                       type: boolean
 *                       format: boolean
 *                       example: true
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 200
 *       '400':
 *         description: Invalid request or missing access token
 *       '401':
 *         description: Unauthorized access or invalid access token
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Unauthorized
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 401
 *       '500':
 *         description: Internal server error
 */
router.post(
  '/amazon',
  requestValidator(userValidator.amazonLoginSchema, 'body'),
  authController.amazonLogin,
);

/**
 * @swagger
 * /auth/gitlab:
 *   post:
 *     summary: Authenticate with gitlab
 *     description: Authenticate a user using a gitlab access token.
 *     tags: [Auth]
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               accessToken:
 *                 type: string
 *                 format: string
 *                 example: 94d620f73c4cd87540e2b4034cf22c856d358568966dbaedbbcd4436bf710174
 *     responses:
 *       '200':
 *         description: Gitlab authentication successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Gitlab authentication successful
 *                 data:
 *                   type: object
 *                   format: object
 *                   properties:
 *                     id:
 *                       type: number
 *                       format: number
 *                       example: 12
 *                     email:
 *                       type: string
 *                       format: string
 *                       example: john@example.com
 *                     role:
 *                       type: string
 *                       format: string
 *                       example: user
 *                     authType:
 *                       type: string
 *                       format: string
 *                       example: gitlab
 *                     isActive:
 *                       type: boolean
 *                       format: boolean
 *                       example: true
 *                     firstName:
 *                       type: string
 *                       format: string
 *                       example: john
 *                     lastName:
 *                       type: string
 *                       format: string
 *                       example: doe
 *                     isVerified:
 *                       type: boolean
 *                       format: boolean
 *                       example: true
 *                     token:
 *                       type: string
 *                       format: string
 *                       example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MTYsInJvbGUiOiJ1c2VyIiwiaXNBY3RpdmUiOnRydWUsImVtYWlsIjoiam9obkBleGFtcGxlLmNvbSIsImZpcnN0TmFtZSI6ImpvaG4iLCJsYXN0TmFtZSI6ImRvZSIsImlzRGVsZXRlZCI6ZmFsc2UsImlhdCI6MTY5ODIxNDg4MywiZXhwIjoxNzI5NzcyNDgzfQ.DRZefS8kzhOYWW_gOLBn66UswSdgwxnRNQE7gVNWK1c
 *                     isTwoFAEnabled:
 *                       type: boolean
 *                       format: boolean
 *                       example: true
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 200
 *       '400':
 *         description: Invalid request or missing access token
 *       '401':
 *         description: Unauthorized access or invalid access token
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Unauthorized
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 401
 *       '500':
 *         description: Internal server error
 */
router.post(
  '/gitlab',
  requestValidator(userValidator.gitlabLoginSchema, 'body'),
  authController.gitlabLogin,
);

/**
 * @swagger
 * /auth/discord:
 *   post:
 *     summary: Authenticate with discord
 *     description: Authenticate a user using a discord access token.
 *     tags: [Auth]
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               accessToken:
 *                 type: string
 *                 format: string
 *                 example: 94d620f73c4cd87540e2b4034cf22c856d358568966dbaedbbcd4436bf710174
 *     responses:
 *       '200':
 *         description: Discord authentication successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Discord authentication successful
 *                 data:
 *                   type: object
 *                   format: object
 *                   properties:
 *                     id:
 *                       type: number
 *                       format: number
 *                       example: 12
 *                     email:
 *                       type: string
 *                       format: string
 *                       example: john@example.com
 *                     role:
 *                       type: string
 *                       format: string
 *                       example: user
 *                     authType:
 *                       type: string
 *                       format: string
 *                       example: discord
 *                     isActive:
 *                       type: boolean
 *                       format: boolean
 *                       example: true
 *                     firstName:
 *                       type: string
 *                       format: string
 *                       example: john
 *                     lastName:
 *                       type: string
 *                       format: string
 *                       example: doe
 *                     isVerified:
 *                       type: boolean
 *                       format: boolean
 *                       example: true
 *                     token:
 *                       type: string
 *                       format: string
 *                       example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MTYsInJvbGUiOiJ1c2VyIiwiaXNBY3RpdmUiOnRydWUsImVtYWlsIjoiam9obkBleGFtcGxlLmNvbSIsImZpcnN0TmFtZSI6ImpvaG4iLCJsYXN0TmFtZSI6ImRvZSIsImlzRGVsZXRlZCI6ZmFsc2UsImlhdCI6MTY5ODIxNDg4MywiZXhwIjoxNzI5NzcyNDgzfQ.DRZefS8kzhOYWW_gOLBn66UswSdgwxnRNQE7gVNWK1c
 *                     isTwoFAEnabled:
 *                       type: boolean
 *                       format: boolean
 *                       example: true
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 200
 *       '400':
 *         description: Invalid request or missing access token
 *       '401':
 *         description: Unauthorized access or invalid access token
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Unauthorized
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 401
 *       '500':
 *         description: Internal server error
 */
router.post(
  '/discord',
  requestValidator(userValidator.discordLoginSchema, 'body'),
  authController.discordLogin,
);

/**
 * @swagger
 * /auth/microsoft:
 *   post:
 *     summary: Authenticate with microsoft
 *     description: Authenticate a user using a microsoft access token.
 *     tags: [Auth]
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               accessToken:
 *                 type: string
 *                 format: string
 *                 example: EwBgA8l6BAAUs5+HQn0N+h2FxWzLS31ZgQVuHsYAAZldFn0Gv61yUlJcM+4FeVirYPk+79fw4QZIMxCYgKThvF1aJuS8kVgXfLuvsVFN/6jnalX7jFhGqPwwubIotheep2YZWt68UK8QubbkGhXgfSPfe6QGzmxT7g5szMZ88//6EyQ9F335WoaPHKR4CRJweUuD04NXcQZgarjrr5iht0LnHs+cBah7FZHYfrcNS/HnYAEoOR2IB0RoCrn0CEFSqUh3cS3jZfKKGgT2qbxUUx1jPAr5Fj6KBTMJTp85MRzNivjQiwnNo8nDL+ihvKXDq7UL9W7N2aibJ/VXvGf+aCiRaXqVAc5jQ6PV9PbaR+LiaHFvJRyFaBJAmWsXDKwDZgAACBFcoAh1L9UBMAIoppkuUI3Mp7pYbRoAeBkYdVt7Emn1l0fH7peZJykHBFrrXdqij1i9KVX3dMGe78kD4tzDiI6ERPukyp/kE9SHBxZreOp1v0iwn9XxggYQiOktNNJiNnUY29gvsWnp+7Z8/N9jVmV9BAuEX2qJdKzT343nPCt1FVWVy+nH7rufzbUJtAh6rKVKOPFZCamNfG9A3caKHh8wXIIb6eAL5zl+hud3rfhO37gQVosfn/4N4bjl8FNgH2kGp/SgwQniEEcWjCbhU1/BNOfufgtY+1mgJP9OZiDWhyOaHI4T3l+nEvBeoAzXfEUymhVBPW4LYVYKjo2+9RHnRD09O7BVx5ePlV2Uv791EWq6jpT+n4IQ/XCjsq+UujuOnJzZyxU9z4FkdbTjyblSQDkw7km+tVCiTc/TH5CPdKE+aEofcdGXVP443umE8aU0mJFiBcni1VYgj1cnx1GCUKKhGFbPHIl/jRWo/xlNphimuf3neGzDSIP38RoQrfYGb/qhzku3wfgAO+52wxS4c3GfQ4YL0WWPjGdez6UKrIexQJRYKCEEkjuSOx3DKjI6+UBZOxO02Z4+AnT/I81nM1sMjS3eomj19G/w/rBh671DBpQcEHDwLOldjQtanH3gCopDgmDqFYKtRmdxSJEeyQhiPR2i4Zs7wjxcz9e1WZRQkW5qlpIQeFRgmvlwi/ldGNxOZnurkXBlw0xznwfebmibILnsvGfprY37A9II878KXyGsauXQWG0C
 *     responses:
 *       '200':
 *         description: Microsoft authentication successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Microsoft authentication successful
 *                 data:
 *                   type: object
 *                   format: object
 *                   properties:
 *                     id:
 *                       type: number
 *                       format: number
 *                       example: 12
 *                     email:
 *                       type: string
 *                       format: string
 *                       example: john@example.com
 *                     role:
 *                       type: string
 *                       format: string
 *                       example: user
 *                     authType:
 *                       type: string
 *                       format: string
 *                       example: microsoft
 *                     isActive:
 *                       type: boolean
 *                       format: boolean
 *                       example: true
 *                     firstName:
 *                       type: string
 *                       format: string
 *                       example: john
 *                     lastName:
 *                       type: string
 *                       format: string
 *                       example: doe
 *                     isVerified:
 *                       type: boolean
 *                       format: boolean
 *                       example: true
 *                     token:
 *                       type: string
 *                       format: string
 *                       example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MTYsInJvbGUiOiJ1c2VyIiwiaXNBY3RpdmUiOnRydWUsImVtYWlsIjoiam9obkBleGFtcGxlLmNvbSIsImZpcnN0TmFtZSI6ImpvaG4iLCJsYXN0TmFtZSI6ImRvZSIsImlzRGVsZXRlZCI6ZmFsc2UsImlhdCI6MTY5ODIxNDg4MywiZXhwIjoxNzI5NzcyNDgzfQ.DRZefS8kzhOYWW_gOLBn66UswSdgwxnRNQE7gVNWK1c
 *                     isTwoFAEnabled:
 *                       type: boolean
 *                       format: boolean
 *                       example: true
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 200
 *       '400':
 *         description: Invalid request or missing access token
 *       '401':
 *         description: Unauthorized access or invalid access token
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Unauthorized
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 401
 *       '500':
 *         description: Internal server error
 */
router.post(
  '/microsoft',
  requestValidator(userValidator.microsoftLoginSchema, 'body'),
  authController.microsoftLogin,
);

export default router;
