import appleSigIn from 'apple-signin-auth';
import axios from 'axios';
import { Request, Response } from 'express';

import logger from '../config/logger';
import { Constants } from '../const/constants';
import { IUserData } from '../db/entity/users';
import authService from '../service/auth.service';
import apiHandler from '../utils/ApiHandler';
import emailTrigger from '../utils/EmailTrigger';
import { sendOtp } from '../utils/sendOtp';
class AuthController {
  async register(req: Request, res: Response) {
    try {
      logger.info(
        `Auth Controller : register , req-body ${JSON.stringify(req.body)}`,
      );
      const { email, firstName, lastName, password, mobile } = req.body;
      const userData = { email, firstName, lastName, password, mobile };
      const response = await authService.register(userData);
      if (!response) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.USER_ALREADY_EXIST,
          Constants.Http.CONFLICT,
          res,
        );
      }
      return apiHandler.responseHandler(
        {},
        Constants.SuccessMessage.REGISTER_SUCCESS,
        Constants.Http.CREATED,
        res,
      );
    } catch (error) {
      logger.error(error);
      return apiHandler.errorHandler(error, res);
    }
  }
  async login(req: Request, res: Response) {
    try {
      logger.info(
        `Auth Controller : login , req-body ${JSON.stringify(req.body)}`,
      );
      const { email, password, token } = req.body;
      let isTwoFactorVerified = req.session.isTwoFactorVerified;
      if (req.session.userEmail !== email) {
        isTwoFactorVerified = false;
      }
      const userData = { email, password, token, isTwoFactorVerified };
      const response = await authService.login(userData);
      if (!response) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.USER_NOT_FOUND,
          Constants.Http.UNAUTHORIZED,
          res,
        );
      }
      if (response == Constants.ErrorMessage.USER_NOT_ACTIVE) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.USER_NOT_ACTIVE,
          Constants.Http.UNAUTHORIZED,
          res,
        );
      }
      req.session.isTwoFactorVerified = false;
      return apiHandler.responseHandler(
        response,
        Constants.SuccessMessage.LOGIN_SUCCESS,
        Constants.Http.OK,
        res,
      );
    } catch (error) {
      logger.error(error);
      return apiHandler.errorHandler(error, res);
    }
  }
  async regenerateAccessToken(req: Request, res: Response) {
    try {
      logger.info(
        `Auth Controller : regenerateAccessToken , req-body ${JSON.stringify(
          req.body,
        )}`,
      );
      const { id } = req.body.jwtDecodedUser;
      const response = await authService.regenerateAccessToken(id);
      const header = req.headers?.authorization;
      const refreshToken = header.split(' ')[1];

      if (!response) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.DATA_NOT_FOUND,
          Constants.Http.NOT_FOUND,
          res,
        );
      }
      return apiHandler.responseHandler(
        { ...response, refreshToken },
        Constants.SuccessMessage.GENERATED_SUCCESSFULLY,
        Constants.Http.OK,
        res,
      );
    } catch (error) {
      logger.error(error);
      return apiHandler.errorHandler(error, res);
    }
  }
  async resetPassword(req: Request, res: Response) {
    try {
      logger.info(
        `Auth Controller : resetPassword, request-Body : ${JSON.stringify(
          req.body,
        )}`,
      );
      const userId = req.body.jwtDecodedUser.id;
      const oldPassword = req.body.oldPassword;
      const newPassword = req.body.newPassword;
      const response = await authService.resetPassword(
        userId,
        oldPassword,
        newPassword,
      );
      if (response == Constants.ErrorMessage.OLD_PASSWORD_NOT_MATCH) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.OLD_PASSWORD_NOT_MATCH,
          Constants.Http.UNAUTHORIZED,
          res,
        );
      }
      if (response == Constants.ErrorMessage.SAME_PASSWORD) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.SAME_PASSWORD,
          Constants.Http.UNPROCESSABLE,
          res,
        );
      }
      return apiHandler.responseHandler(
        {},
        Constants.SuccessMessage.UPDATED_SUCCESSFULLY,
        Constants.Http.OK,
        res,
      );
    } catch (error) {
      logger.error(error);
      return apiHandler.errorHandler(error, res);
    }
  }
  async forgotPassword(req: Request, res: Response) {
    try {
      logger.info(
        `Auth Controller : forgotPassword, request-Body : ${JSON.stringify(
          req.body,
        )}`,
      );
      const email: string = req.body.email;
      const response = await authService.forgotPassword(email);

      if (response === Constants.ErrorMessage.INVALID_EMAIL) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.INVALID_EMAIL,
          Constants.Http.UNAUTHORIZED,
          res,
        );
      }
      if (
        response ==
        Constants.ErrorMessage.RESEND_VERIFICATION_CODE_LIMIT_REACHED
      ) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.RESEND_VERIFICATION_CODE_LIMIT_REACHED,
          Constants.Http.FORBIDDEN,
          res,
        );
      }
      if (response && typeof response == 'number') {
        await sendOtp(response, email);
      }
      return apiHandler.responseHandler(
        {},
        Constants.SuccessMessage.OTP_SENT_SUCCESSFULLY,
        Constants.Http.OK,
        res,
      );
    } catch (error) {
      logger.error(error);
      return apiHandler.errorHandler(error, res);
    }
  }
  async forgotPasswordVerify(req: Request, res: Response) {
    try {
      logger.info(
        `Auth Controller : forgotPasswordVerify, request-Body : ${JSON.stringify(
          req.body,
        )}`,
      );
      const email: string = req.body.email;
      const newPassword: string = req.body.newPassword;
      const otp: number = req.body.otp;
      const response = await authService.forgotPasswordVerify(
        otp,
        newPassword,
        email,
      );
      if (response === Constants.ErrorMessage.INVALID_OTP) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.INVALID_OTP,
          Constants.Http.UNAUTHORIZED,
          res,
        );
      }
      if (response === Constants.ErrorMessage.INVALID_EMAIL) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.INVALID_EMAIL,
          Constants.Http.UNAUTHORIZED,
          res,
        );
      }
      if (response == Constants.ErrorMessage.SAME_PASSWORD) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.SAME_PASSWORD,
          Constants.Http.UNPROCESSABLE,
          res,
        );
      }
      return apiHandler.responseHandler(
        {},
        Constants.SuccessMessage.UPDATED_SUCCESSFULLY,
        Constants.Http.OK,
        res,
      );
    } catch (error) {
      logger.error(error);
      return apiHandler.errorHandler(error, res);
    }
  }
  async sendResetPasswordMail(req: Request, res: Response) {
    try {
      logger.info(
        `Auth Controller : sendResetPasswordMail, request-Body : ${JSON.stringify(
          req.body,
        )}`,
      );
      const email: string = req.body.email;
      const response = await authService.sendResetPasswordMail(email);

      if (response === Constants.ErrorMessage.INVALID_EMAIL) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.INVALID_EMAIL,
          Constants.Http.UNAUTHORIZED,
          res,
        );
      }
      if (
        response ==
        Constants.ErrorMessage.RESEND_VERIFICATION_CODE_LIMIT_REACHED
      ) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.RESEND_VERIFICATION_CODE_LIMIT_REACHED,
          Constants.Http.FORBIDDEN,
          res,
        );
      }
      const emailPayload = {
        receivers: [email],
        subject: Constants.EmailSubject.RESET_PASSWORD,
        details: {
          resetPasswordLink: response,
        },
        templateName: Constants.EmailTemplateName.RESET_PASSWORD,
      };
      await emailTrigger.triggerEmail(emailPayload);
      return apiHandler.responseHandler(
        {},
        Constants.SuccessMessage.RESET_PASSWORD_MAIL_SENT_SUCCESSFULLY,
        Constants.Http.OK,
        res,
      );
    } catch (error) {
      logger.error(error);
      return apiHandler.errorHandler(error, res);
    }
  }
  async verifyResetPassword(req: Request, res: Response) {
    try {
      logger.info(
        `Auth Controller : forgotPasswordVerify, request-Body : ${JSON.stringify(
          req.body,
        )}`,
      );
      const email: string = req.body.email;
      const newPassword: string = req.body.newPassword;
      const token: string = req.body.token;
      const response = await authService.verifyResetPassword(
        token,
        newPassword,
        email,
      );
      if (response === Constants.ErrorMessage.INVALID_EMAIL) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.INVALID_EMAIL,
          Constants.Http.UNAUTHORIZED,
          res,
        );
      }
      if (response === Constants.ErrorMessage.INVALID_PASSWORD_TOKEN) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.INVALID_PASSWORD_TOKEN,
          Constants.Http.GONE,
          res,
        );
      }
      if (response == Constants.ErrorMessage.SAME_PASSWORD) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.SAME_PASSWORD,
          Constants.Http.UNPROCESSABLE,
          res,
        );
      }
      return apiHandler.responseHandler(
        {},
        Constants.SuccessMessage.UPDATED_SUCCESSFULLY,
        Constants.Http.OK,
        res,
      );
    } catch (error) {
      logger.error(error);
      return apiHandler.errorHandler(error, res);
    }
  }
  async verifyOtp(req: Request, res: Response) {
    try {
      logger.info(
        `Auth Controller : verifyOtp , req-body ${JSON.stringify(req.body)}`,
      );
      const { email, otp, type, mobile } = req.body;
      const userEmail = req.body.jwtDecodedUser.email;
      const userMobile = req.body.jwtDecodedUser.mobile;
      if (email && mobile) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.EITHER_EMAIL_OR_MOBILE_CAN_VERIFY,
          Constants.Http.BAD_REQUEST,
          res,
        );
      }
      if (!email && !mobile) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.EMAIL_OR_MOBILE_REQUIRED,
          Constants.Http.BAD_REQUEST,
          res,
        );
      }
      if (
        (type == Constants.otpType.EMAIL_VERIFICATION && mobile) ||
        (type == Constants.otpType.SMS_VERIFICATION && email)
      ) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.INVALID_TYPE,
          Constants.Http.UNPROCESSABLE,
          res,
        );
      }
      if (type == Constants.otpType.EMAIL_VERIFICATION && email != userEmail) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.INVALID_EMAIL,
          Constants.Http.UNAUTHORIZED,
          res,
        );
      }
      if (type == Constants.otpType.SMS_VERIFICATION && mobile != userMobile) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.INVALID_MOBILE,
          Constants.Http.UNAUTHORIZED,
          res,
        );
      }
      let response;
      if (type == Constants.otpType.EMAIL_VERIFICATION) {
        response = await authService.verifyOtp(email, otp, type);
        if (response == Constants.ErrorMessage.INVALID_EMAIL) {
          return apiHandler.responseHandler(
            {},
            Constants.ErrorMessage.INVALID_EMAIL,
            Constants.Http.UNAUTHORIZED,
            res,
          );
        }
        if (response == Constants.ErrorMessage.EMAIL_ALREADY_VERIFIED) {
          return apiHandler.responseHandler(
            {},
            Constants.ErrorMessage.EMAIL_ALREADY_VERIFIED,
            Constants.Http.FORBIDDEN,
            res,
          );
        }
      }
      if (type == Constants.otpType.SMS_VERIFICATION) {
        response = await authService.verifyOtp(mobile, otp, type);
        if (response == Constants.ErrorMessage.INVALID_EMAIL) {
          return apiHandler.responseHandler(
            {},
            Constants.ErrorMessage.INVALID_MOBILE,
            Constants.Http.UNAUTHORIZED,
            res,
          );
        }
        if (response == Constants.ErrorMessage.MOBILE_ALREADY_VERIFIED) {
          return apiHandler.responseHandler(
            {},
            Constants.ErrorMessage.MOBILE_ALREADY_VERIFIED,
            Constants.Http.FORBIDDEN,
            res,
          );
        }
      }
      if (!response) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.INVALID_OTP,
          Constants.Http.UNAUTHORIZED,
          res,
        );
      }
      return apiHandler.responseHandler(
        {},
        Constants.SuccessMessage.OTP_VERIFICATION_SUCCESS,
        Constants.Http.OK,
        res,
      );
    } catch (error) {
      logger.error(error);
      return apiHandler.errorHandler(error, res);
    }
  }
  async regenerateOtp(req: Request, res: Response) {
    try {
      logger.info(
        `Auth Controller : regenerateOtp , req-body ${JSON.stringify(
          req.body,
        )}`,
      );
      const { email, mobile, type } = req.body;
      const userEmail = req.body.jwtDecodedUser.email;
      const userMobile = req.body.jwtDecodedUser.mobile;
      if (email && mobile) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.EITHER_EMAIL_OR_MOBILE_ALLOWED,
          Constants.Http.BAD_REQUEST,
          res,
        );
      }
      if (
        (type == Constants.otpType.EMAIL_VERIFICATION && mobile) ||
        (type == Constants.otpType.SMS_VERIFICATION && email)
      ) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.INVALID_TYPE,
          Constants.Http.UNPROCESSABLE,
          res,
        );
      }
      if (type == Constants.otpType.EMAIL_VERIFICATION && email != userEmail) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.INVALID_EMAIL,
          Constants.Http.UNAUTHORIZED,
          res,
        );
      }
      if (type == Constants.otpType.SMS_VERIFICATION && mobile != userMobile) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.INVALID_MOBILE,
          Constants.Http.UNAUTHORIZED,
          res,
        );
      }
      let response;
      if (type == Constants.otpType.EMAIL_VERIFICATION) {
        response = await authService.regenerateOtp(email, type);
        if (response == Constants.ErrorMessage.INVALID_EMAIL) {
          return apiHandler.responseHandler(
            {},
            Constants.ErrorMessage.INVALID_EMAIL,
            Constants.Http.UNAUTHORIZED,
            res,
          );
        }
        if (response == Constants.ErrorMessage.EMAIL_ALREADY_VERIFIED) {
          return apiHandler.responseHandler(
            {},
            Constants.ErrorMessage.EMAIL_ALREADY_VERIFIED,
            Constants.Http.FORBIDDEN,
            res,
          );
        }
      }
      if (type == Constants.otpType.SMS_VERIFICATION) {
        response = await authService.regenerateOtp(mobile, type);
        if (response == Constants.ErrorMessage.INVALID_MOBILE) {
          return apiHandler.responseHandler(
            {},
            Constants.ErrorMessage.INVALID_MOBILE,
            Constants.Http.UNAUTHORIZED,
            res,
          );
        }
        if (response == Constants.ErrorMessage.MOBILE_ALREADY_VERIFIED) {
          return apiHandler.responseHandler(
            {},
            Constants.ErrorMessage.MOBILE_ALREADY_VERIFIED,
            Constants.Http.FORBIDDEN,
            res,
          );
        }
      }
      if (
        response ==
        Constants.ErrorMessage.RESEND_VERIFICATION_CODE_LIMIT_REACHED
      ) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.RESEND_VERIFICATION_CODE_LIMIT_REACHED,
          Constants.Http.FORBIDDEN,
          res,
        );
      }

      if (
        typeof response == 'number' &&
        type == Constants.otpType.EMAIL_VERIFICATION
      ) {
        //TODO: send otp for sms also
        await sendOtp(response, email);
      }

      return apiHandler.responseHandler(
        {},
        Constants.SuccessMessage.OTP_SENT_SUCCESSFULLY,
        Constants.Http.OK,
        res,
      );
    } catch (error) {
      logger.error(error);
      return apiHandler.errorHandler(error, res);
    }
  }
  async twoFA(req: Request, res: Response) {
    try {
      logger.info(
        `Auth Controller : twoFA , req-body ${JSON.stringify(req.body)}`,
      );
      const { email, enable } = req.body;
      const userEmail = req.body.jwtDecodedUser.email;
      if (email != userEmail) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.INVALID_EMAIL,
          Constants.Http.UNAUTHORIZED,
          res,
        );
      }
      const response = await authService.twoFA(email, enable);
      if (!response) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.INVALID_EMAIL,
          Constants.Http.UNAUTHORIZED,
          res,
        );
      }
      if (response == Constants.ErrorMessage.TWO_FA_NOT_ENABLED) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.TWO_FA_NOT_ENABLED,
          Constants.Http.FORBIDDEN,
          res,
        );
      }
      if (response == Constants.SuccessMessage.TWO_FA_DISABLED_SUCCESS) {
        return apiHandler.responseHandler(
          {},
          Constants.SuccessMessage.TWO_FA_DISABLED_SUCCESS,
          Constants.Http.OK,
          res,
        );
      }
      if (typeof response == 'object') {
        return apiHandler.responseHandler(
          { qrCode: response.qrCode, backupCode: response.backupCode },
          Constants.SuccessMessage.TWO_FA_ENABLED_SUCCESS,
          Constants.Http.OK,
          res,
        );
      }
    } catch (error) {
      logger.error(error);
      return apiHandler.errorHandler(error, res);
    }
  }
  async verify2FA(req: Request, res: Response) {
    try {
      logger.info(
        `Auth Controller : verify2FA , req-body ${JSON.stringify(req.body)}`,
      );
      const { email, code } = req.body;
      const response = await authService.verify2FA(email, code);
      if (!response) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.INVALID_EMAIL,
          Constants.Http.UNAUTHORIZED,
          res,
        );
      }
      if (response == Constants.ErrorMessage.INVALID_CODE) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.INVALID_CODE,
          Constants.Http.UNAUTHORIZED,
          res,
        );
      }
      if (response == Constants.ErrorMessage.TWO_FA_NOT_ENABLED) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.TWO_FA_NOT_ENABLED,
          Constants.Http.FORBIDDEN,
          res,
        );
      }
      req.session.isTwoFactorVerified = true;
      req.session.userEmail = email;
      return apiHandler.responseHandler(
        {},
        Constants.SuccessMessage.TWO_FA_Verification_SUCCESS,
        Constants.Http.OK,
        res,
      );
    } catch (error) {
      logger.error(error);
      return apiHandler.errorHandler(error, res);
    }
  }
  async disable2FA(req: Request, res: Response) {
    try {
      logger.info(
        `Auth Controller : disable2FA , req-body ${JSON.stringify(req.body)}`,
      );
      const { email, backupCode } = req.body;
      const response = await authService.disable2FA(email, backupCode);
      if (!response) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.INVALID_EMAIL,
          Constants.Http.UNAUTHORIZED,
          res,
        );
      }
      if (response == Constants.ErrorMessage.INVALID_BACKUP_CODE) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.INVALID_BACKUP_CODE,
          Constants.Http.UNAUTHORIZED,
          res,
        );
      }
      if (response == Constants.ErrorMessage.TWO_FA_NOT_ENABLED) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.TWO_FA_NOT_ENABLED,
          Constants.Http.FORBIDDEN,
          res,
        );
      }
      return apiHandler.responseHandler(
        {},
        Constants.SuccessMessage.TWO_FA_DISABLED_SUCCESS,
        Constants.Http.OK,
        res,
      );
    } catch (error) {
      logger.error(error);
      return apiHandler.errorHandler(error, res);
    }
  }
  async facebookLogin(req: Request, res: Response) {
    try {
      logger.info(
        `Auth Controller : facebookLogin, request-body : ${JSON.stringify(
          req.body,
        )}`,
      );
      const { data } = await axios({
        url: Constants.userLookupUrl.Facebook,
        method: 'get',
        params: {
          fields: [
            'id',
            'email',
            'first_name',
            'last_name',
            'gender',
            'birthday',
            'picture',
          ].join(','),
          access_token: req.body.accessToken,
        },
      });
      const email = data?.email || req.body.email;
      let firstName = data.first_name;
      let lastName = data.last_name;

      if (data.name) {
        const fullName = data['name'].split(' ');
        const nameLength = fullName.length;
        lastName = fullName[nameLength - 1];
        delete fullName[nameLength - 1];
        firstName = fullName.join(' ');
      }
      let isTwoFactorVerified = req.session.isTwoFactorVerified;
      if (req.session.userEmail !== email) {
        isTwoFactorVerified = false;
      }
      const userData: IUserData = {
        email,
        authType: Constants.AuthType.FACEBOOK,
        role: Constants.UserRole.USER,
        isActive: true,
        firstName,
        lastName,
        isEmailVerified: data?.email ? true : false,
        isTwoFactorVerified,
      };
      const response = await authService.socialLogin(
        userData,
        Constants.AuthType.FACEBOOK,
      );

      if (response == Constants.ErrorMessage.USER_NOT_ACTIVE) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.USER_NOT_ACTIVE,
          Constants.Http.UNAUTHORIZED,
          res,
        );
      }
      if (typeof response == 'object' && response.otp) {
        const { otp, email } = response;
        await sendOtp(otp, email);
        delete response.otp;
      }
      req.session.isTwoFactorVerified = false;
      return apiHandler.responseHandler(
        response,
        Constants.SuccessMessage.FACEBOOK_AUTHENTICATION_SUCCESS,
        Constants.Http.OK,
        res,
      );
    } catch (error) {
      logger.error(error);
      if (error?.response?.status === Constants.Http.BAD_REQUEST) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.UNAUTHORIZED,
          Constants.Http.UNAUTHORIZED,
          res,
        );
      }
      return apiHandler.errorHandler(error, res);
    }
  }
  async googleLogin(req: Request, res: Response) {
    try {
      logger.info(
        `Auth Controller : googleLogin, request-body : ${JSON.stringify(
          req.body,
        )}`,
      );
      const { data } = await axios({
        url: Constants.userLookupUrl.Google,
        method: 'get',
        headers: {
          Authorization: `Bearer ${req.body.accessToken}`,
        },
      });
      let isTwoFactorVerified = req.session.isTwoFactorVerified;
      if (req.session.userEmail !== data.email) {
        isTwoFactorVerified = false;
      }
      const userData: IUserData = {
        email: data.email,
        authType: Constants.AuthType.GOOGLE,
        role: Constants.UserRole.USER,
        isActive: true,
        firstName: data.given_name,
        lastName: data.family_name,
        isEmailVerified: true,
        isTwoFactorVerified,
      };
      const response = await authService.socialLogin(
        userData,
        Constants.AuthType.GOOGLE,
      );

      if (response == Constants.ErrorMessage.USER_NOT_ACTIVE) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.USER_NOT_ACTIVE,
          Constants.Http.UNAUTHORIZED,
          res,
        );
      }
      req.session.isTwoFactorVerified = false;
      return apiHandler.responseHandler(
        response,
        Constants.SuccessMessage.GOOGLE_AUTHENTICATION_SUCCESS,
        Constants.Http.OK,
        res,
      );
    } catch (error) {
      logger.error(error);
      if (error?.response?.status === Constants.Http.UNAUTHORIZED) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.UNAUTHORIZED,
          Constants.Http.UNAUTHORIZED,
          res,
        );
      }
      return apiHandler.errorHandler(error, res);
    }
  }
  async appleLogin(req: Request, res: Response) {
    try {
      logger.info(
        `Auth Controller : appleLogin, request-body : ${JSON.stringify(
          req.body,
        )}`,
      );

      const data = await appleSigIn.verifyIdToken(req.body.accessToken, {
        ignoreExpiration: true,
      });
      let isTwoFactorVerified = req.session.isTwoFactorVerified;
      if (req.session.userEmail !== data.email) {
        isTwoFactorVerified = false;
      }
      const userData: IUserData = {
        email: data.email,
        authType: Constants.AuthType.APPLE,
        role: Constants.UserRole.USER,
        isActive: true,
        isEmailVerified: true,
        isTwoFactorVerified,
      };
      const response = await authService.socialLogin(
        userData,
        Constants.AuthType.APPLE,
      );

      if (response == Constants.ErrorMessage.USER_NOT_ACTIVE) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.USER_NOT_ACTIVE,
          Constants.Http.UNAUTHORIZED,
          res,
        );
      }
      req.session.isTwoFactorVerified = false;
      return apiHandler.responseHandler(
        response,
        Constants.SuccessMessage.APPLE_AUTHENTICATION_SUCCESS,
        Constants.Http.OK,
        res,
      );
    } catch (error) {
      logger.error(error);
      if (error?.name === Constants.ErrorMessage.APPLE_LOGIN_ERROR) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.UNAUTHORIZED,
          Constants.Http.UNAUTHORIZED,
          res,
        );
      }
      return apiHandler.errorHandler(error, res);
    }
  }
  async linkedinLogin(req: Request, res: Response) {
    try {
      logger.info(
        `Auth Controller : linkedinLogin, request-body : ${JSON.stringify(
          req.body,
        )}`,
      );
      const { data } = await axios.get(Constants.userLookupUrl.Linkedin, {
        headers: {
          Authorization: `Bearer ${req.body.accessToken}`,
          Connection: 'Keep-Alive',
        },
      });
      let isTwoFactorVerified = req.session.isTwoFactorVerified;
      if (req.session.userEmail !== data.email) {
        isTwoFactorVerified = false;
      }
      const userData: IUserData = {
        email: data.email,
        authType: Constants.AuthType.LINKEDIN,
        role: Constants.UserRole.USER,
        isActive: true,
        firstName: data.given_name,
        lastName: data.family_name,
        isEmailVerified: true,
        isTwoFactorVerified,
      };
      const response = await authService.socialLogin(
        userData,
        Constants.AuthType.LINKEDIN,
      );

      if (response == Constants.ErrorMessage.USER_NOT_ACTIVE) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.USER_NOT_ACTIVE,
          Constants.Http.UNAUTHORIZED,
          res,
        );
      }
      req.session.isTwoFactorVerified = false;
      return apiHandler.responseHandler(
        response,
        Constants.SuccessMessage.LINKEDIN_AUTHENTICATION_SUCCESS,
        Constants.Http.OK,
        res,
      );
    } catch (error) {
      logger.error(error);
      if (error?.response?.status === Constants.Http.UNAUTHORIZED) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.UNAUTHORIZED,
          Constants.Http.UNAUTHORIZED,
          res,
        );
      }
      return apiHandler.errorHandler(error, res);
    }
  }
  async githubLogin(req: Request, res: Response) {
    try {
      logger.info(
        `Auth Controller : githubLogin, request-body : ${JSON.stringify(
          req.body,
        )}`,
      );
      const { data } = await axios.get(Constants.userLookupUrl.Github, {
        headers: { Authorization: `Bearer ${req.body.accessToken}` },
      });
      const fullName = data['name'].split(' ');
      const nameLength = fullName.length;
      const lastName = fullName[nameLength - 1];
      delete fullName[nameLength - 1];
      const firstName = fullName.join(' ');
      let isTwoFactorVerified = req.session.isTwoFactorVerified;
      if (req.session.userEmail !== data.email) {
        isTwoFactorVerified = false;
      }
      const userData: IUserData = {
        email: data.email,
        authType: Constants.AuthType.GITHUB,
        role: Constants.UserRole.USER,
        isActive: true,
        firstName,
        lastName,
        isEmailVerified: true,
        isTwoFactorVerified,
      };
      const response = await authService.socialLogin(
        userData,
        Constants.AuthType.GITHUB,
      );

      if (response == Constants.ErrorMessage.USER_NOT_ACTIVE) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.USER_NOT_ACTIVE,
          Constants.Http.UNAUTHORIZED,
          res,
        );
      }
      req.session.isTwoFactorVerified = false;
      return apiHandler.responseHandler(
        response,
        Constants.SuccessMessage.GITHUB_AUTHENTICATION_SUCCESS,
        Constants.Http.OK,
        res,
      );
    } catch (error) {
      logger.error(error);
      if (error?.response?.status === Constants.Http.UNAUTHORIZED) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.UNAUTHORIZED,
          Constants.Http.UNAUTHORIZED,
          res,
        );
      }
      return apiHandler.errorHandler(error, res);
    }
  }
  async twitterLogin(req: Request, res: Response) {
    try {
      logger.info(
        `Auth Controller : twitterLogin, request-body : ${JSON.stringify(
          req.body,
        )}`,
      );
      const { data } = await axios.get(Constants.userLookupUrl.Twitter, {
        headers: {
          Authorization: `Bearer ${req.body.accessToken}`,
        },
      });
      const fullName = data.data['name'].split(' ');
      const nameLength = fullName.length;
      const lastName = fullName[nameLength - 1];
      delete fullName[nameLength - 1];
      const firstName = fullName.join(' ');
      let isTwoFactorVerified = req.session.isTwoFactorVerified;
      if (req.session.userEmail !== req.body.email) {
        isTwoFactorVerified = false;
      }

      const userData: IUserData = {
        email: req.body.email,
        authType: Constants.AuthType.TWITTER,
        role: Constants.UserRole.USER,
        isActive: true,
        firstName,
        lastName,
        isEmailVerified: false,
        isTwoFactorVerified,
      };
      const response = await authService.socialLogin(
        userData,
        Constants.AuthType.TWITTER,
      );
      if (response == Constants.ErrorMessage.USER_NOT_ACTIVE) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.USER_NOT_ACTIVE,
          Constants.Http.UNAUTHORIZED,
          res,
        );
      }
      if (typeof response == 'object' && response.otp) {
        const { otp, email } = response;
        await sendOtp(otp, email);

        delete response.otp;
      }
      req.session.isTwoFactorVerified = false;

      return apiHandler.responseHandler(
        response,
        Constants.SuccessMessage.TWITTER_AUTHENTICATION_SUCCESS,
        Constants.Http.OK,
        res,
      );
    } catch (error) {
      logger.error(error);
      if (
        error?.response?.status === Constants.Http.FORBIDDEN ||
        error?.response?.status === Constants.Http.UNAUTHORIZED
      ) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.UNAUTHORIZED,
          Constants.Http.UNAUTHORIZED,
          res,
        );
      }
      if (error?.response?.status === Constants.Http.TOO_MANY_REQUESTS) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.TOO_MANY_REQUEST,
          Constants.Http.TOO_MANY_REQUESTS,
          res,
        );
      }
      return apiHandler.errorHandler(error, res);
    }
  }
  async redditLogin(req: Request, res: Response) {
    try {
      logger.info(
        `Auth Controller : redditLogin, request-body : ${JSON.stringify(
          req.body,
        )}`,
      );
      const { data } = await axios.get(Constants.userLookupUrl.Reddit, {
        headers: {
          Authorization: `bearer ${req.body.accessToken}`,
        },
      });
      let isTwoFactorVerified = req.session.isTwoFactorVerified;
      if (req.session.userEmail !== req.body.email) {
        isTwoFactorVerified = false;
      }

      const userData: IUserData = {
        email: req.body.email,
        authType: Constants.AuthType.REDDIT,
        role: Constants.UserRole.USER,
        isActive: true,
        firstName: data.name,
        isEmailVerified: false,
        isTwoFactorVerified,
      };
      const response = await authService.socialLogin(
        userData,
        Constants.AuthType.REDDIT,
      );

      if (response == Constants.ErrorMessage.USER_NOT_ACTIVE) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.USER_NOT_ACTIVE,
          Constants.Http.UNAUTHORIZED,
          res,
        );
      }
      if (typeof response == 'object' && response.otp) {
        const { otp, email } = response;
        await sendOtp(otp, email);
        delete response.otp;
      }
      req.session.isTwoFactorVerified = false;

      return apiHandler.responseHandler(
        response,
        Constants.SuccessMessage.REDDIT_AUTHENTICATION_SUCCESS,
        Constants.Http.OK,
        res,
      );
    } catch (error) {
      logger.error(error);
      if (error?.response?.status === Constants.Http.UNAUTHORIZED) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.UNAUTHORIZED,
          Constants.Http.UNAUTHORIZED,
          res,
        );
      }
      return apiHandler.errorHandler(error, res);
    }
  }
  async yahooLogin(req: Request, res: Response) {
    try {
      logger.info(
        `Auth Controller : yahooLogin, request-body : ${JSON.stringify(
          req.body,
        )}`,
      );
      const { data } = await axios.get(Constants.userLookupUrl.Yahoo, {
        headers: {
          Authorization: `bearer ${req.body.accessToken}`,
        },
      });

      let isTwoFactorVerified = req.session.isTwoFactorVerified;
      if (req.session.userEmail !== data.email) {
        isTwoFactorVerified = false;
      }
      const userData: IUserData = {
        email: data.email,
        authType: Constants.AuthType.YAHOO,
        role: Constants.UserRole.USER,
        isActive: true,
        firstName: data.given_name,
        lastName: data.family_name,
        isEmailVerified: true,
        isTwoFactorVerified,
      };
      const response = await authService.socialLogin(
        userData,
        Constants.AuthType.YAHOO,
      );

      if (response == Constants.ErrorMessage.USER_NOT_ACTIVE) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.USER_NOT_ACTIVE,
          Constants.Http.UNAUTHORIZED,
          res,
        );
      }
      req.session.isTwoFactorVerified = false;

      return apiHandler.responseHandler(
        response,
        Constants.SuccessMessage.YAHOO_AUTHENTICATION_SUCCESS,
        Constants.Http.OK,
        res,
      );
    } catch (error) {
      logger.error(error);
      if (error?.response?.status === Constants.Http.UNAUTHORIZED) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.UNAUTHORIZED,
          Constants.Http.UNAUTHORIZED,
          res,
        );
      }
      return apiHandler.errorHandler(error, res);
    }
  }
  async amazonLogin(req: Request, res: Response) {
    try {
      logger.info(
        `Auth Controller : amazonLogin, request-body : ${JSON.stringify(
          req.body,
        )}`,
      );
      const { data } = await axios.get(Constants.userLookupUrl.Amazon, {
        headers: {
          Authorization: `Bearer ${req.body.accessToken}`,
        },
      });
      let firstName, lastName;
      if (data.name) {
        const fullName = data['name'].split(' ');
        const nameLength = fullName.length;
        lastName = fullName[nameLength - 1];
        delete fullName[nameLength - 1];
        firstName = fullName.join('');
      }
      let isTwoFactorVerified = req.session.isTwoFactorVerified;
      if (req.session.userEmail !== data.email) {
        isTwoFactorVerified = false;
      }
      const userData: IUserData = {
        email: data.email,
        authType: Constants.AuthType.AMAZON,
        role: Constants.UserRole.USER,
        isActive: true,
        firstName,
        lastName,
        isEmailVerified: true,
        isTwoFactorVerified,
      };
      const response = await authService.socialLogin(
        userData,
        Constants.AuthType.AMAZON,
      );

      if (response == Constants.ErrorMessage.USER_NOT_ACTIVE) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.USER_NOT_ACTIVE,
          Constants.Http.UNAUTHORIZED,
          res,
        );
      }
      req.session.isTwoFactorVerified = false;

      return apiHandler.responseHandler(
        response,
        Constants.SuccessMessage.AMAZON_AUTHENTICATION_SUCCESS,
        Constants.Http.OK,
        res,
      );
    } catch (error) {
      logger.error(error);
      if (
        error?.response?.status === Constants.Http.UNAUTHORIZED ||
        error?.response?.status === Constants.Http.BAD_REQUEST
      ) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.UNAUTHORIZED,
          Constants.Http.UNAUTHORIZED,
          res,
        );
      }
      return apiHandler.errorHandler(error, res);
    }
  }
  async gitlabLogin(req: Request, res: Response) {
    try {
      logger.info(
        `Auth Controller : gitlabLogin, request-body : ${JSON.stringify(
          req.body,
        )}`,
      );
      const { data } = await axios.get(Constants.userLookupUrl.Gitlab, {
        headers: {
          Authorization: `Bearer ${req.body.accessToken}`,
        },
      });
      let firstName, lastName;
      if (data.name) {
        const fullName = data['name'].split(' ');
        const nameLength = fullName.length;
        lastName = fullName[nameLength - 1];
        delete fullName[nameLength - 1];
        firstName = fullName.join('');
      }
      let isTwoFactorVerified = req.session.isTwoFactorVerified;
      if (req.session.userEmail !== data.email) {
        isTwoFactorVerified = false;
      }
      const userData: IUserData = {
        email: data.email,
        authType: Constants.AuthType.GITLAB,
        role: Constants.UserRole.USER,
        isActive: true,
        firstName,
        lastName,
        isEmailVerified: true,
        isTwoFactorVerified,
      };
      const response = await authService.socialLogin(
        userData,
        Constants.AuthType.GITLAB,
      );

      if (response == Constants.ErrorMessage.USER_NOT_ACTIVE) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.USER_NOT_ACTIVE,
          Constants.Http.UNAUTHORIZED,
          res,
        );
      }
      req.session.isTwoFactorVerified = false;

      return apiHandler.responseHandler(
        response,
        Constants.SuccessMessage.GITLAB_AUTHENTICATION_SUCCESS,
        Constants.Http.OK,
        res,
      );
    } catch (error) {
      logger.error(error);
      if (error?.response?.status === Constants.Http.UNAUTHORIZED) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.UNAUTHORIZED,
          Constants.Http.UNAUTHORIZED,
          res,
        );
      }
      return apiHandler.errorHandler(error, res);
    }
  }
  async discordLogin(req: Request, res: Response) {
    try {
      logger.info(
        `Auth Controller : discordLogin, request-body : ${JSON.stringify(
          req.body,
        )}`,
      );
      const { data } = await axios.get(Constants.userLookupUrl.Discord, {
        headers: {
          Authorization: `Bearer ${req.body.accessToken}`,
        },
      });
      let isTwoFactorVerified = req.session.isTwoFactorVerified;
      if (req.session.userEmail !== data.email) {
        isTwoFactorVerified = false;
      }
      const userData: IUserData = {
        email: data.email,
        authType: Constants.AuthType.DISCORD,
        role: Constants.UserRole.USER,
        isActive: true,
        firstName: data.username,
        isEmailVerified: true,
        isTwoFactorVerified,
      };
      const response = await authService.socialLogin(
        userData,
        Constants.AuthType.DISCORD,
      );

      if (response == Constants.ErrorMessage.USER_NOT_ACTIVE) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.USER_NOT_ACTIVE,
          Constants.Http.UNAUTHORIZED,
          res,
        );
      }
      req.session.isTwoFactorVerified = false;
      return apiHandler.responseHandler(
        response,
        Constants.SuccessMessage.GITLAB_AUTHENTICATION_SUCCESS,
        Constants.Http.OK,
        res,
      );
    } catch (error) {
      logger.error(error);
      if (error?.response?.status === Constants.Http.UNAUTHORIZED) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.UNAUTHORIZED,
          Constants.Http.UNAUTHORIZED,
          res,
        );
      }
      return apiHandler.errorHandler(error, res);
    }
  }
  async microsoftLogin(req: Request, res: Response) {
    try {
      logger.info(
        `Auth Controller : microsoftLogin, request-body : ${JSON.stringify(
          req.body,
        )}`,
      );
      const { data } = await axios.get(Constants.userLookupUrl.Microsoft, {
        headers: {
          Authorization: `Bearer ${req.body.accessToken}`,
        },
      });
      let isTwoFactorVerified = req.session.isTwoFactorVerified;
      if (req.session.userEmail !== data.mail) {
        isTwoFactorVerified = false;
      }
      const userData: IUserData = {
        email: data.mail,
        authType: Constants.AuthType.MICROSOFT,
        role: Constants.UserRole.USER,
        isActive: true,
        firstName: data.givenName,
        lastName: data.surname,
        isEmailVerified: true,
        isTwoFactorVerified,
      };
      const response = await authService.socialLogin(
        userData,
        Constants.AuthType.MICROSOFT,
      );

      if (response == Constants.ErrorMessage.USER_NOT_ACTIVE) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.USER_NOT_ACTIVE,
          Constants.Http.UNAUTHORIZED,
          res,
        );
      }
      req.session.isTwoFactorVerified = false;

      return apiHandler.responseHandler(
        response,
        Constants.SuccessMessage.MICROSOFT_AUTHENTICATION_SUCCESS,
        Constants.Http.OK,
        res,
      );
    } catch (error) {
      logger.error(error);
      if (error?.response?.status === Constants.Http.UNAUTHORIZED) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.UNAUTHORIZED,
          Constants.Http.UNAUTHORIZED,
          res,
        );
      }
      return apiHandler.errorHandler(error, res);
    }
  }
}

const authController: AuthController = new AuthController();
export default authController;
