import Joi from 'joi';
import { joiPasswordExtendCore } from 'joi-password';

import { Constants } from '../const/constants';

const joiPassword = Joi.extend(joiPasswordExtendCore);
export class UserValidator {
  registerUserSchema = Joi.object().keys({
    firstName: Joi.string().required(),
    lastName: Joi.string().required(),
    email: Joi.string().email().lowercase().required(),
    mobile: Joi.string().optional(),
    password: joiPassword
      .string()
      .minOfLowercase(1)
      .minOfNumeric(1)
      .minOfSpecialCharacters(1)
      .noWhiteSpaces()
      .min(8)
      .required(),
  });

  userLoginSchema = Joi.object().keys({
    email: Joi.string().email(),
    password: joiPassword
      .string()
      .minOfLowercase(1)
      .minOfNumeric(1)
      .minOfSpecialCharacters(1)
      .noWhiteSpaces()
      .min(8)
      .required(),
  });

  verifyOtpSchema = Joi.object()
    .keys({
      email: Joi.string().email().lowercase().optional(),
      mobile: Joi.string().optional(),
      otp: Joi.number().required(),
      type: Joi.string()
        .valid(
          Constants.otpType.EMAIL_VERIFICATION,
          Constants.otpType.SMS_VERIFICATION,
        )
        .required(),
    })
    .unknown();

  regenerateOtpSchema = Joi.object()
    .keys({
      email: Joi.string().email().lowercase().optional(),
      mobile: Joi.string().optional(),
      type: Joi.string()
        .valid(
          Constants.otpType.EMAIL_VERIFICATION,
          Constants.otpType.SMS_VERIFICATION,
        )
        .required(),
    })
    .unknown();

  verifyForgotPasswordSchema = Joi.object().keys({
    email: Joi.string().email().lowercase().required(),
    otp: Joi.number().required(),
    newPassword: joiPassword
      .string()
      .minOfLowercase(1)
      .minOfNumeric(1)
      .minOfSpecialCharacters(1)
      .noWhiteSpaces()
      .min(8)
      .required(),
  });

  verifyPasswordResetSchema = Joi.object().keys({
    email: Joi.string().email().lowercase().required(),
    token: Joi.string().required(),
    newPassword: joiPassword
      .string()
      .minOfLowercase(1)
      .minOfNumeric(1)
      .minOfSpecialCharacters(1)
      .noWhiteSpaces()
      .min(8)
      .required(),
  });

  facebookLoginSchema = Joi.object().keys({
    accessToken: Joi.string().required(),
    email: Joi.string().email().required(),
  });

  googleLoginSchema = Joi.object().keys({
    accessToken: Joi.string().required(),
  });

  appleLoginSchema = Joi.object().keys({
    accessToken: Joi.string().required(),
  });
  linkedinLoginSchema = Joi.object().keys({
    accessToken: Joi.string().required(),
  });
  githubLoginSchema = Joi.object().keys({
    accessToken: Joi.string().required(),
  });
  twitterLoginSchema = Joi.object().keys({
    accessToken: Joi.string().required(),
    email: Joi.string().email().required(),
  });
  redditLoginSchema = Joi.object().keys({
    accessToken: Joi.string().required(),
    email: Joi.string().email().required(),
  });
  yahooLoginSchema = Joi.object().keys({
    accessToken: Joi.string().required(),
  });
  amazonLoginSchema = Joi.object().keys({
    accessToken: Joi.string().required(),
  });
  gitlabLoginSchema = Joi.object().keys({
    accessToken: Joi.string().required(),
  });
  discordLoginSchema = Joi.object().keys({
    accessToken: Joi.string().required(),
  });
  microsoftLoginSchema = Joi.object().keys({
    accessToken: Joi.string().required(),
  });
  twoFASchema = Joi.object()
    .keys({
      email: Joi.string().email().required(),
      enable: Joi.boolean().required(),
    })
    .unknown();
  verify2FASchema = Joi.object().keys({
    email: Joi.string().email().required(),
    code: Joi.string().required(),
  });
  disable2FASchema = Joi.object().keys({
    email: Joi.string().email().required(),
    backupCode: Joi.string().required(),
  });

  resetpasswordSchema = Joi.object()
    .keys({
      oldPassword: joiPassword
        .string()
        .minOfLowercase(1)
        .minOfNumeric(1)
        .minOfSpecialCharacters(1)
        .noWhiteSpaces()
        .min(8)
        .required(),
      newPassword: joiPassword
        .string()
        .minOfLowercase(1)
        .minOfNumeric(1)
        .minOfSpecialCharacters(1)
        .noWhiteSpaces()
        .min(8)
        .required(),
    })
    .unknown();

  forgotPasswordSchema = Joi.object().keys({
    email: Joi.string().email().lowercase().required(),
  });

  sendResetPasswordMailSchema = Joi.object().keys({
    email: Joi.string().email().lowercase().required(),
  });

  getUserSchema = Joi.object().keys({
    id: Joi.number(),
  });

  updateUserBodySchema = Joi.object()
    .keys({
      firstName: Joi.string().optional(),
      lastName: Joi.string().optional(),
    })
    .unknown();

  updateUserParamSchema = Joi.object()
    .keys({
      id: Joi.number(),
    })
    .unknown();

  getUserListSchema = Joi.object().keys({
    page: Joi.number().positive().optional(),
    limit: Joi.number().positive().optional(),
  });

  deleteUserSchema = Joi.object().keys({
    id: Joi.number(),
  });
}

const userValidator: UserValidator = new UserValidator();
export default userValidator;
