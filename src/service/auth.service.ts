import jwt, { JwtPayload } from 'jsonwebtoken';
import moment, { DurationInputArg1, DurationInputArg2 } from 'moment';
import randomCSPRNG from 'random-number-csprng';
import randomString from 'randomstring';

import logger from '../config/logger';
import { Constants } from '../const/constants';
import { DatabaseInitialization } from '../db/dbConnection';
import { TwoFactorAuthenticators } from '../db/entity/twoFactorAuthenticators';
import { UserOtps } from '../db/entity/userOtps';
import { IJwtData, IUserData, Users } from '../db/entity/users';
import twoFAHandler from '../utils/twoFAHandler';
import { SSMService } from './ssm.service';
const secret = SSMService.secret;
class AuthService {
  usersRepository = DatabaseInitialization.dataSource.getRepository(Users);
  userOtpsRepository =
    DatabaseInitialization.dataSource.getRepository(UserOtps);
  twoFactorAuthenticatorsRepository =
    DatabaseInitialization.dataSource.getRepository(TwoFactorAuthenticators);
  async register(userData: IUserData) {
    try {
      logger.info(
        `Auth service : register , userData: ${JSON.stringify(userData)}`,
      );
      const { email, firstName, lastName, password, mobile } = userData;
      const userDetails = await this.usersRepository.findOne({
        where: { email: email.toLowerCase() },
        withDeleted: true,
      });
      if (userDetails) {
        if (userDetails.deletedAt) {
          //update the user if user is deleted
          userData.password = userDetails.hashPassword(password) as string;
          delete userData.email;

          await this.usersRepository.update(
            { id: userDetails.id },
            {
              ...userData,
              deletedAt: null,
              authType: Constants.AuthType.EMAIL,
              isActive: true,
            },
          );
          return userDetails;
        }
        return null;
      } else {
        if (mobile) {
          const user = await this.usersRepository.findOne({
            where: { mobile },
            withDeleted: true,
          });
          if (user) {
            return null;
          }
        }
      }
      const user = new Users();
      user.firstName = firstName;
      user.lastName = lastName;
      user.email = email.toLowerCase();
      user.password = password;
      user.authType = Constants.AuthType.EMAIL;
      user.isEmailVerified = false;
      user.mobile = mobile;
      const newUser = await this.usersRepository.save(user);
      return newUser;
    } catch (error) {
      throw error;
    }
  }
  async login(userData: IUserData) {
    try {
      logger.info(
        `Auth service : login , userData: ${JSON.stringify(userData)}`,
      );
      const { email, password } = userData;
      let isTwoFAEnabled = false;
      const userDetails = await this.usersRepository.findOne({
        where: { email: email.toLowerCase() },
        relations: ['twoFactorAuthenticators'],
      });
      if (!userDetails) {
        return null;
      }
      const isPasswordValid = await userDetails.verifyPassword(password);
      if (!isPasswordValid) {
        return null;
      }
      if (!userDetails.isActive) {
        return Constants.ErrorMessage.USER_NOT_ACTIVE;
      }
      const userDetailsResponse = await userDetails.toAuthJSON();
      if (userDetails.authType !== Constants.AuthType.EMAIL) {
        await this.usersRepository.update(
          { id: userDetails.id },
          { authType: Constants.AuthType.EMAIL },
        );
        userDetailsResponse.authType = Constants.AuthType.EMAIL;
        const jwtData = { ...userDetailsResponse };
        delete jwtData.token;
        delete jwtData.timeToLive;
        delete jwtData.refreshToken;
        userDetailsResponse.token = await userDetails.generateJWT(jwtData);
      }
      if (userDetails.twoFactorAuthenticators) {
        isTwoFAEnabled = true;
        if (!userData.isTwoFactorVerified) {
          delete userDetailsResponse.token;
          delete userDetailsResponse.refreshToken;
          delete userDetailsResponse.timeToLive;
        }
      }

      return { ...userDetailsResponse, isTwoFAEnabled };
    } catch (error) {
      throw error;
    }
  }
  async regenerateAccessToken(id: number) {
    try {
      logger.info(`Auth service : regenerateAccessToken }`);
      const user = await this.usersRepository.findOne({ where: { id } });
      if (!user) {
        return null;
      }
      const { token, timeToLive } = await user.toAuthJSON();
      return { token, timeToLive };
    } catch (error) {
      throw error;
    }
  }
  async resetPassword(id: number, oldPassword: string, newPassword: string) {
    try {
      logger.info(`Auth Service : resetPassword, userId : ${id},
      oldPassword : ${oldPassword}, newPassword: ${newPassword}`);
      const user = await this.usersRepository.findOne({ where: { id } });

      if (!(await user.verifyPassword(oldPassword))) {
        return Constants.ErrorMessage.OLD_PASSWORD_NOT_MATCH;
      }
      if (await user.verifyPassword(newPassword)) {
        return Constants.ErrorMessage.SAME_PASSWORD;
      }
      user.hashPassword(newPassword);
      await this.usersRepository.save(user);
      return Constants.SuccessMessage.UPDATED_SUCCESSFULLY;
    } catch (error) {
      throw error;
    }
  }
  async forgotPassword(email: string) {
    try {
      logger.info(`Auth Service : forgotPassword, email : ${email}`);
      const user = await this.usersRepository
        .createQueryBuilder('user')
        .leftJoinAndSelect(
          'user.userOtps',
          'userOtps',
          'userOtps.type = :type',
          {
            type: Constants.otpType.FORGOT_PASSWORD,
          },
        )
        .where('user.email = :email', { email: email.toLowerCase() })
        .getOne();
      if (!user) {
        return Constants.ErrorMessage.INVALID_EMAIL;
      }
      if (user.userOtps[0] && user.userOtps[0].retryCount) {
        if (
          user.userOtps[0].retryCount >= Constants.RESEND_OTP.MAX_LIMIT &&
          moment().isBefore(
            moment(user.userOtps[0].updatedAt).add(
              Constants.RESEND_OTP.DURATION as DurationInputArg1,
              Constants.RESEND_OTP.DURATION_TIME_UNIT as DurationInputArg2,
            ),
          )
        ) {
          return Constants.ErrorMessage.RESEND_VERIFICATION_CODE_LIMIT_REACHED;
        }
        if (
          user.userOtps[0].updatedAt &&
          user.userOtps[0].retryCount &&
          moment().isAfter(
            moment(user.userOtps[0].updatedAt).add(
              Constants.RESEND_OTP.DURATION as DurationInputArg1,
              Constants.RESEND_OTP.DURATION_TIME_UNIT as DurationInputArg2,
            ),
          )
        ) {
          user.userOtps[0].retryCount = 0;
          await this.userOtpsRepository.save(user.userOtps);
        }
      }
      return await this.generateOtp(user.id, Constants.otpType.FORGOT_PASSWORD);
    } catch (error) {
      throw error;
    }
  }
  async sendResetPasswordMail(email: string) {
    try {
      logger.info(`Auth Service : forgotPassword, email : ${email}`);
      const user = await this.usersRepository.findOne({ where: { email } });
      if (!user) {
        return Constants.ErrorMessage.INVALID_EMAIL;
      }

      user.passwordToken = randomString.generate();
      if (user && user.retryCount) {
        if (
          user.retryCount >= Constants.RESEND_OTP.MAX_LIMIT &&
          moment().isBefore(
            moment(user.updatedAt).add(
              Constants.RESEND_OTP.DURATION as DurationInputArg1,
              Constants.RESEND_OTP.DURATION_TIME_UNIT as DurationInputArg2,
            ),
          )
        ) {
          return Constants.ErrorMessage.RESEND_VERIFICATION_CODE_LIMIT_REACHED;
        }
        if (
          user.updatedAt &&
          user.retryCount &&
          moment().isAfter(
            moment(user.updatedAt).add(
              Constants.RESEND_OTP.DURATION as DurationInputArg1,
              Constants.RESEND_OTP.DURATION_TIME_UNIT as DurationInputArg2,
            ),
          )
        ) {
          user.retryCount = 0;
          await this.usersRepository.save(user);
        }
      }
      user.retryCount = user.retryCount + 1;
      user.updatedAt = new Date();
      await this.usersRepository.save(user);
      logger.info(
        `Auth service : auth, reset-password-link : ${JSON.stringify({
          resetPasswordLink: `${secret.FRONT_END_HOST_URL}passwordReset?token=${user.passwordToken}`,
        })}`,
      );
      return `${secret.FRONT_END_HOST_URL}passwordReset?token=${user.passwordToken}`;
    } catch (error) {
      throw error;
    }
  }
  async verifyResetPassword(token: string, newPassword: string, email: string) {
    try {
      logger.info(
        `Auth Service : verifyResetPassword, token : ${token}, newPassword: ${newPassword}`,
      );
      const user = await this.usersRepository.findOne({
        where: { email },
      });
      if (!user) {
        return Constants.ErrorMessage.INVALID_EMAIL;
      }
      if (!user.passwordToken || token !== user.passwordToken) {
        return Constants.ErrorMessage.INVALID_PASSWORD_TOKEN;
      }
      if (await user.verifyPassword(newPassword)) {
        return Constants.ErrorMessage.SAME_PASSWORD;
      }
      user.passwordToken = null;
      await this.usersRepository.save(user);

      const hashedPassword = user.hashPassword(newPassword);
      await this.usersRepository.update(
        { id: user.id },
        { password: hashedPassword as string },
      );
      return;
    } catch (error) {
      throw error;
    }
  }
  async socialLogin(userData: IUserData, authType: string) {
    try {
      logger.info(
        `Auth Service : socialLogin, userData : ${JSON.stringify(
          userData,
        )} , authType: ${authType}`,
      );
      let user;
      let response;
      let otp;
      let isTwoFAEnabled = false;

      user = await this.usersRepository.findOne({
        where: {
          email: userData.email.toLowerCase(),
        },
        relations: ['twoFactorAuthenticators'],
        withDeleted: true,
      });
      if (!user) {
        // If user is not already present create a new user
        user = new Users();
        user.firstName = userData.firstName;
        user.lastName = userData.lastName;
        user.email = userData.email.toLowerCase();
        user.authType = authType;
        user.isEmailVerified = userData.isEmailVerified;
        const newUser = await this.usersRepository.save(user);
        user = newUser;
        if (!user.isEmailVerified) {
          otp = await this.generateOtp(
            user.id,
            Constants.otpType.EMAIL_VERIFICATION,
          );
        }
      } else if (user.authType !== authType) {
        delete userData.email;
        // userData have current user data and user have old user data
        response = await this.updateUser(user, userData, authType);
        if (!response.isEmailVerified) {
          otp = await this.generateOtp(
            user.id,
            Constants.otpType.EMAIL_VERIFICATION,
          );
        }
        if (user.twoFactorAuthenticators) {
          isTwoFAEnabled = true;
          if (!userData.isTwoFactorVerified) {
            delete response.token;
            delete response.refreshToken;
            delete response.timeToLive;
          }
        }
        return { ...response, isTwoFAEnabled, otp };
      } else if (!user.isActive) {
        return Constants.ErrorMessage.USER_NOT_ACTIVE;
      }
      await this.usersRepository.update(
        { id: user.id },
        { deletedAt: null, authType },
      );
      response = await user.toAuthJSON();
      if (user.twoFactorAuthenticators) {
        isTwoFAEnabled = true;
        if (!userData.isTwoFactorVerified) {
          delete response.token;
          delete response.refreshToken;
          delete response.timeToLive;
        }
      }
      return { ...response, isTwoFAEnabled, otp };
    } catch (error) {
      throw error;
    }
  }
  async updateUser(user: Users, userData: IUserData, authType: string) {
    const updateData: IUserData = {
      id: user.id,
      email: user.email,
      isEmailVerified: userData.isEmailVerified || user.isEmailVerified,
      isMobileVerified: user.isMobileVerified,
      mobile: user.mobile,
      isActive: userData.isActive,
      deletedAt: null,
      authType,
      firstName: userData.firstName || user.firstName,
      lastName: userData.lastName || user.lastName,
      role: user.role,
    };

    await this.usersRepository.update({ id: user.id }, updateData);
    delete updateData.deletedAt; // deletedAt will not be signed in jwt token
    if (!user.mobile) {
      delete updateData.mobile, delete updateData.isMobileVerified;
    }
    const userJSONData = {
      ...updateData,
      token: await user.generateJWT(updateData as IJwtData),
      refreshToken: await user.createRefreshToken(),
      timeToLive: 0,
    };
    const { exp } = jwt.verify(
      userJSONData.token,
      secret?.JWT_SECRET,
    ) as JwtPayload;
    userJSONData.timeToLive = exp;
    return userJSONData;
  }
  async forgotPasswordVerify(otp: number, newPassword: string, email: string) {
    try {
      logger.info(
        `Auth Service : forgotPasswordVerify, otp : ${otp}, newPassword: ${newPassword}`,
      );
      const otpVerificationRes = await this.usersRepository
        .createQueryBuilder('user')
        .leftJoinAndSelect(
          'user.userOtps',
          'userOtps',
          'userOtps.type = :type AND userOtps.otp = :otp',
          {
            type: Constants.otpType.FORGOT_PASSWORD,
            otp,
          },
        )
        .where('user.email = :email', { email: email.toLowerCase() })
        .getOne();
      if (!otpVerificationRes) {
        return Constants.ErrorMessage.INVALID_EMAIL;
      }
      if (!otpVerificationRes.userOtps[0]) {
        return Constants.ErrorMessage.INVALID_OTP;
      }
      if (await otpVerificationRes.verifyPassword(newPassword)) {
        return Constants.ErrorMessage.SAME_PASSWORD;
      }
      await this.userOtpsRepository.delete({
        otp,
        userId: otpVerificationRes.id,
      });

      const hashedPassword = otpVerificationRes.hashPassword(newPassword);
      await this.usersRepository.update(
        { id: otpVerificationRes.id },
        { password: hashedPassword as string },
      );
      logger.info(
        `Auth service : forgotPasswordVerify, otpVerification : Verified`,
      );
      return;
    } catch (error) {
      throw error;
    }
  }
  async verifyOtp(targetIdentity: string, otp: number, type: string) {
    try {
      logger.info(
        `Auth Service : verifyOtp, targetIdentity : ${targetIdentity} , otp : ${otp}, type : ${type}`,
      );
      let userDetails;
      const queryBuilder = this.usersRepository
        .createQueryBuilder('user')
        .leftJoinAndSelect(
          'user.userOtps',
          'userOtps',
          'userOtps.type = :type AND userOtps.otp = :otp',
          {
            type,
            otp,
          },
        );
      if (type == Constants.otpType.EMAIL_VERIFICATION) {
        userDetails = await queryBuilder
          .where('user.email = :email', { email: targetIdentity.toLowerCase() })
          .getOne();
        if (!userDetails) {
          return Constants.ErrorMessage.INVALID_EMAIL;
        }
        if (userDetails.isEmailVerified) {
          return Constants.ErrorMessage.EMAIL_ALREADY_VERIFIED;
        }
      }
      if (type == Constants.otpType.SMS_VERIFICATION) {
        userDetails = await queryBuilder
          .where('user.mobile = :mobile', { mobile: targetIdentity })
          .getOne();
        if (!userDetails) {
          return Constants.ErrorMessage.INVALID_MOBILE;
        }
        if (userDetails.isMobileVerified) {
          return Constants.ErrorMessage.MOBILE_ALREADY_VERIFIED;
        }
      }
      if (!userDetails.userOtps[0] || userDetails.userOtps[0].otp !== otp) {
        return null;
      }
      if (type == Constants.otpType.SMS_VERIFICATION) {
        userDetails.isMobileVerified = true;
      }
      if (type == Constants.otpType.EMAIL_VERIFICATION) {
        userDetails.isEmailVerified = true;
      }
      await this.userOtpsRepository.delete({ otp, userId: userDetails.id });
      delete userDetails.userOtps;
      await this.usersRepository.save(userDetails);
      return userDetails;
    } catch (error) {
      throw error;
    }
  }
  async regenerateOtp(targetIdentity: string, type: string) {
    try {
      logger.info(
        `Auth Service : regenerateOtp, targetIdentity : ${targetIdentity}, type: ${type}`,
      );
      let userDetails;
      const queryBuilder = this.usersRepository
        .createQueryBuilder('user')
        .leftJoinAndSelect(
          'user.userOtps',
          'userOtps',
          'userOtps.type = :type',
          {
            type,
          },
        );
      if (type == Constants.otpType.EMAIL_VERIFICATION) {
        userDetails = await queryBuilder
          .where('user.email = :email', { email: targetIdentity.toLowerCase() })
          .getOne();
        if (!userDetails) {
          return Constants.ErrorMessage.INVALID_EMAIL;
        }
        if (userDetails.isEmailVerified) {
          return Constants.ErrorMessage.EMAIL_ALREADY_VERIFIED;
        }
      }
      if (type == Constants.otpType.SMS_VERIFICATION) {
        userDetails = await queryBuilder
          .where('user.mobile = :mobile', { mobile: targetIdentity })
          .getOne();
        if (!userDetails) {
          return Constants.ErrorMessage.INVALID_MOBILE;
        }
        if (userDetails.isMobileVerified) {
          return Constants.ErrorMessage.MOBILE_ALREADY_VERIFIED;
        }
      }
      if (userDetails.userOtps[0] && userDetails.userOtps[0].retryCount) {
        if (
          userDetails.userOtps[0].retryCount >=
            Constants.RESEND_OTP.MAX_LIMIT &&
          moment().isBefore(
            moment(userDetails.userOtps[0].updatedAt).add(
              Constants.RESEND_OTP.DURATION as DurationInputArg1,
              Constants.RESEND_OTP.DURATION_TIME_UNIT as DurationInputArg2,
            ),
          )
        ) {
          return Constants.ErrorMessage.RESEND_VERIFICATION_CODE_LIMIT_REACHED;
        }
        if (
          userDetails.userOtps[0].updatedAt &&
          userDetails.userOtps[0].retryCount &&
          moment().isAfter(
            moment(userDetails.userOtps[0].updatedAt).add(
              Constants.RESEND_OTP.DURATION as DurationInputArg1,
              Constants.RESEND_OTP.DURATION_TIME_UNIT as DurationInputArg2,
            ),
          )
        ) {
          userDetails.userOtps[0].retryCount = 0;
          await this.userOtpsRepository.save(userDetails.userOtps);
        }
      }
      const otp = await this.generateOtp(userDetails.id, type);
      return otp;
    } catch (error) {
      throw error;
    }
  }
  async twoFA(email: string, enable: boolean) {
    logger.info(`Auth Service : twoFA , email : ${email}, enable : ${enable}`);
    try {
      const userDetails = await this.usersRepository.findOne({
        where: { email: email.toLowerCase() },
        relations: ['twoFactorAuthenticators'],
      });
      if (!userDetails) {
        return null;
      }
      if (!enable) {
        if (!userDetails.twoFactorAuthenticators) {
          return Constants.ErrorMessage.TWO_FA_NOT_ENABLED;
        }
        await this.twoFactorAuthenticatorsRepository.delete({
          userId: userDetails.id,
        });
        return Constants.SuccessMessage.TWO_FA_DISABLED_SUCCESS;
      }
      let qrCode, backupCode;
      qrCode = userDetails.twoFactorAuthenticators?.qrCode;
      backupCode = userDetails.twoFactorAuthenticators?.backupCode;

      if (!userDetails.twoFactorAuthenticators) {
        const { code, secret } = await twoFAHandler.generateQr(userDetails.id);
        qrCode = code;
        backupCode = secret.substring(0, 24);
        const twoFA = new TwoFactorAuthenticators();
        twoFA.userId = userDetails.id;
        twoFA.qrCode = qrCode;
        twoFA.secret = secret;
        twoFA.backupCode = backupCode;
        await this.twoFactorAuthenticatorsRepository.save(twoFA);
      }
      return { qrCode, backupCode };
    } catch (error) {
      throw error;
    }
  }
  async verify2FA(email: string, code: string) {
    logger.info(`Auth Service : verify2FA , email : ${email} , code : ${code}`);
    try {
      const userDetails = await this.usersRepository.findOne({
        where: { email: email.toLowerCase() },
        relations: ['twoFactorAuthenticators'],
      });
      if (!userDetails) {
        return null;
      }
      if (!userDetails.twoFactorAuthenticators) {
        return Constants.ErrorMessage.TWO_FA_NOT_ENABLED;
      }
      const is2FAVerified = twoFAHandler.verify2FACode(
        userDetails.twoFactorAuthenticators.secret,
        code,
      );
      if (!is2FAVerified) {
        return Constants.ErrorMessage.INVALID_CODE;
      }
      return is2FAVerified;
    } catch (error) {
      throw error;
    }
  }
  async disable2FA(email: string, backupCode: string) {
    logger.info(
      `Auth Service : disable2FA , email : ${email}, backupCode : ${backupCode}`,
    );
    try {
      const userDetails = await this.usersRepository.findOne({
        where: { email: email.toLowerCase() },
        relations: ['twoFactorAuthenticators'],
      });
      if (!userDetails) {
        return null;
      }
      if (!userDetails.twoFactorAuthenticators) {
        return Constants.ErrorMessage.TWO_FA_NOT_ENABLED;
      }
      if (backupCode !== userDetails.twoFactorAuthenticators.backupCode) {
        return Constants.ErrorMessage.INVALID_BACKUP_CODE;
      }
      await this.twoFactorAuthenticatorsRepository.delete({
        userId: userDetails.id,
      });
      return Constants.SuccessMessage.TWO_FA_DISABLED_SUCCESS;
    } catch (error) {
      throw error;
    }
  }
  async generateOtp(id: number, type: string): Promise<number> {
    // generate an otp for verification
    const otp = await randomCSPRNG(1000, 9999);
    await this.userOtpsRepository.upsert(
      [
        {
          userId: id,
          otp,
          type,
        },
      ],
      { conflictPaths: ['userId', 'type'] },
    );
    await this.userOtpsRepository
      .createQueryBuilder()
      .update()
      .set({ retryCount: () => '"retryCount" + 1', updatedAt: new Date() })
      .where('userId = :id AND type = :type', { id, type })
      .execute();
    logger.info(`otp: ${otp}`);
    return otp;
  }
}
const authService: AuthService = new AuthService();
export default authService;
