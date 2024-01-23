import logger from '../config/logger';
import { Constants } from '../const/constants';
import { DatabaseInitialization } from '../db/dbConnection';
import { UserOtps } from '../db/entity/userOtps';
import {
  IGetUserListQueryParams,
  IUserUpdateData,
  Users,
} from '../db/entity/users';
import authService from './auth.service';

class UsersService {
  usersRepository = DatabaseInitialization.dataSource.getRepository(Users);
  userOtpsRepository =
    DatabaseInitialization.dataSource.getRepository(UserOtps);
  async getUserDetails(id: number) {
    try {
      logger.info(`User Service : getUserDetails, id : ${id}`);
      const userData = await this.usersRepository.findOne({
        where: { id },
        select: {
          firstName: true,
          lastName: true,
          email: true,
          mobile: true,
          role: true,
          authType: true,
          updatedAt: true,
          createdAt: true,
        },
      });
      if (!userData) {
        return null;
      }

      return userData;
    } catch (error) {
      throw error;
    }
  }

  async updateUser(userUpdateData: IUserUpdateData, id: number) {
    try {
      logger.info(
        `User Service : updateUserProfile, userUpdateData : ${JSON.stringify(
          userUpdateData,
        )}, id : ${id}`,
      );
      await this.usersRepository.update({ id }, userUpdateData);
      if (userUpdateData.mobile) {
        authService.generateOtp(id, Constants.otpType.SMS_VERIFICATION);
      }
    } catch (error) {
      throw error;
    }
  }
  async getUserList(reqQuery: IGetUserListQueryParams) {
    try {
      logger.info(
        `User Service: getUserList, reqQuery : ${JSON.stringify(reqQuery)}`,
      );

      const page: number = reqQuery.page;
      const limit: number = reqQuery.limit;
      const offset: number = (page - 1) * limit;
      const users = await this.usersRepository.findAndCount({
        take: limit,
        skip: offset,
        select: {
          id: true,
          email: true,
          firstName: true,
          lastName: true,
          role: true,
          authType: true,
          isActive: true,
          createdAt: true,
          updatedAt: true,
        },
        order: { id: 'ASC' },
      });
      return { usersList: users[0], totalCount: users[1] };
    } catch (error) {
      throw error;
    }
  }
  async deleteUserById(id: number) {
    try {
      logger.info(`User Service : deleteUserById, id : ${id}`);
      const userDetails = await this.usersRepository.findOne({ where: { id } });
      if (!userDetails) {
        return Constants.ErrorMessage.INVALID_USER;
      }
      await this.usersRepository.softDelete(id);
      await this.userOtpsRepository.delete({ userId: id });
    } catch (error) {
      throw error;
    }
  }
}
const usersService: UsersService = new UsersService();
export default usersService;
