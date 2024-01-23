import { Request, Response } from 'express';

import logger from '../config/logger';
import { Constants } from '../const/constants';
import { IGetUserListQueryParams, IUserUpdateData } from '../db/entity/users';
import usersService from '../service/users.service';
import apiHandler from '../utils/ApiHandler';
class UsersController {
  async getUserDetails(req: Request, res: Response) {
    try {
      logger.info(
        `User Controller: getUserDetails, request-params : ${JSON.stringify(
          req.params,
        )}, request-body : ${JSON.stringify(req.body)}`,
      );
      const userId: number = req.body.jwtDecodedUser['id'];
      const userRole: string = req.body.jwtDecodedUser['role'];
      const id: number = parseInt(req.params['id']);
      if (!(userId === id || userRole === Constants.UserRole.ADMIN)) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.INVALID_USER,
          Constants.Http.UNAUTHORIZED,
          res,
        );
      }
      const response = await usersService.getUserDetails(id);
      if (!response) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.DATA_NOT_FOUND,
          Constants.Http.NOT_FOUND,
          res,
        );
      }
      return apiHandler.responseHandler(
        response,
        Constants.SuccessMessage.USER_DATA_FETCHED_SUCCESSFULLY,
        Constants.Http.OK,
        res,
      );
    } catch (error) {
      logger.error(error);
      return apiHandler.errorHandler(error, res);
    }
  }
  async updateUser(req: Request, res: Response) {
    try {
      logger.info(
        `User Controller : updateUser, request-Body : ${JSON.stringify(
          req.body,
        )},
         request-params : ${JSON.stringify(req.params)}`,
      );

      const userId: number = req.body.jwtDecodedUser['id'];
      const id: number = parseInt(req.params['id']);
      const { firstName, lastName, mobile } = req.body;
      const userUpdateData: IUserUpdateData = { firstName, lastName, mobile };
      if (userId !== id) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.INVALID_USER,
          Constants.Http.UNAUTHORIZED,
          res,
        );
      }
      await usersService.updateUser(userUpdateData, id);
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
  async getUserList(req: Request, res: Response) {
    try {
      logger.info(
        `User Controller : getUserList, request-query : ${JSON.stringify(
          req.query,
        )}`,
      );
      const reqQuery: IGetUserListQueryParams = {
        page: Constants.Pagination.DEFAULT_PAGE,
        limit: Constants.Pagination.DEFAULT_LIMIT,
      };
      if (req.query?.page) {
        const page: number = parseInt(req.query['page'] as string);
        reqQuery.page = page;
      }
      if (req.query?.limit) {
        const limit: number = parseInt(req.query['limit'] as string);
        reqQuery.limit = limit;
      }
      const response = await usersService.getUserList(reqQuery);
      if (!response) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.DATA_NOT_FOUND,
          Constants.Http.NOT_FOUND,
          res,
        );
      }
      return apiHandler.responseHandler(
        response,
        Constants.SuccessMessage.USER_DATA_FETCHED_SUCCESSFULLY,
        Constants.Http.OK,
        res,
      );
    } catch (error) {
      logger.error(error);
      return apiHandler.errorHandler(error, res);
    }
  }
  async deleteUserById(req: Request, res: Response) {
    try {
      logger.info(
        `User Controller: deleteUserById, request-params : ${JSON.stringify(
          req.params,
        )}, request-body : ${JSON.stringify(req.body)}`,
      );
      const userId: number = req.body.jwtDecodedUser['id'];
      const userRole: string = req.body.jwtDecodedUser['role'];
      const id: number = Number(req.params['id']);
      if (!(userId === id || userRole === Constants.UserRole.ADMIN)) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.INVALID_USER,
          Constants.Http.UNAUTHORIZED,
          res,
        );
      }
      const response = await usersService.deleteUserById(id);
      if (response == Constants.ErrorMessage.INVALID_USER) {
        return apiHandler.responseHandler(
          {},
          Constants.ErrorMessage.INVALID_USER,
          Constants.Http.UNAUTHORIZED,
          res,
        );
      }
      return apiHandler.responseHandler(
        {},
        Constants.SuccessMessage.USER_DELETED_SUCCESSFULLY,
        Constants.Http.OK,
        res,
      );
    } catch (error) {
      logger.error(error);
      return apiHandler.errorHandler(error, res);
    }
  }
}
const usersController: UsersController = new UsersController();
export default usersController;
