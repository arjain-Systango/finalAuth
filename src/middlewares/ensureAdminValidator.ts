import { NextFunction, Request, Response } from 'express';

import { Constants } from '../const/constants';
import apiHandler from '../utils/ApiHandler';

export const ensureAdminValidator = (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  if (req.body.jwtDecodedUser?.role !== Constants.UserRole.ADMIN) {
    return apiHandler.responseHandler(
      {},
      Constants.ErrorMessage.INVALID_USER,
      Constants.Http.FORBIDDEN,
      res,
    );
  }
  next();
};
