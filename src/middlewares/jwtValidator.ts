import { NextFunction, Request, Response } from 'express';
import jwt from 'jsonwebtoken';

import logger from '../config/logger';
import { Constants } from '../const/constants';
import { SSMService } from '../service/ssm.service';
import apiHandler from '../utils/ApiHandler';

export const jwtValidator = (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  const secret = SSMService.secret;
  logger.info(`Middelware : performing jwtValidator`);
  try {
    const header = req.headers?.authorization;
    if (!header) {
      return apiHandler.responseHandler(
        {},
        Constants.ErrorMessage.INVALID_TOKEN,
        Constants.Http.UNAUTHORIZED,
        res,
      );
    }

    const parts = header.split(' ');
    if (parts.length !== 2) {
      return apiHandler.responseHandler(
        {},
        Constants.ErrorMessage.INVALID_TOKEN,
        Constants.Http.UNAUTHORIZED,
        res,
      );
    }
    const scheme = parts[0];
    const token = parts[1];

    if (!/^Bearer$/i.test(scheme)) {
      logger.error(`Middelware : jwt validator failed`);
      return apiHandler.responseHandler(
        {},
        Constants.ErrorMessage.INVALID_TOKEN,
        Constants.Http.UNAUTHORIZED,
        res,
      );
    }
    const decoded = jwt.verify(token, secret?.JWT_SECRET);
    req.body.jwtDecodedUser = decoded;
    logger.info(`Middelware : jwt validator passed`);
    next();
  } catch (err) {
    logger.error(`Middelware : jwt validator failed`);
    return apiHandler.responseHandler(
      {},
      Constants.ErrorMessage.INVALID_TOKEN,
      Constants.Http.UNAUTHORIZED,
      res,
    );
  }
};
