import { NextFunction, Request, Response } from 'express';

import apiHandler from '../utils/ApiHandler';

export const requestValidator = (
  schema: any,
  validationPart: 'body' | 'params' | 'query' | 'headers',
) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const { error } = schema.validate(req[validationPart], {
      abortEarly: false,
    });
    if (error) {
      return apiHandler.errorHandler(error, res);
    } else {
      next();
    }
  };
};
