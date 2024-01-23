import { Response } from 'express';

import { Constants } from '../const/constants';

class ApiHandler {
  constructor() {}

  errorHandler(err: any, res: Response) {
    // Error handling for Joi validation errors
    if (err && err.isJoi) {
      const body = {
        error: `${err.name ? err.name : ''}: `,
      };
      res.status(Constants.Http.BAD_REQUEST);
      if (err.details && err.details.length) {
        err.details.forEach((element: { message: string }) => {
          if (element.message) {
            body.error += element.message.replace(/"/g, '');
          }
        });
      }
      body.error = body.error.replace('ValidationError:', '').trim();
      res.json({
        message: body.error,
        data: {},
        status: Constants.Http.BAD_REQUEST,
      });
    } else {
      res.status(
        err.statusCode ? err.statusCode : Constants.Http.INTERNAL_SERVER_ERROR,
      );
      res.json({
        message: err.error
          ? err.error.error && err.error.error.message
            ? err.error.error.message
            : err.error.error
          : err.message,
        data: {},
        status: Constants.Http.INTERNAL_SERVER_ERROR,
      });
    }
  }

  responseHandler(
    data: any,
    message: string,
    statusCode: number,
    res: Response,
  ) {
    res.status(statusCode);
    res.json({
      message: message,
      data: data,
      status: statusCode,
    });
  }
}

const apiHandler: ApiHandler = new ApiHandler();
export default apiHandler;
