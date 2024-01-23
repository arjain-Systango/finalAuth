import express from 'express';

import usersController from '../controller/users.controller';
import { ensureAdminValidator } from '../middlewares/ensureAdminValidator';
import { jwtValidator } from '../middlewares/jwtValidator';
import { requestValidator } from '../middlewares/requestValidator';
import userValidator from '../validation/user.validator';
const router = express.Router();
/**
 * @swagger
 * /users/{id}:
 *   get:
 *     security:
 *       - bearerAuth: []
 *     summary: Find user by id
 *     description: Return user details, can be used by admin or user
 *     tags: [User]
 *     produces:
 *       - application/json
 *     parameters:
 *       - in: path
 *         name: id
 *         format: number
 *         schema:
 *           type: number
 *         required: true
 *         description: Id of user to return details
 *     responses:
 *       '200':
 *         description: user details fetched successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: user details fetched successfully
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
 *                       example: 8888000034
 *                     role:
 *                       type: string
 *                       format: string
 *                       example: user
 *                     authType:
 *                       type: string
 *                       format: string
 *                       example: email
 *                     firstName:
 *                       type: string
 *                       format: string
 *                       example: john
 *                     lastName:
 *                       type: string
 *                       format: string
 *                       example: doe
 *                     createdAt:
 *                       type: string
 *                       format: date-time
 *                       example: '2023-06-12T08:48:33.398Z'
 *                     updatedAt:
 *                       type: string
 *                       format: date-time
 *                       example: '2023-06-12T08:48:33.398Z'
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 200
 *       '400':
 *         description: Bad Request
 *       '401':
 *         description: Invalid Token Or Invalid User
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Invalid User
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
 *       500:
 *         description: Internal server error
 */
router.get(
  '/:id',
  jwtValidator,
  requestValidator(userValidator.getUserSchema, 'params'),
  usersController.getUserDetails,
);

/**
 * @swagger
 * /users/{id}:
 *   put:
 *     security:
 *       - bearerAuth: []
 *     summary: update user details by id
 *     description: update user details by id, only user can update it's details
 *     tags: [User]
 *     parameters:
 *       - name: id
 *         in: path
 *         format: number
 *         description: id of the user
 *         required: true
 *         schema:
 *           type: number
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               firstName:
 *                 type: string
 *                 format: string
 *                 example: 'john'
 *               lastName:
 *                 type: string
 *                 format: string
 *                 example: 'wick'
 *     responses:
 *       '200':
 *         description: user updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: user updated successfully
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
 *                   example: lastName is not allowed to be empty
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 400
 *       '401':
 *         description: Invalid Token Or Invalid User
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Invalid User
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 401
 *       500:
 *         description: Internal server error
 */
router.put(
  '/:id',
  jwtValidator,
  requestValidator(userValidator.updateUserBodySchema, 'body'),
  requestValidator(userValidator.updateUserParamSchema, 'params'),
  usersController.updateUser,
);

/**
 * @swagger
 * /users:
 *   get:
 *     security:
 *       - bearerAuth: []
 *     summary: Return user list
 *     description: Return user list, only admin can use this api
 *     tags: [User]
 *     produces:
 *       - application/json
 *     parameters:
 *       - in: query
 *         name: page
 *         schema:
 *           type: number
 *       - in: query
 *         name: limit
 *         schema:
 *           type: number
 *     responses:
 *       200:
 *         description: users details fetched successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: users details fetched successfully
 *                 data:
 *                   type: object
 *                   format: object
 *                   properties:
 *                     usersList:
 *                       type: array
 *                       items:
 *                         type: object
 *                         properties:
 *                           id:
 *                             type: number
 *                             example: 3
 *                           email:
 *                             type: string
 *                             example: john@example.com
 *                           firstName:
 *                             type: string
 *                             example: john
 *                           lastName:
 *                             type: string
 *                             example: doe
 *                           role:
 *                             type: string
 *                             example: admin
 *                           authType:
 *                             type: string
 *                             example: email
 *                           isActive:
 *                             type: boolean
 *                             example: true
 *                           createdAt:
 *                             type: string
 *                             format: date-time
 *                             example: "2023-11-23T08:14:44.793Z"
 *                           updatedAt:
 *                             type: string
 *                             format: date-time
 *                             example: "2023-11-23T08:14:44.793Z"
 *                     totalCount:
 *                       type: number
 *                       format: number
 *                       example: 10
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 200
 *       '400':
 *         description: Bad Request
 *       '401':
 *         description: unauthorized
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
 *       '403':
 *         description: forbidden
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Invalid User
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
router.get(
  '/',
  jwtValidator,
  ensureAdminValidator,
  requestValidator(userValidator.getUserListSchema, 'query'),
  usersController.getUserList,
);

/**
 * @swagger
 * /users/{id}:
 *   delete:
 *     security:
 *       - bearerAuth: []
 *     summary: soft delete user by id
 *     description: Delete user by userId - user can delete itself or admin can delete user
 *     tags: [User]
 *     produces:
 *       - application/json
 *     parameters:
 *       - in: path
 *         name: id
 *         format: number
 *         schema:
 *           type: number
 *         required: true
 *         description: Id of user to return details
 *     responses:
 *       '200':
 *         description: user deleted successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: user deleted successfully
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 200
 *       '400':
 *         description: Bad Request
 *       '401':
 *         description: Invalid Token Or Invalid User
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   format: string
 *                   example: Invalid User
 *                 data:
 *                   type: object
 *                   format: object
 *                   example: {}
 *                 status:
 *                   type: number
 *                   format: number
 *                   example: 401
 *       500:
 *         description: Internal server error
 */
router.delete(
  '/:id',
  jwtValidator,
  requestValidator(userValidator.deleteUserSchema, 'params'),
  usersController.deleteUserById,
);
export default router;
