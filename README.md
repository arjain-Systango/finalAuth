# Authentication Service using NodeJS

This project is a Authentication Service implemented using Node.js, Express, TypeORM, Postgres, TypeScript, AWS Secret Manager, AWS Parameter Store.

## Overview

The Authentication Service provides a seamless solution for managing authentication processes,  integrated with various Single Sign-On (SSO) login methods, two-factor authentication, and handling forgot password scenarios. Additionally, it facilitates CRUD (Create, Read, Update, Delete) operations for user management. To enhance security, sensitive information is managed through integration with AWS Secret Manager and AWS Parameter Store.

## Table of Contents

- [Getting Started](#getting-started)
  - [Pre-requisites](#pre-requisites)
  - [Add initial env variables](#add-initial-env-variables)
  - [Installation](#installation)
  - [Build](#build)
  - [Run](#run)
- [Technologies Used](#technologies-used)
- [Configuration](#Configuration)
- [Swagger URL](#swagger-url)

## Getting Started

### Pre-requisites

Before you begin, ensure you have the following installed:

- https://nodejs.org/
- https://www.npmjs.com/

AWS account with following services:
- Different IAM roles for all aws services
- IAM role for a secret manager with read access. Add its credentials in .env
- IAM role for a parameter store with read access, Add these credentials in secret manager


### Add initial env variables
Rename the `.env.example` file in the `backend` folder to `.env` and add the following .env variables:
- ### Required Keys:
  - `AWS_ACCESS_KEY_ID={YOUR_ACCESS_KEY}` // used to initialize the secret manager
  - `AWS_SECRET_ACCESS_KEY={YOUR_AWS_SECRET_ACCESS_KEY}` // used to initialize the secret manager
  - `AWS_REGION={YOUR_AWS_REGION}`
  - `APP_NAME={YOUR_APP_NAME}` // This could be anything. 
  - `APP_ENV={YOUR_NODE_ENV}` // This could be your environment like local, dev, stage, or prod
- #### Other env variable required if not set in SSM
  - `APP_PORT={YOUR_APP_PORT}`
  - `DB_PORT={YOUR_DB_PORT}`
  - `DB_HOST={YOUR_DB_HOST}`
  - `DB_DIALECT={YOUR_DB_DIALECT}`
  - `DB_USER={YOUR_DB_USER}`
  - `DB_PASSWORD={YOUR_DB_PASSWORD}`
  - `DB_NAME={YOUR_DB_NAME}`
  - `JWT_SECRET={YOUR_JWT_SECRET}`
  - `JWT_EXPIRE={YOUR_JWT_EXPIRE}`
  - `TRIGGER_EMAIL_URL={YOUR_TRIGGER_EMAIL_URL}`
  - `PARAMETER_STORE_AWS_ACCESS_KEY_ID={YOUR_PARAMETER_STORE_AWS_ACCESS_KEY_ID}`
  - `PARAMETER_STORE_AWS_SECRET_ACCESS_KEY={YOUR_PARAMETER_STORE_AWS_SECRET_ACCESS_KEY}`
  - `JWT_SYSTEM_ROLE={YOUR_JWT_SYSTEM_ROLE}`
  - `JWT_USER_ROLE={YOUR_JWT_USER_ROLE}`
  - `AWS_ACCESS_DENIED_EXCEPTION={YOUR_AWS_ACCESS_DENIED_EXCEPTION}`
  - `SESSION_SECRET={YOUR_SESSION_SECRET}`
  - `REFRESH_TOKEN_SECRET={YOUR_REFRESH_TOKEN_SECRET}`
  - `REFRESH_TOKEN_EXPIRE={YOUR_REFRESH_TOKEN_EXPIRE}`
  - `FRONT_END_HOST_URL={YOUR_FRONT_END_HOST_URL}`

### Installation

Run the following command to install project dependencies:

```bash
npm install
```
### Database migrations

Run the following command to create the tables in postgres database.

```bash
npm run migration:run
```
### Build
Create a production build using:
```bash
npm run build
```

### Run
To start the project in the production environment:
```bash
npm start
```

## Technologies Used

This project leverages the following technologies:

- ***Node.js:*** JavaScript runtime for server-side development.
- ***Express:*** Minimal and flexible Node.js web application framework.
- ***TypeScript:*** Typed superset of JavaScript that compiles to plain JavaScript.
- ***TypeORM:*** Library that makes it easy to link your TypeScript application up to a relational database.
- ***AWS Secret Manager:*** Securely store and manage sensitive information.
- ***AWS Parameter Store:*** Securely store and manage sensitive information and used to interact with notification service to send emails.

## Configuration

Before running the Authentication Service, ensure you have properly configured the following:

### AWS Secret Manager

1. *Set up AWS Secret Manager:*
   - Create a new secret in AWS Secret Manager containing the necessary credentials for your application.

2. *Update Credentials:*
   - In your application, update the Credentials in env to fetch and use credentials securely from AWS Secret Manager.

### AWS Parameter Store

1. *Set up AWS Parameter Store:*
   - Create a new key-value pairs in AWS Parameter Store containing the necessary credentials for your application.

2. *Update Credentials:*
   - Configure your application to use the AWS Parameter Store by updating the relevant credentials in AWS Secret Manager.

### Database Configuration

1. *set up Postgres Database:*
   - Create a database in postgres, in order to create the required tables by running the migrations.

2. *Update Credentials:*
   - Configure your application to use the postgres database by updating the relevant credentials in .env file.

Ensure that all configurations are correctly set before running the Authentication Service.

## Swagger URL
**http://localhost:3000/api-docs** 
The API flow for Authentication is mentioned in swagger.

