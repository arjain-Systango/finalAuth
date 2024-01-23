/* eslint-disable no-console */
import { DataSource } from 'typeorm';

import logger from '../config/logger';
import getConfig from './dataSourceOptions';

// Export of dataSource instance is required to run migration
export class DatabaseInitialization {
  public static dataSource: DataSource;
  public static AppDataSource: DataSource;

  static async dataSourceInstance() {
    this.AppDataSource = new DataSource(await getConfig());

    return this.AppDataSource;
  }

  static async dbCreateConnection() {
    try {
      if (!this.AppDataSource) {
        await this.dataSourceInstance();
      }

      // Check if datasource in already initialized
      if (!this.dataSource) {
        this.dataSource = await this.AppDataSource.initialize();
        logger.info('db connected');
      }

      // return datasource
      return this.dataSource;
    } catch (err) {
      logger.error(err);
    }
    return null;
  }
}

export default DatabaseInitialization.dataSourceInstance();
