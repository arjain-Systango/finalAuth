import path from 'path';
import { DataSourceOptions } from 'typeorm';

import { SSMService } from '../service/ssm.service';

async function getConfig() {
  let secret = SSMService.secret;

  if (!secret) {
    secret = await SSMService.getSecretManagerValue();
  }

  return {
    type: secret?.DB_DIALECT,
    host: secret?.DB_HOST,
    port: secret?.DB_PORT,
    username: secret?.DB_USER,
    password: secret?.DB_PASSWORD,
    database: secret?.DB_NAME,
    entities: [path.join(__dirname + '/entity/**/*.{ts,js}')],
    migrations: [path.join(__dirname + '/migration/**/*.{ts,js}')],
    seeds: [path.join(__dirname + '/seeder/**/*.{ts,js}')],
    synchronize: false,
    logging: false,
  } as DataSourceOptions;
}

export = getConfig;
