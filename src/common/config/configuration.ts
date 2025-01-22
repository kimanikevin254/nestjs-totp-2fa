import { registerAs } from '@nestjs/config';

interface Config {
  db: {
    user: string;
    password: string;
    database: string;
    port: number;
    host: string;
  };
  jwt: {
    secret: string;
    ttl: string;
  };
}

export default registerAs<Config>('config', () => ({
  db: {
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    port: parseInt(process.env.DB_PORT),
    host: process.env.DB_HOST,
  },
  jwt: {
    secret: process.env.JWT_SECRET,
    ttl: process.env.JWT_TTL_MINS,
  },
}));
