import { createPool } from "mysql2/promise";
import { DB_HOST, DB_USER, DB_PASSWORD, DB_NAME, DB_PORT} from "./config.js";
import fs from 'fs'

export const pool = createPool({
    host: DB_HOST,
    user: DB_USER,
    password: DB_PASSWORD,
    database: DB_NAME,
    port: DB_PORT
});

try {
    let sql = fs.readFileSync('src/db/user.sql', 'utf8');
    await pool.query(sql)
} catch (err) {
    console.error('Error al ejecutar comandos SQL:', err);
}