import {Router} from "express";
import {pool} from "../db.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const router = Router()

router.get('/ping', async (req, res) => {
    const [result] = await pool.query('SELECT 1 + 1 AS result')
    res.json(result)
})

router.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            res.status(400).send("username and password is required");
            return;
        }

        const hashedPassword = await bcrypt.hash(password, 4);
        const query = 'INSERT INTO users (username, password) VALUES (?, ?)';

        await pool.query(query, [username, hashedPassword]);
        res.send({
            message: "Usuario registrado existosamente"
        })
    } catch (error) {
        return res.status(500).json({
            message: "Something goes wrong, " + error
        })
    }
});

router.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        const [result] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
        if (result.length === 0) {
            res.status(401).send({ message: 'Credenciales incorrectas' });
        } else {
            const match = bcrypt.compare(password, result[0].password);

            if (match) {
                const token = jwt.sign({ username }, 'secretkey', { expiresIn: '1h' });

                res.cookie('token', token, { httpOnly: true });
                res.status(200).send({ message: 'Inicio de sesión exitoso', token });
            } else {
                res.status(401).send({ message: 'Credenciales incorrectas' });
            }
        }
    }
    catch (error) {
        return res.status(500).json({
            message: "Something goes wrong" + error
        })
    }
});

router.get('/protected', (req, res) => {
    if (!req.cookies.token) {
        res.status(401).send({ message: 'Acceso no autorizado' });
    } else {
        jwt.verify(token, 'secretkey', (err, decoded) => {
            if (err) {
                res.status(401).send({ message: 'Token inválido' });
            } else {
                res.status(200).send({ message: 'Acceso autorizado', user: decoded });
            }
        });
    }
});

export default router