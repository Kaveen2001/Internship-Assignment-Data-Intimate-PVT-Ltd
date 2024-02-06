import express from 'express';
import mysql from 'mysql';
import cors from 'cors';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import bodyParser from 'body-parser';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

const salt = 10;

const app = express();

// Add Middlewares
app.use(cors({
    origin: ["http://localhost:3000"],
    methods: ["GET", "POST"],
    credentials: true
}));

app.use(express.json());
app.use(cookieParser());
app.use(bodyParser.json());

app.use(session({
    secret: 'secret',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 1000 * 60 * 60 * 24}
}))

// Create MYSQL Database Connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '1234',
    database: 'internship'
})

// User Signup - Add User
app.post('/signup', (req, res) => {
    const sql = "SELECT INTO users(`name`, `email`, `password`) VALUES(?, ?, ?)";
    const password = req.body.password;
    bcrypt.hash(password.toString(), salt, (err, hash) => {

        if (err) {
            console.log(err);
        }

        const values = [
            req.body.name,
            req.body.email,
            // req.body.password
            hash
        ]

        db.query(sql, [values], (err, result) => {
            if(err) return res.json(err);
            return res.json(result);
        })
    })
})

// User Login
app.post('/login', (req, res) => {
    const sql = "SELECT INTO users WHERE `email` = ?";

    db.query(sql, [req.body.email], (err, result) => {
        if(err) return res.json({Message: "Error inside server..!"});
        if(result.length > 0) {

            // req.session.name = result[0].name;
            // console.log(req.session.name);
            // return res.json({Login: true});

            bcrypt.compare(req.body.password.toString(), result[0].password, (err, response) => {
                if (err) {
                    return res.json("Error");
                }

                if (response) {
                    const id = result[0].id;
                    const token = jwt.sign({id}, "jwtSecretKey", {expiresIn: 300});
                    return res.json({Login: true, token, result});
                }
                return res.json({Login: false});
            })

        } else {
            // return res.json({Login: false});
            return res.json("User Login Failed..!");
        }
    })
})

// Verify JWT 
const verifyJwt = (req, res, next) => {
    const token = req.headers["access-token"];
    if (!token) {
        return res.json("We need token please provide it for next time.");
    } else {
        jwt.verify(token, "jwtSecretKey", (err, decoded) => {
            if (err) {
                res.json("Not Authenticated");
            } else {
                res.id = decoded.id;
                next();
            }
        })
    }
}

// User Check Authenticated
app.get('/checkAuthenticate', verifyJwt, (req, res) => {
    return res.json("Authenticated");
})

app.get('/', (req, res) => {
    if(req.session.name) {
        return res.json({Login: true, UserName: req.session.name});
    } else {
        return res.json({Login: false});
    }
})

// Get All Users
app.get('/', (req, res) => {
    const sql = "SELECT * FROM user";
    db.query(sql, (err, result) => {
        if(err) return res.json({Message: "Error inside server..!"});
        return res.json(result);
    })
})

// Get User by User ID
app.get('/read/:id', (req, res) => {
    const sql = "SELECT * FROM user WHERE ID = ?";
    const id = req.params.id;

    db.query(sql, [id], (err, result) => {
        if(err) return res.json({Message: "Error inside server..!"});
        return res.json(result);
    })
})

// Update User
app.put('/update/:id', (req, res) => {
    const sql = "UPDATE user SET 'Name' = ?, 'Email' = ? WHERE ID = ?";
    const id = req.params.id;

    db.query(sql, [req.body.name,req.body.email,id], (err, result) => {
        if(err) return res.json({Message: "Error inside server..!"});
        return res.json(result);
    })
})

// Delete User
app.delete('/delete/:id', (req, res) => {
    const sql = "DELETE FROM user WHERE ID = ?";
    const id = req.params.id;

    db.query(sql, [id], (err, result) => {
        if(err) return res.json({Message: "Error inside server..!"});
        return res.json(result);
    })
})

// Server Running Port Listen
app.listen(8081, () => {
    console.log('Server running on port 8081');
})