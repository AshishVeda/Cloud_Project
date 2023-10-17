const express = require('express');
const multer = require('multer');
const AWS = require('aws-sdk');
const path = require('path');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
// const app = express();
// const frontendPort = 4000;

require('dotenv').config();

const app = express();
const port = 4000;

app.use(express.static('public'));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static('uploads'));
app.use(cors());

AWS.config.update({
    accessKeyId: process.env.ENV_AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.ENV_AWS_SECRET_ACCESS_KEY,
    region: process.env.ENV_AWS_REGION
});

const s3 = new AWS.S3();

const upload = multer({ dest: 'uploads/' });

var mysql = require('mysql');

var connection = mysql.createConnection({
    host: "userauth.cnipypphagbj.us-east-1.rds.amazonaws.com",
    user: "admin",
    password: "Password",
    port: 3306,
    database: "USERS"
});

const JWT_SECRET = 'your_jwt_secret_key';

function authenticateJWT(req, res, next) {
    try {
        const token = req.cookies.token;
        if (!token) return res.redirect("/auth?error=" + encodeURIComponent('Please login again, Token not available')); // Forbidden if no token provided

        jwt.verify(token, JWT_SECRET, (err, user) => {
            if (err) {
                return res.redirect("/auth?error=" + encodeURIComponent('Please login again, Token not verified')); // Forbidden if token is invalid
            }
            req.user = user;
            res.locals.user = user;

            next(); 
        });
    } catch (err) {
        console.log(err);
        res.redirect("/auth");
    }

}



app.get('/auth', (req, res) => {
    var error = req.query.error;

    res.render(path.join(__dirname, 'views', 'index.ejs'), { error: error });
});

app.get('/admin/dashboard', authenticateJWT, (req, res) => {
    if (req.cookies.role === 'admin') {
        connection.query('SELECT * FROM AUTHUSERS', (error, results, fields) => {
            if (error) throw error;

            results = results.filter(function (obj) {
                return obj.UserRole !== 'admin';
            });
            console.log("objects listing ",results);
            res.render("adminDashboard.ejs", { users: results });
        });
    } else {
        res.redirect("/auth");
    }
});


app.get("/admin/dashboard/:id", authenticateJWT, (req, res) => {
    const params = {
        Bucket: process.env.S3_BUCKET_NAME
    };
    s3.listObjects(params, async (err, data) => {
        if (err) {
            console.error('Error listing objects in S3 bucket:', err);
        } else {

            var temp = []; var count = 0;
            for (const object of data.Contents) {
                const metadata = await getObjectMetadata(object.Key);
                if (metadata && metadata.username) {
                    if (metadata.username == req.params.id) {
                        object["metadata"] = metadata;
                        temp.push(object);
                    }

                }
            }
            console.log("Listing objects");
            res.render("adminDelete.ejs", { files: temp });
        }
    })
});

const getObjectMetadata = async (objectKey) => {
    const headParams = {
        Bucket: process.env.S3_BUCKET_NAME,
        Key: objectKey
    };
    try {
        const headData = await s3.headObject(headParams).promise();
        return headData.Metadata;
    } catch (error) {
        console.error(`Error fetching metadata for object ${objectKey}:`, error);
        return null;
    }
};


app.get("/upload", authenticateJWT, (req, res) => {
    const params = {
        Bucket: process.env.S3_BUCKET_NAME
    };


    connection.query('SELECT * FROM AUTHUSERS WHERE UserName = ?', [res.locals.user.username], (error, results, fields) => {
        if (error) throw error;

        if (results.length > 0) {
            const currUser = results[0];
            s3.listObjects(params, async (err, data) => {
                if (err) {
                    console.error('Error listing objects in S3 bucket:', err);
                } else {

                    var temp = []; var count = 0;
                    for (const object of data.Contents) {
                        const metadata = await getObjectMetadata(object.Key);
                        if (metadata && metadata.username) {
                            if (metadata.username == currUser.UserName) {
                                object["metadata"] = metadata;
                                temp.push(object);
                            }

                        }
                    }

                    console.log("Listing objects");
                    res.render("upload.ejs", { files: temp });
                }
            });
        }
    });
})


app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
