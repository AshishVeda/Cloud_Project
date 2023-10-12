const express = require('express');
const multer = require('multer');
const AWS = require('aws-sdk');
const path = require('path');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const serverless = require("serverless-http");
require('dotenv').config();

const app = express();
const port = 3000;

app.use(express.static('public'));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static('uploads'));

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

// Middleware to verify JWT
function authenticateJWT(req, res, next) {
    // console.log(req.header("authorization"));
    try {
        const token = req.cookies.token;
        console.log(token);
        if (!token) return res.redirect("/auth?error=" + encodeURIComponent('Please login again, Token not available')); // Forbidden if no token provided

        jwt.verify(token, JWT_SECRET, (err, user) => {
            if (err) {
                return res.redirect("/auth?error=" + encodeURIComponent('Please login again, Token not verified')); // Forbidden if token is invalid
            }
            req.user = user;
            res.locals.user = user;

            next(); // Continue with the request processing
        });
    } catch (err) {
        console.log(err);
        res.redirect("/auth");
    }

}

connection.connect(function (err) {
    if (err) {
        console.error('Database connection failed: ' + err.stack);
        return;
    }

    console.log('Connected to database.');
});

app.get('/auth', (req, res) => {
    var error = req.query.error;

    res.render(path.join(__dirname, 'views', 'index.ejs'), { error: error });
});

app.post('/auth/register', (req, res) => {
    const UserName = req.body.UserName;
    const FirstName = req.body.FirstName;
    const LastName = req.body.LastName;
    const password = req.body.password;
    console.log(UserName, FirstName, LastName, password);
    // Hash the password
    bcrypt.hash(password, 10, (err, hash) => {
        if (err) {
            res.send(err);
        }

        // Store user data in the database
        connection.query('INSERT INTO AUTHUSERS (UserName, FirstName, LastName, Password) VALUES (?, ?, ?, ?)', [UserName, FirstName, LastName, hash], (error, results, fields) => {
            if (error) throw error;
            res.redirect('/auth');
        });
    });
});


app.post('/auth/login', (req, res) => {
    const username = req.body.UserName;
    const password = req.body.password;

    // Retrieve user data from the database
    connection.query('SELECT * FROM AUTHUSERS WHERE UserName = ?', [username], (error, results, fields) => {
        if (error) throw error;

        if (results.length > 0) {
            const user = results[0];
            // console.log(user.password, password);
            // Compare hashed password with the provided password
            bcrypt.compare(password, user.Password, (err, result) => {
                if (err) throw err;

                if (result) {
                    // Generate JWT token if passwords match  

                    const token = jwt.sign({ username: user.UserName, id: user.UserId }, JWT_SECRET, { expiresIn: '1h' });
                    // res.status(200).json({ token });
                    console.log(token);
                    res.cookie('token', token, {
                        httpOnly: true,
                        secure: true,
                        sameSite: 'strict'
                    });

                    res.redirect("/upload");
                } else {
                    res.redirect("/auth?error=" + encodeURIComponent('Invalid Credentials'));
                }
            });
        } else {
            res.redirect("/auth?error=" + encodeURIComponent('Invalid Credentials'));
        }
    });
});

app.get("/logout", authenticateJWT, function (req, res) {
    res.cookie("token", "", { maxAge: 1 });
    res.redirect("/auth");
})

/////////////////////////////////////////////////////////////////

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
            // console.log(currUser);
            s3.listObjects(params, async (err, data) => {
                if (err) {
                    console.error('Error listing objects in S3 bucket:', err);
                } else {

                    var temp = []; var count = 0;
                    for (const object of data.Contents) {
                        const metadata = await getObjectMetadata(object.Key);
                        if (metadata && metadata.username) {
                            console.log(metadata.username, currUser);
                            if (metadata.username == currUser.UserName) {
                                object["metadata"] = metadata;
                                temp.push(object);
                            }

                        }
                        // console.log(metadata);
                    }


                    res.render("upload.ejs", { files: temp });
                }
            });
        }
    });
    // console.log(currUser);

    // res.render("upload.ejs");
})

// app.post('/upload', authenticateJWT, upload.single('file'), (req, res) => {
//     const file = req.file;
//     const desc = req.body.FileDesc;

//     if (!file) {
//         return res.status(400).send('No file uploaded.');
//     }
//     connection.query('SELECT * FROM AUTHUSERS WHERE UserName = ?', [res.locals.user.username], (error, results, fields) => {
//         if (error) throw error;

//         if (results.length > 0) {
//             const currUser = results[0];
//             const fileContent = require('fs').readFileSync(file.path);
//             const params = {
//                 Bucket: process.env.S3_BUCKET_NAME,
//                 Key: file.originalname,
//                 Body: fileContent,
//                 Metadata: {
//                     UserName: currUser.UserName, // Replace this with the actual username of the uploader
//                     desc: desc,
//                     uploadTime: new Date().toISOString(),
//                     updateTime: new Date().toISOString()
//                 }
//             };
//             console.log(params);

//             s3.upload(params, (err, data) => {
//                 if (err) {
//                     console.error('Error uploading file:', err);
//                     return res.status(500).send('Error uploading file to S3.');
//                 }

//                 require('fs').unlinkSync(file.path);
//                 const fileUrl = data.Location;
//                 res.status(200).send(`File uploaded to: ${fileUrl}`);
//             });
//         }
//     });

// });

app.post('/upload', authenticateJWT, upload.single('file'), (req, res) => {
    const file = req.file;
    const desc = req.body.FileDesc;

    if (!file) {
        return res.status(400).send('No file uploaded.');
    }

    const currUser = res.locals.user.username;
    const fileContent = require('fs').readFileSync(file.path);
    const params = {
        Bucket: process.env.S3_BUCKET_NAME,
        Key: file.originalname,
        Body: fileContent,
        Metadata: {
            UserName: currUser, // Replace this with the actual username of the uploader
            desc: desc,
            uploadTime: new Date().toISOString(),
            updateTime: new Date().toISOString()
        }
    };
    console.log(params);

    s3.upload(params, (err, data) => {
        if (err) {
            console.error('Error uploading file:', err);
            return res.status(500).send('Error uploading file to S3.');
        }

        require('fs').unlinkSync(file.path);
        const fileUrl = data.Location;
        res.redirect("/upload");
    });



});


app.post("/update", authenticateJWT, upload.single('file'), async (req, res) => {
    const updatedFile = req.file;
    const desc = req.body.FileDesc;
    const Key = req.body.fileKey;
    console.log("updated route")
    console.log(updatedFile, desc, Key);
    if (!updatedFile) {
        return res.status(400).send('No file uploaded.');
    }
    var metadata = await getObjectMetadata(Key);
    console.log(metadata);
    metadata["updatetime"] = new Date().toISOString();
    console.log(metadata);

    const updatedFileContent = require('fs').readFileSync(updatedFile.path);
    const putObjectParams = {
        Bucket: process.env.S3_BUCKET_NAME,
        Key: updatedFile.originalname,
        Body: updatedFileContent,
        Metadata: metadata
    };

    s3.putObject(putObjectParams, (err, data) => {
        if (err) {
            console.error('Error uploading file:', err);
            return res.status(500).send('Error uploading file to S3.');
        }
        res.redirect("/upload");
    });

});

app.get("/list", authenticateJWT, (req, res) => {
    const params = {
        Bucket: process.env.S3_BUCKET_NAME
    };

    s3.listObjects(params, (err, data) => {
        if (err) {
            console.error('Error listing objects in S3 bucket:', err);
        } else {
            console.log('Objects in the bucket:');
            var temp = []; var count = 0;
            data.Contents.forEach((object) => {
                temp.push(object);
                // console.log(object);
            });
            console.log(temp);
            res.render("list.ejs", { files: temp });
        }
    });
});

app.post("/delete/:id", (req, res) => {
    var currObj = req.params.id;
    const params = {
        Bucket: process.env.S3_BUCKET_NAME,
        Key: currObj
    };
    s3.deleteObject(params, (err, data) => {
        if (err) {
            console.error('Error deleting object:', err);
        } else {
            console.log('Object deleted successfully:', data);
        }
    });
    res.redirect("/upload");
})

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});


// module.exports.handler = serverless(app);