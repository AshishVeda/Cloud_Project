const express = require('express');
const multer = require('multer');
const AWS = require('aws-sdk');
const path = require('path');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const axios = require('axios');
const cors = require('cors');




require('dotenv').config();

const app = express();
const port = 3000;

app.use(express.static('public'));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static('uploads'));
app.use(cors({
    origin: 'http://44.192.39.79:4000', // Allow requests from this origin
    credentials: true // Enable credentials (cookies, authorization headers, etc.)
}));

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
        console.log(token);
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
    const userType = req.body.userType;

    bcrypt.hash(password, 10, (err, hash) => {
        if (err) {
            res.send(err);
        }

        connection.query('INSERT INTO AUTHUSERS (UserName, FirstName, LastName, Password, UserRole) VALUES (?, ?, ?, ?, ?)', [UserName, FirstName, LastName, hash, userType], (error, results, fields) => {
            if (error) throw error;
            res.redirect('http://44.192.39.79:4000/auth');
        });
    });
});


app.post('/auth/login', (req, res) => {
    
    const username = req.body.UserName;
    const password = req.body.password;
    const userType = req.body.userType;

    connection.query('SELECT * FROM AUTHUSERS WHERE UserName = ? and UserRole = ?', [username, userType], (error, results, fields) => {
        if (error) throw error;

        if (results.length > 0) {
            const user = results[0];
            bcrypt.compare(password, user.Password, (err, result) => {
                if (err) throw err;

                if (result) {
                    
                    const token = jwt.sign({ username: user.UserName, id: user.UserId }, JWT_SECRET, { expiresIn: '1h' });

                    res.cookie('token', token, {SameSite:'None', secure: true });
                    const userRole = user.UserRole;

                    res.cookie('role', userRole, {SameSite:'None', secure: true });
                    if (userRole === 'admin') {
                        // res.redirect("/admin/dashboard"); 
                        res.redirect('http://44.192.39.79:4000/admin/dashboard');

                    } else {
                        // res.redirect("/upload"); 
                        res.redirect('http://44.192.39.79:4000/upload');
                        // res.status(200).json({
                        //     success: true,
                        //     message: 'Registration successful!',
                        //     redirectURL: '/success' // Specify the redirect URL for a successful registration
                        // });
                    }
                    
                } else {
                    res.redirect("http://44.192.39.79:4000/auth?error=" + encodeURIComponent('Invalid Credentials'));
                }
            });
        } else {
            res.redirect("http://44.192.39.79:4000/auth?error=" + encodeURIComponent('Invalid Credentials'));
        }
    });
});

app.get("/logout", authenticateJWT, function (req, res) {
    res.cookie("token", "", { maxAge: 1 });
    res.redirect("http://44.192.39.79:4000/auth");
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

async function addData(results, metadata, object) {
    for (var i = 0; i < results.length; i++) {
        if (results[i].UserName == metadata.username) {
            if (results[i]["Key"]) {
                results[i]["Key"].push(object.Key);
            } else {
                results[i]["Key"] = [object.Key];
            }
        }
    }
    return results;
}
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


app.post('/admin/delete/:userId/:id', authenticateJWT, (req, res) => {

    const userId = req.params.userId;
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
    console.log("deleted object by admin");
    res.redirect("http://44.192.39.79:4000/admin/dashboard/" + userId);


});

// app.get("/upload", authenticateJWT, (req, res) => {
//     const params = {
//         Bucket: process.env.S3_BUCKET_NAME
//     };


//     connection.query('SELECT * FROM AUTHUSERS WHERE UserName = ?', [res.locals.user.username], (error, results, fields) => {
//         if (error) throw error;

//         if (results.length > 0) {
//             const currUser = results[0];
//             s3.listObjects(params, async (err, data) => {
//                 if (err) {
//                     console.error('Error listing objects in S3 bucket:', err);
//                 } else {

//                     var temp = []; var count = 0;
//                     for (const object of data.Contents) {
//                         const metadata = await getObjectMetadata(object.Key);
//                         if (metadata && metadata.username) {
//                             if (metadata.username == currUser.UserName) {
//                                 object["metadata"] = metadata;
//                                 temp.push(object);
//                             }

//                         }
//                     }

//                     console.log("Listing objects");
//                     res.render("upload.ejs", { files: temp });
//                 }
//             });
//         }
//     });
// })


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
            UserName: currUser, 
            desc: desc,
            uploadTime: new Date().toISOString(),
            updateTime: new Date().toISOString()
        }
    };

    s3.upload(params, (err, data) => {
        if (err) {
            console.error('Error uploading file:', err);
            return res.status(500).send('Error uploading file to S3.');
        }

        require('fs').unlinkSync(file.path);
        const fileUrl = data.Location;
        console.log("uploaded object");
        res.redirect("http://44.192.39.79:4000/upload");
    });



});


app.post("/update", authenticateJWT, upload.single('file'), async (req, res) => {
    const updatedFile = req.file;
    const desc = req.body.FileDesc;
    const Key = req.body.fileKey;

    if (!updatedFile) {
        return res.status(400).send('No file uploaded.');
    }
    var metadata = await getObjectMetadata(Key);
    
    metadata["updatetime"] = new Date().toISOString();
    metadata["desc"] = desc;
    

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
        console.log("updated object");
        res.redirect("http://44.192.39.79:4000/upload");
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
            
            var temp = []; var count = 0;
            data.Contents.forEach((object) => {
                temp.push(object);
               
            });
            console.log("Listing all objects");
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
    res.redirect("http://44.192.39.79:4000/upload");
})

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});

