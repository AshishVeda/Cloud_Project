var mysql = require('mysql');

var connection = mysql.createConnection({
    host: "userauth.cnipypphagbj.us-east-1.rds.amazonaws.com",
    user: "admin",
    password: "Password",
    port: 3306,
    database: "USERS"
});

connection.connect(function (err) {
    if (err) {
        console.error('Database connection failed: ' + err.stack);
        return;
    }

    console.log('Connected to database.');
});

// CREATE TABLE USERS (UserID INT AUTO_INCREMENT PRIMARY KEY, FirstName VARCHAR(255) NOT NULL, LastName VARCHAR(255) NOT NULL, Password VARCHAR(255) NOT NULL)
// connection.query("SHOW DATABASES;", (err, res) => {
//     if (err) {
//         console.log(err);
//     } else {
//         console.log(res);
//     }

// })
// connection.query("CREATE DATABASE USERS;", (err, res) => {
//     if (err) {
//         console.log(err);
//     } else {
//         console.log("Database created");
//     }

// });
// connection.query("SELECT DATABASES;", (err, res) => {
//     if (err) {
//         console.log(err);
//     } else {
//         console.log(res);
//     }

// });

// connection.query("CREATE TABLE AUTHUSERS (UserID INT AUTO_INCREMENT PRIMARY KEY, FirstName VARCHAR(255) NOT NULL, LastName VARCHAR(255) NOT NULL, Password VARCHAR(255) NOT NULL, UserName VARCHAR(255) UNIQUE NOT NULL);", (err, res) => {
//     if (err) {
//         console.log(err);
//     } else {
//         console.log("Created table");
//     }
// });


connection.end();