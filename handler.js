'use strict';
const express = require('express');
const bodyParser = require('body-parser');

const app = require("./app");
const serverless = require("serverless-http");


const app = express();
app.use(bodyParser.json());

module.exports.hello = serverless(app); 
