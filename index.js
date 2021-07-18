const https = require('https');
const http = require('http');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const express = require('express');
const ldap = require('ldapjs');
const fs = require('fs')
const speakeasy = require('speakeasy');
const mailer = require('nodemailer');
const tools = require('./tools/tools.js');
const session = require('express-session');
const server = express();
const useragent = require('useragent');

let bruteTemp = [];
let bruteDelta = [];
let compteurBrutforce = 1;
let mariadb = require('mariadb');
let con = mariadb.createPool({
    host: "192.168.1.29",
    user: "msprsecu",
    password: "Epsi#1234!",
    database: "mspr",
    port:3307
});
//setup emailer data
let transport = mailer.createTransport( {
    host: 'smtp.mailtrap.io',
    port: 2525,
    auth: {
        user: 'e2ac6dad04f2b0',
        pass: 'b75b5bf2169b79'
    }
});

let codeBarre = "";
let secretTemp = "";

con.getConnection()
    .then(conn => {
        conn.query("SELECT * FROM code ").then((res) => {
            codeBarre = '<img src="' + res[0].code + '">';
            secretTemp = res[0].secret;
        }).then(res => {
            conn.release();
          });
    });
    server.set('view engine', 'ejs');
server.use(bodyParser.urlencoded({ extended: true }));

server.get('/', (req, res) => {
    res.render('authentification', {img: codeBarre,message:""});
});

server.get('/authentification/', (req, res) => {
    res.render('authentification', {img: codeBarre,message:""});
});

server.post('/login', function(req, res){
    let userIp = req.ip;
    let nom = req.body.nom;
    let password = req.body.password;
    let ban = tools.checkIfIpIsBan(con, userIp);

    if(ban){
        res.render('ban');
    }

    let mail = authenticateDN("CN="+nom,password);

    if(mail && mail !== "PAS DE MAIL"){
        let agent = tools.recuperationAgentFromRequest(req,useragent);

        if(tools.checkUserAgent(mail,con,agent)){
            req.session.password = password;
            req.session.nom = nom;
            res.render('check');
        }else{
            let date = new Date();
            code = Math.random()*1000;
            tools.enAttente(code,mail,date,agent,con);
            tools.sendMailByType(mail, 1, transport,code);
            tools.declarationChangementSupport(mail,agent,date,con);
            res.render('wait');
        };
    }

    if(compteurBrutforce > 5) {
          tools.saveBruteForceData(con, bruteDelta, userIp, nom, transport)
          res.render('ban');
    }if(mail === "PAS DE MAIL"){
        res.render('authentification',{img: codeBarre,message:"Votre compte n'est pas paramétrer. Contactez l'administrateur."});
    }
    else {
          let timeStamp = new Date();
          bruteTemp.push(timeStamp);
          res.render('authentification',{img: codeBarre,message:"Mot de passe ou nom de compte invalide"});
      }
});

server.get('/valide',function(req,res){
    res.render('valide');
})

//Après envoie de mail
server.post('/valide', function(req, res) {
    let code = req.body.code;
    let mail = req.body.mail;
    if(mail && code){
        if(tools.checkValide(con,mail,code)){
            let agent = tools.getAgentFromAccessValidation(con,mail,code);
            tools.updateAccess(con,mail,agent);
            res.render('authentification',{img: codeBarre,message:"Vous pouvez maintenant vous reconnecter"});
        }
    }
    res.render('authentification',{img: codeBarre,message:"Impossible de réaliser la mise à jour"});
});


server.post('/check', function(req, res) {
    let code = req.body.code; // récupération du code depuis l'authentification Google
    let verified = speakeasy.totp.verify({
        secret : secretTemp,
        encoding: 'base32',
        token: code
    });
    
    //Récupération des données depuis la session
    let password = req.session.password;
    let nom = req.session.nom;

    // verification
    let corrompu = tools.check_password_api(password,crypto,https);
    
    if(verified) {
        res.render('login',{corrompu:corrompu});
    }else{
        res.render('authentification',{img: codeBarre,message:""});
    }
})

server.get('/logout', function(req, res){
    req.session.destroy();
    res.render('authentification',{img: codeBarre,message:""});
});

server.use(express.static(__dirname + '/public'));

/* START SERVEUR*/
https.createServer({
    key: fs.readFileSync('server.key'),
    cert: fs.readFileSync('server.cert')
  }, server)
  .listen(443, function () {
    console.log('Express Server is running... https://localhost:443/');
});

//Forcé la redirection
const httpApp = express();
httpApp.get("*", function(request, response){
  response.redirect("https://" + request.headers.host + request.url);
});
httpApp.listen(80, () => console.log(`HTTP server listening: http://localhost:80`));

function authenticateDN(username,password){
    let sufix = "DC=chatelet-mspr,DC=ovh";
    let sync = true;
    let valeur_retour = false;
    let client = ldap.createClient({
        url: "ldap://192.168.1.29:389"
    });
    if(!password){
        password = " ";
    }

    let appelBind = username + ",CN=Users," + sufix;
    client.bind(appelBind,password,function(err){
        if(!err){
            client.search(sufix,{ filter: "("+username+")",attributes: ['dn', 'sn', 'cn',"mail",],scope: 'sub',},(err,res) => {
                res.on('searchEntry', function(entry) {
                    mail = JSON.stringify(entry.object.mail);
                    if(mail){
                        valeur_retour = mail.replace('"','').replace('"','');
                    }else{
                        valeur_retour="PAS DE MAIL";
                    }
                });
            });
        }
        sync = false;
    });
    while(sync) {require('deasync').sleep(100);}
    return valeur_retour;
};