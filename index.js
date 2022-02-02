const express = require("express");
const fs = require("fs");
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const saltRounds = 10;
const app = express();


//get other user info
app.get("/users" ,(req,res)=>{
    fs.readFile("data.json" , "utf8", (error, data) =>{
        if(error){
            res.send("Something went wrong");
        }
        else{
            let token = req.headers.token.split(' ')[1]
            var got = jwt.verify(token, 'secretkey');

            const d = JSON.parse(data);
            const ind = d.findIndex(p => p.Email == got.Email);
            d.splice(ind, 1);
          
            for(let i=0; i<d.length; i++){
                delete d[i].Password;
            }
          
            return res.send(d);       
        }
    })
})

app.use(express.json());

// Registration
app.post("/register", (req,res) =>{
    fs.readFile("data.json", "utf8", (error, data) =>{
    if(error){
        return res.send("Something went wrong");
    }
    else{
        if (data.length <1){
            if (req.body.Password.length >=7){

                const hash = bcrypt.hashSync(req.body.Password, saltRounds);
                req.body.Password = hash
              
                const d1 = JSON.stringify([req.body]);
                console.log(d1);
                fs.writeFile("data.json", d1, error=>{
                    if(error){
                        return res.send("Something went wrong");
                    }
                    else{
                        return res.send({Message:"Registration Successful"});
                    }
                })
            }
         
        }

        else{
            const d = JSON.parse(data); 
            
            if (req.body.Password.length >=5){

                const hash = bcrypt.hashSync(req.body.Password, saltRounds);
                req.body.Password = hash
                d[d.length] = req.body;
                const d1 = JSON.stringify(d);
                fs.writeFile("data.json", d1, error=>{
                    if(error){
                        return res.send("Something went wrong");
                    }
                    else{
                        return res.send({Message:"Registration Successful"});
                    }
                })
            }
            else{
                return res.send("Password Should be greater than 5 characters");
            }
        }
    }
})
});


//Login
app.post("/login" ,(req,res)=>{
    fs.readFile("data.json", "utf8", (error, data) =>{
        if(error){
            res.send("Something went wrong");
        }
        else{
            const d = JSON.parse(data); 
            for(let i=0; i<d.length; i++){
                if (d[i].Email === req.body.Email && bcrypt.compareSync(req.body.Password, d[i].Password ) )
                {    
                    
                    
                    let token = jwt.sign( {Email:req.body.Email} , "secretkey", { expiresIn:"10h"})
                    return res.send({Status: " User Logged in Successfully", Token:token}); 
                }   
            }
            return res.send("Invalid Credentials"); 
        }     
} )
});

//Our own detail

app.get("/owndetail", (req,res)=>{
    fs.readFile("data.json", "utf8", (error, data) =>{
        if(error){
            res.send("Something went wrong");
        }
        else{
            let token = req.headers.token.split(' ')[1]
            var decoded = jwt.verify(token, 'secretkey');

            const d = JSON.parse(data);
            const ind = d.findIndex(p => p.Email == decoded.Email);
            var me = d.splice(ind, 1);
            return res.send(me);       
        }
    })
})

//Update Info
app.put("/updateinfo", (req,res)=>{
    
    fs.readFile("data.json", "utf8", (error, data) =>{
        if(error){
            res.send("Something went wrong");
        }
        else{
            let token = req.headers.token.split(' ')[1]
            var decoded = jwt.verify(token, 'secretkey');
            const d = JSON.parse(data);
            const ind = d.findIndex(p => p.Email == decoded.Email);
            var spliced = d.splice(ind, 1);
            const objkey =  Object.keys(req.body)
            for(let i=0; i<objkey.length;i++){
                if (objkey[i] == "Name"){
                    spliced[0].Name = req.body.Name;
                }
                else if (objkey[i] == "Mobile"){
                    spliced[0].Mobile = req.body.Mobile;
                }
                
            }
            d[ind] = spliced[0];
            const d1 = JSON.stringify(d);
            fs.writeFile("data.json", d1, error=>{
                if(error){
                    return res.send("Something went wrong");
                }
                else{
                    res.send("Information is successfully updated");
                }
            })
        }
    })
})


//Update Password
app.put("/updatepass", (req,res)=>{
    
    fs.readFile("data.json", "utf8", (error, data) =>{
        if(error){
            res.send("Something went wrong");
        }
        else{
            let token = req.headers.token.split(' ')[1]
            var decoded = jwt.verify(token, 'secretkey');
            const d = JSON.parse(data);
            const ind = d.findIndex(p => p.Email == decoded.Email);
            var datas = d.splice(ind, 1);

            if (bcrypt.compareSync(req.body.CurPass, datas[0].Password )  && req.body.NewPass == req.body.ConfirmPass && req.body.NewPass.length >=7) {
                const hash = bcrypt.hashSync(req.body.NewPass, saltRounds);
                datas[0].Password = hash;
                d[ind] = datas[0];
                const d1 = JSON.stringify(d);
                fs.writeFile("data.json", d1, error=>{
                    if(error){
                        return res.send("Something went wrong");
                    }
                    else{
                        return res.send("Password Changed Successfully");
                        }
                    }) 
                }
            else{
                return res.send("Something went wrong");   
                }
    }})});




app.listen(8000);