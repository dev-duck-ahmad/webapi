import express from 'express';
import mysql from 'mysql';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import path from 'path';

const app = express();
app.use(cors(
    {
        origin: ["http://localhost:3000"],
        methods: ["POST", "GET", "PUT", "DELETE"],
        credentials: true
    }
));
app.use(cookieParser());
app.use(express.json());
app.use(express.static('public'));
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'public/images')
    },
    filename: (req, file, cb) => {
        cb(null, file.fieldname + "_" + Date.now() + path.extname(file.originalname));
    }
})
const upload = multer({ storage });

app.post("/image/upload", upload.single("file"), function (req, res) {
  const file = req.file;
  res.status(200).json(file.filename);
});

const con = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database: "mrafiq"

})
con.connect(function (err) {
    if (err) {
        console.log("Error in Connection");
    } else {
        console.log("Connected");
    }
})


// LOGIN //

// Admin Login //
app.post('/login', (req, res) => {
    const sql = "SELECT * FROM admin Where email = ? AND  password = ?";
    con.query(sql, [req.body.email, req.body.password], (err, result) => {
        if (err) return res.json({ Status: "Error", Error: "Error in runnig query" });
        if (result.length > 0) {
            const token = jwt.sign({ role: "admin" }, "jwt-secret-key", { expiresIn: '1d' });
            res.cookie('token', token);
            return res.json({ Status: "Success" })
        } else {
            return res.json({ Status: "Error", Error: "Wrong Email or Password" });
        }
    })
})
// User login //
app.post('/login/user', (req, res) => {
    const sql = "SELECT * FROM users Where email = ?";
    con.query(sql, [req.body.email], (err, result) => {
        if (err) return res.json({ Status: "Error", Error: "Error in runnig query" });
        if (result.length > 0) {
            bcrypt.compare(req.body.password.toString(), result[0].password, (err, response) => {
                if (err) return res.json({ Error: "password error" });
                if (response) {
                    const token = jwt.sign({ role: "user", id: result[0].id, labid: result[0].labid }, "jwt-secret-key", { expiresIn: '1d' });
                    res.cookie('token', token);
                    return res.json({ Status: "Success", id: result[0].id, labid: result[0].labid })
                } else {
                    return res.json({ Status: "Error", Error: "Wrong Email or Password" });
                }
            })
        } else {
            return res.json({ Status: "Error", Error: "Wrong Email or Password" });
        }
    })
})
// Labadmin login //
app.post('/login/labadmin', (req, res) => {
    const sql = "SELECT * FROM labadmin Where email = ?";
    con.query(sql, [req.body.email], (err, result) => {
        if (err) return res.json({ Status: "Error", Error: "Error in runnig query" });
        if (result.length > 0) {
            bcrypt.compare(req.body.password.toString(), result[0].password, (err, response) => {
                if (err) return res.json({ Error: "password error" });
                if (response) {
                    const token = jwt.sign({ role: "labadmin", labid: result[0].labid , name: result[0].name  }, "jwt-secret-key", { expiresIn: '1d' });
                    res.cookie('token', token);
                    return res.json({ Status: "Success", labid: result[0].labid , name: result[0].name   })
                } else {
                    return res.json({ Status: "Error", Error: "Wrong Email or Password" });
                }
            })
        } else {
            return res.json({ Status: "Error", Error: "Wrong Email or Password" });
        }
    })
})
// verfyUser //
const verifyUser = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        return res.json({ Error: "You are no Authenticated" });
    } else {
        jwt.verify(token, "jwt-secret-key", (err, decoded) => {
            if (err) return res.json({ Error: "Token wrong" });
            req.role = decoded.role;
            req.id = decoded.id;
            req.labid = decoded.labid;
            req.labname= decoded.name
            next();
        })
    }
}
// verfyUser Data //
app.get('/dashboard', verifyUser, (req, res) => {
    return res.json({ Status: "Success", role: req.role, id: req.id, labid: req.labid , labname : req.labname})
})
// User Logout //
app.get('/logout', (req, res) => {
    res.clearCookie('token');
    return res.json({ Status: "Success" });
})



// LAB ADMIN //



// CreateLAb Data //
app.post('/createlab', upload.single('image'), (req, res) => {
    var role = 0
    const token = req.cookies.token;
    if (!token) {
        return res.json({ Error: "You are no Authenticated" });
    } else {
        jwt.verify(token, "jwt-secret-key", (err, decoded) => {
            if (err) return res.json({ Error: "Token wrong" });
            role = decoded.role;
            if (role === "admin") {
                const sql = "INSERT INTO `labadmin`(`name`, `email`, `password`) VALUES (?)"
                bcrypt.hash(req.body.password.toString(), 10, (err, hash) => {
                    if (err) return res.json({ Error: "Error in password" })
                    const values = [
                        req.body.name,
                        req.body.email,
                        hash,
                    ]
                    con.query(sql, [values], (err, result) => {
                        if (err) return res.json({ Error: "Please check that you have included the title and entered a unique URL before posting." })
                        return res.json({ Status: "Success" })
                    })
                })
            }
            else {
                return res.json({ Error: "You Not You are not allowed this link" });
            }

        })
    }
})
// All User Data On One Lab//
app.get('/userdata', (req, res) => {
    var labid = 0
    const token = req.cookies.token;
    if (!token) {
        return res.json({ Error: "You are no Authenticated" });
    } else {
        jwt.verify(token, "jwt-secret-key", (err, decoded) => {
            if (err) return res.json({ Error: "Token wrong" });
            labid = decoded.labid;
        })
    }
    const sql = "SELECT * FROM `users` WHERE labid = ? ORDER BY `users`.`id` DESC ";
    con.query(sql, [labid], (err, result) => {
        if (err) return res.json({ Error: "Get employee error in sql" });
        return res.json({ Status: "Success", Result: result })
    })
})



// SuperAdmin //


// Admin  Lab Data With ID  //
app.get('/admin/lab/:id', (req, res) => {
    const id = req.params.id;
    var role = 0
    const token = req.cookies.token;
    if (!token) {
        return res.json({ Error: "You are no Authenticated" });
    } else {
        jwt.verify(token, "jwt-secret-key", (err, decoded) => {
            if (err) return res.json({ Error: "Token wrong" });
            role = decoded.role;
            if (role === "admin") {
                const sql = "SELECT * FROM `labadmin` WHERE labid = ?";
                con.query(sql, [id], (err, result) => {
                    if (err) return res.json({ Error: "Get post error in sql" });
                    return res.json({ Status: "Success", Result: result })
                })
            }
            else {
                return res.json({ Error: "You Not You are not allowed this link" });
            }
        })
    }
})
// Admin Lab data update //
app.put('/update/lab/:id', (req, res) => {
    const id = req.params.id;
    var role = 0
    const token = req.cookies.token;
    if (!token) {
        return res.json({ Error: "You are no Authenticated" });
    } else {
        jwt.verify(token, "jwt-secret-key", (err, decoded) => {
            if (err) return res.json({ Error: "Token wrong" });
            role = decoded.role;
            if (role === "admin") {
                bcrypt.hash(req.body.password.toString(), 10, (err, hash) => {
                    if (err) return res.json({ Error: "Error in password" })
                    const sql = "UPDATE labadmin set name = ?, email = ?, password  = ? WHERE labid = ?";
                    con.query(sql, [req.body.name, req.body.email, hash, id], (err, result) => {
                        if (err) return res.json({ Error: "update Lab error in sql" });
                        return res.json({ Status: "Success" })
                    })
                })
            }
            else {
                return res.json({ Error: "You Not You are not allowed this link" });
            }
        })
    }
})
// Admin Get Post //
app.get('/admin/get/all/post', (req, res) => {
    var role = 0
    const token = req.cookies.token;
    if (!token) {
        return res.json({ Error: "You are no Authenticated" });
    } else {
        jwt.verify(token, "jwt-secret-key", (err, decoded) => {
            if (err) return res.json({ Error: "Token wrong" });
            role = decoded.role;
            if (role === "admin") {
                const sql = "SELECT * FROM `post`";
                con.query(sql, (err, result) => {
                    if (err) return res.json({ Error: "Get post error in sql" });
                    return res.json({ Status: "Success", Result: result })
                })
            }
            else {
                return res.json({ Error: "You Not You are not allowed this link" });
            }
        })
    }
})
// Admin Get All Labs //
app.get('/admin/get/all/labs', (req, res) => {
    var role = 0
    const token = req.cookies.token;
    if (!token) {
        return res.json({ Error: "You are no Authenticated" });
    } else {
        jwt.verify(token, "jwt-secret-key", (err, decoded) => {
            if (err) return res.json({ Error: "Token wrong" });
            role = decoded.role;
            if (role === "admin") {
                const sql = "SELECT * FROM `labadmin`";
                con.query(sql, (err, result) => {
                    if (err) return res.json({ Error: "Get post error in sql" });
                    return res.json({ Status: "Success", Result: result })
                })
            }
            else {
                return res.json({ Error: "You Not You are not allowed this link" });
            }
        })
    }
})
// Admin Get All Labs For User Add //
app.get('/admin/get/all/labs/user/data', (req, res) => {
    var role = 0
    const token = req.cookies.token;
    if (!token) {
        return res.json({ Error: "You are no Authenticated" });
    } else {
        jwt.verify(token, "jwt-secret-key", (err, decoded) => {
            if (err) return res.json({ Error: "Token wrong" });
            role = decoded.role;
            if (role === "admin") {
                const sql = "SELECT `labid`, `name` FROM `labadmin` ORDER BY `labadmin`.`name` ASC";
                con.query(sql, (err, result) => {
                    if (err) return res.json({ Error: "Get post error in sql" });
                    return res.json({ Status: "Success", Result: result })
                })
            }
            else {
                return res.json({ Error: "You Not You are not allowed this link" });
            }
        })
    }
})
// Admin  User Data With ID  //
app.get('/admin/user/:id', (req, res) => {
    const id = req.params.id;
    var role = 0
    const token = req.cookies.token;
    if (!token) {
        return res.json({ Error: "You are no Authenticated" });
    } else {
        jwt.verify(token, "jwt-secret-key", (err, decoded) => {
            if (err) return res.json({ Error: "Token wrong" });
            role = decoded.role;
            if (role === "admin") {
                const sql = "SELECT * FROM `users` WHERE id = ?";
                con.query(sql, [id], (err, result) => {
                    if (err) return res.json({ Error: "Get post error in sql" });
                    return res.json({ Status: "Success", Result: result })
                })
            }
            else {
                return res.json({ Error: "You Not You are not allowed this link" });
            }
        })
    }
})
// All User Data//
app.get('/admin/userdata', (req, res) => {
    const token = req.cookies.token;
    if (!token) {
        return res.json({ Error: "You are no Authenticated" });
    } else {
        jwt.verify(token, "jwt-secret-key", (err, decoded) => {
            if (err) return res.json({ Error: "Token wrong" });
          const  role = decoded.role;
            if (role === "admin") {
                const sql = "SELECT id , name , email, labid  FROM `users` ORDER BY `users`.`id` DESC ";
                con.query(sql, (err, result) => {
                    if (err) return res.json({ Error: "Get Post error in sql" });
                    return res.json({ Status: "Success", Result: result })
                })
            }
            else {
                return res.json({ Error: "You Not You are not allowed this link" });
            }
        })
    }
})
// Admin DELETE Lab //
app.delete('/lab/delete/:id', (req, res) => {
    var role = 0
    const id = req.params.id;
    const token = req.cookies.token;
    if (!token) {
        return res.json({ Error: "You are no Authenticated" });
    } else {
        jwt.verify(token, "jwt-secret-key", (err, decoded) => {
            if (err) return res.json({ Error: "Token wrong" });
            role = decoded.role;
            if (role === "admin") {
                const sql = "DELETE FROM `labadmin` WHERE labid = ?";
                con.query(sql, [id], (err, result) => {
                    if (err) return res.json({ Error: "delete employee error in sql" });
                    return res.json({ Status: "Success" })
                })
            }
            else {
                return res.json({ Error: "You Not You are not allowed this link" });
            }
        })
    }
})
//Admin Delete Post //
app.delete('/admin/post/delete/:id', (req, res) => {
    var role = 0
    const id = req.params.id;
    const token = req.cookies.token;
    if (!token) {
        return res.json({ Error: "You are no Authenticated" });
    } else {
        jwt.verify(token, "jwt-secret-key", (err, decoded) => {
            if (err) return res.json({ Error: "Token wrong" });
            role = decoded.role;
            if (role === "admin") {
                const sql = "DELETE FROM `post` WHERE pid = ?";
                con.query(sql, [id], (err, result) => {
                    if (err) return res.json({ Error: "Delete Post error in sql" });
                    return res.json({ Status: "Success" })
                })
            }
            else {
                return res.json({ Error: "You Not You are not allowed this link" });
            }
        })
    }
})
// Admin Post  Update //
app.put('/update/admin/post/:id', (req, res) => {
    var role = 0
    const id = req.params.id;
    const token = req.cookies.token;
    if (!token) {
        return res.json({ Error: "You are no Authenticated" });
    } else {
        jwt.verify(token, "jwt-secret-key", (err, decoded) => {
            if (err) return res.json({ Error: "Token wrong" });
            role = decoded.role;
            if (role === "admin") {
                const sql = "UPDATE post SET title = ?, slug = ?, decs = ?, cat = ?, img = ?, content = ?, bgimg = ?, status = ? WHERE pid = ? ";
                con.query(sql, [
                    req.body.title,
                    req.body.slug,
                    req.body.decs,
                    req.body.cat,
                    req.body.img,
                    req.body.content,
                    req.body.bgimg,
                    req.body.status,
                    id
                ], (err, result) => {
                    if (err) return res.json({ Error: "update Post error in sql" });
                    return res.json({ Status: "Success" })
                })
            }
            else {
                return res.json({ Error: "You Not You are not allowed this link" });
            }
        })
    }
})
// Admin Get Post Date  Id //
app.get('/admin/updatepostget/:id', (req, res) => {
    var role = 0
    const id = req.params.id;
    const token = req.cookies.token;
    if (!token) {
        return res.json({ Error: "You are no Authenticated" });
    } else {
        jwt.verify(token, "jwt-secret-key", (err, decoded) => {
            if (err) return res.json({ Error: "Token wrong" });
            role = decoded.role;
            if (role === "admin") {
                const sql = "SELECT * FROM post where pid = ? ";
                con.query(sql, [id], (err, result) => {
                    if (err) return res.json({ Error: "error in " });
                    if (!result.length) return res.status(201).json({ Error: "Post not found" });
                    return res.json({ Status: "Success", Result: result })
                })
            }
            else {
                return res.json({ Error: "You Not You are not allowed this link" });
            }
        })
    }
})
// Admin CreateUser Data //
app.post('/admin/createuser',(req, res) => {
    var role = 0
    const token = req.cookies.token;
    if (!token) {
        return res.json({ Error: "You are no Authenticated" });
    } else {
        jwt.verify(token, "jwt-secret-key", (err, decoded) => {
            if (err) return res.json({ Error: "Token wrong" });
            role = decoded.role;
            if (role === "admin") {
                const sql = "INSERT INTO `users`(`name`, `email`, `password` , `labid`, `labname`  ) VALUES (?)"
                bcrypt.hash(req.body.password.toString(), 10, (err, hash) => {
                    if (err) return res.json({ Error: "Error in password" })
                    const values = [
                        req.body.name,
                        req.body.email,
                        hash,
                        req.body.labid,
                        req.body.labname,
                    ]
                    con.query(sql, [values], (err, result) => {
                        if (err) return res.json({ Error: "Please check that you have included the title and entered a unique URL before posting." })
                        return res.json({ Status: "Success" })
                    })
                })
            }
            else {
                return res.json({ Error: "You Not You are not allowed this link" });
            }
        })
    }
})
// User data update //
app.put('/admin/update/user/:id', (req, res) => {
    var role = 0
    const id = req.params.id;
    const token = req.cookies.token;
    if (!token) {
        return res.json({ Error: "You are no Authenticated" });
    } else {
        jwt.verify(token, "jwt-secret-key", (err, decoded) => {
            if (err) return res.json({ Error: "Token wrong" });
            role = decoded.role;
            if (role === "admin") {
                bcrypt.hash(req.body.password.toString(), 10, (err, hash) => {
                    if (err) return res.json({ Error: "Error in password" })
                    const sql = "UPDATE users set name = ?, email = ?, password  = ? WHERE id = ?";
                    con.query(sql, [req.body.name, req.body.email, hash, id], (err, result) => {
                        if (err) return res.json({ Error: "update User error" });
                        return res.json({ Status: "Success" })
                    })
                })
            }
            else {
                return res.json({ Error: "You Not You are not allowed this link" });
            }
        })
    }
})



// USER //

// User data update //
app.put('/update/user/:id', (req, res) => {
    const id = req.params.id;
    const token = req.cookies.token;
    if (!token) {
        return res.json({ Error: "You are no Authenticated" });
    } else {
        jwt.verify(token, "jwt-secret-key", (err, decoded) => {
            if (err) return res.json({ Error: "Token wrong" });
           const role = decoded.role;
            if (role === "labadmin") {
                bcrypt.hash(req.body.password.toString(), 10, (err, hash) => {
                    if (err) return res.json({ Error: "Error in password" })
                    const sql = "UPDATE users set name = ?, email = ?, password  = ? WHERE id = ?";
                    con.query(sql, [req.body.name, req.body.email, hash, id], (err, result) => {
                        if (err) return res.json({ Error: "update User error" });
                        return res.json({ Status: "Success" })
                    })
                })
            }
            else {
                return res.json({ Error: "You Not You are not allowed this link" });
            }
        })
    }
})
// CreateUser Data //
app.post('/createuser',(req, res) => {
    const token = req.cookies.token;
    if (!token) {
        return res.json({ Error: "You are no Authenticated" });
    } else {
        jwt.verify(token, "jwt-secret-key", (err, decoded) => {
            if (err) return res.json({ Error: "Token wrong" });
           const role = decoded.role;
           const labid = decoded.labid;
           const labname= decoded.name
            if (role === "labadmin") {
                const sql = "INSERT INTO `users`(`name`, `email`, `password`, `labid`, `labname`, `image`) VALUES (?)"
                bcrypt.hash(req.body.password.toString(), 10, (err, hash) => {
                    if (err) return res.json({ Error: "Error in password" })
                    const values = [
                        req.body.name,
                        req.body.email,
                        hash,
                        labid,
                        labname,
                        req.body.Image
                    ]
                    con.query(sql, [values], (err, result) => {
                        if (err) return res.json({ Error: "Please check that you have included the title and entered a unique URL before posting." })
                        return res.json({ Status: "Success" })
                    })
                })
            }
            else {
                return res.json({ Error: "You Not You are not allowed this link" });
            }
        })
    }
})
// User Data With ID //
app.get('/user/:id', (req, res) => {
    const id = req.params.id;
    const token = req.cookies.token;
    if (!token) {
        return res.json({ Error: "You are no Authenticated" });
    } else {
        jwt.verify(token, "jwt-secret-key", (err, decoded) => {
            if (err) return res.json({ Error: "Token wrong" });
           const role = decoded.role;
           const labid = decoded.labid;
            if (role === "labadmin") {
                const sql = "SELECT * FROM `users` WHERE id = ? AND labid= ?";
                con.query(sql, [id, labid], (err, result) => {
                    if (err) return res.json({ Error: "error in " });
                    if (!result.length) return res.status(201).json({ Error: "Post not found" });
                    return res.json({ Status: "Success", Result: result })
                })
            }
            else {
                return res.json({ Error: "You Not You are not allowed this link" });
            }
        })
    }
})
// User Delete //
app.delete('/user/delete/:id', (req, res) => {
    const id = req.params.id;
    const token = req.cookies.token;
    if (!token) {
        return res.json({ Error: "You are no Authenticated" });
    } else {
        jwt.verify(token, "jwt-secret-key", (err, decoded) => {
            if (err) return res.json({ Error: "Token wrong" });
           const role = decoded.role;
           const labid = decoded.labid;
            if (role === "labadmin") {
                const sql = "DELETE FROM `users` WHERE id = ? AND labid = ? ";
                con.query(sql, [id, labid], (err, result) => {
                    if (err) return res.json({ Error: "delete error in sql" });
                    return res.json({ Status: "Success" })
                })
            }
            else {
                return res.json({ Error: "You Not You are not allowed this link" });
            }
        })
    }
})



// USER POST //



// CreatePost //
app.post('/user/creatpost', (req, res) => {
    var role = 0
    var id = 0
    var labid = 0
    const token = req.cookies.token;
    if (!token) {
        return res.json({ Error: "You are no Authenticated" });
    } else {
        jwt.verify(token, "jwt-secret-key", (err, decoded) => {
            if (err) return res.json({ Error: "Token wrong" });
            role = decoded.role;
            id = decoded.id;
            labid = decoded.labid;
            if (role === "user") {
                const sql = "INSERT INTO `post`( `title`, `slug`, `decs`, `cat`, `img`, `content`, `bgimg`, `status`, `labid`, `userid` ) VALUES  (?)"
                const values = [
                    req.body.title,
                    req.body.slug,
                    req.body.decs,
                    req.body.cat,
                    req.body.img,
                    req.body.content,
                    req.body.bgimg,
                    req.body.status,
                    labid,
                    id
                ]
                con.query(sql, [values], (err, result) => {
                    if (err) return res.json({ Error: "Please check that you have included the title and entered a unique URL before posting." });
                    return res.json({ Status: "Success", Result: result })
                })

            }
            else {
                return res.json({ Error: "You Not You are not allowed this link" });
            }
        })
    }
})
//  Post  Update //
app.put('/update/post/:id', (req, res) => {
    var role = 0
    const id = req.params.id;
    const token = req.cookies.token;
    if (!token) {
        return res.json({ Error: "You are no Authenticated" });
    } else {
        jwt.verify(token, "jwt-secret-key", (err, decoded) => {
            if (err) return res.json({ Error: "Token wrong" });
            role = decoded.role;
            if (role === "user") {
                const sql = "UPDATE post SET title = ?, slug = ?, decs = ?, cat = ?, img = ?, content = ?, bgimg = ?, status = ? WHERE pid = ? ";
                con.query(sql, [
                    req.body.title,
                    req.body.slug,
                    req.body.decs,
                    req.body.cat,
                    req.body.img,
                    req.body.content,
                    req.body.bgimg,
                    req.body.status,
                    id
                ], (err, result) => {
                    if (err) return res.json({ Error: "update Post error in sql" });
                    return res.json({ Status: "Success" })
                })

            }
            else {
                return res.json({ Error: "You Not You are not allowed this link" });
            }
        })
    }
})
// Get Post Date with User id ANd Post Id //
app.get('/updatepostget/:id', (req, res) => {
    var role = 0
    var uid = 0
    const id = req.params.id;
    const token = req.cookies.token;
    if (!token) {
        return res.json({ Error: "You are no Authenticated" });
    } else {
        jwt.verify(token, "jwt-secret-key", (err, decoded) => {
            if (err) return res.json({ Error: "Token wrong" });
            role = decoded.role;
            uid = decoded.id;
            if (role === "user") {
                const sql = "SELECT * FROM post where pid = ? AND userid = ? ";
                con.query(sql, [id, uid], (err, result) => {
                    if (err) return res.json({ Error: "error in " });
                    if (!result.length) return res.status(201).json({ Error: "Post not found" });
                    return res.json({ Status: "Success", Result: result })
                })
            }
            else {
                return res.json({ Error: "You Not You are not allowed this link" });
            }
        })
    }
})
// Get Post Data with User id And Date //
app.get('/user-post', (req, res) => {
    var role = 0
    var uid = 0
    const token = req.cookies.token;
    if (!token) {
        return res.json({ Error: "You are no Authenticated" });
    } else {
        jwt.verify(token, "jwt-secret-key", (err, decoded) => {
            if (err) return res.json({ Error: "Token wrong" });
            role = decoded.role;
            uid = decoded.id
            if (role === "user") {
                const sql = "SELECT * FROM `post` WHERE userid = ? ORDER BY `post`.`date` DESC";
                con.query(sql, [uid], (err, result) => {
                    if (err) return res.json({ Error: "error in " });
                    return res.json({ Status: "Success", Result: result })
                })
            }
            else {
                return res.json({ Error: "You Not You are not allowed this link" });
            }
        })
    }
})
// Delete Post //
app.delete('/post/delete/:id', (req, res) => {
    var role = 0
    const id = req.params.id;
    const token = req.cookies.token;
    if (!token) {
        return res.json({ Error: "You are no Authenticated" });
    } else {
        jwt.verify(token, "jwt-secret-key", (err, decoded) => {
            if (err) return res.json({ Error: "Token wrong" });
            role = decoded.role;
            if (role === "user") {
                const sql = "DELETE FROM `post` WHERE pid = ?";
                con.query(sql, [id], (err, result) => {
                    if (err) return res.json({ Error: "delete employee error in sql" });
                    return res.json({ Status: "Success" })
                })
            }
            else {
                return res.json({ Error: "You Not You are not allowed this link" });
            }
        })
    }
})


app.listen(8081, () => {

})
