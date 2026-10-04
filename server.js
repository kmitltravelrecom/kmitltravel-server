require("dotenv").config();

const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const session = require("express-session");

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// SESSION
app.use(session({
    secret: "kmitl-travel-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 24 * 60 * 60 * 1000
    }
}));

app.use(express.static(__dirname));

// =========================
// MySQL
// =========================

const db = mysql.createConnection({
    host: process.env.MYSQLHOST,
    port: process.env.MYSQLPORT,
    user: process.env.MYSQLUSER,
    password: process.env.MYSQLPASSWORD,
    database: process.env.MYSQLDATABASE
});
db.connect((err) => {
    if (err) {
        console.log("เชื่อมต่อ MySQL ไม่สำเร็จ");
        console.log(err);
        return;
    }

    console.log("เชื่อมต่อ MySQL สำเร็จ");
});

// =========================
// EMAIL
// =========================

const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// =========================
// REGISTER
// =========================

app.post("/register", async (req, res) => {

    const {
        username,
        email,
        password,
        fname,
        lname
    } = req.body;

    if (!username || !email || !password || !fname || !lname) {
        return res.status(400).json({
            success: false,
            message: "กรุณากรอกข้อมูลให้ครบ"
        });
    }

    try {

        // ตรวจ Username / Email ซ้ำ
        const checkSql = `
            SELECT USER_ID
            FROM USER
            WHERE USER_USERNAME = ?
               OR USER_EMAIL = ?
        `;

        db.query(
            checkSql,
            [username, email],
            async (err, results) => {

                if (err) {
                    console.log(err);

                    return res.status(500).json({
                        success: false,
                        message: "ตรวจสอบข้อมูลไม่สำเร็จ"
                    });
                }

                if (results.length > 0) {
                    return res.status(400).json({
                        success: false,
                        message: "Username หรือ Email นี้มีอยู่แล้ว"
                    });
                }

                // เข้ารหัส Password
                const hashedPassword =
                    await bcrypt.hash(password, 10);

                // สร้าง Token สำหรับลิงก์ยืนยัน
                const verifyToken =
                    crypto.randomBytes(32).toString("hex");

                // บันทึก User
                const sql = `
                    INSERT INTO USER
                    (
                        USER_USERNAME,
                        USER_EMAIL,
                        USER_PASSWORD,
                        USER_FNAME,
                        USER_LNAME,
                        USER_EMAIL_VERIFIED,
                        USER_VERIFY_TOKEN
                    )
                    VALUES (?, ?, ?, ?, ?, 0, ?)
                `;

                db.query(
                    sql,
                    [
                        username,
                        email,
                        hashedPassword,
                        fname,
                        lname,
                        verifyToken
                    ],
                    async (err, result) => {

                        if (err) {
                            console.log(err);

                            return res.status(500).json({
                                success: false,
                                message: "สมัครสมาชิกไม่สำเร็จ"
                            });
                        }

                        // =========================
                        // สร้างลิงก์ยืนยัน
                        // =========================

                        const verifyLink =
                            `http://localhost:3000/verify?token=${verifyToken}`;

                        // =========================
                        // ส่ง Email
                        // =========================

                        const mailOptions = {
                            from: process.env.EMAIL_USER,
                            to: email,
                            subject: "ยืนยันอีเมล - เที่ยวไหนดี สจล.",
                            html: `
                                <div style="
                                    font-family: Arial, sans-serif;
                                    max-width: 600px;
                                    margin: auto;
                                    padding: 30px;
                                    text-align: center;
                                ">

                                    <h2>ยืนยันอีเมล</h2>

                                    <p>
                                        สวัสดี ${fname}
                                    </p>

                                    <p>
                                        ขอบคุณที่สมัครสมาชิก
                                        <b>เที่ยวไหนดี สจล.</b>
                                    </p>

                                    <p>
                                        กรุณากดปุ่มด้านล่าง
                                        เพื่อยืนยันอีเมลของคุณ
                                    </p>

                                    <a href="${verifyLink}"
                                       style="
                                            display: inline-block;
                                            padding: 12px 25px;
                                            background: #ff8c00;
                                            color: white;
                                            text-decoration: none;
                                            border-radius: 8px;
                                            font-weight: bold;
                                       ">
                                        ยืนยันอีเมล
                                    </a>

                                    <p style="
                                        margin-top: 25px;
                                        color: #777;
                                        font-size: 13px;
                                    ">
                                        หากคุณไม่ได้สมัครสมาชิก
                                        สามารถละเว้นอีเมลนี้ได้
                                    </p>

                                </div>
                            `
                        };

                        try {

                            await transporter.sendMail(mailOptions);

                            console.log(
                                "ส่งอีเมลยืนยันไปที่:",
                                email
                            );

                            res.json({
                                success: true,
                                message:
                                    "สมัครสมาชิกสำเร็จ กรุณาตรวจสอบอีเมลเพื่อยืนยัน"
                            });

                        } catch (emailError) {

                            console.log(
                                "ส่งอีเมลไม่สำเร็จ:",
                                emailError
                            );

                            // ถ้าส่งเมลไม่ได้ ลบ User ที่เพิ่งสร้าง
                            db.query(
                                "DELETE FROM USER WHERE USER_ID = ?",
                                [result.insertId]
                            );

                            res.status(500).json({
                                success: false,
                                message:
                                    "ส่งอีเมลไม่สำเร็จ กรุณาตรวจสอบการตั้งค่า Gmail"
                            });

                        }

                    }
                );

            }
        );

    } catch (error) {

        console.log(error);

        res.status(500).json({
            success: false,
            message: "เกิดข้อผิดพลาด"
        });

    }

});

// =========================
// VERIFY EMAIL
// =========================

app.get("/verify", (req, res) => {

    const token = req.query.token;

    if (!token) {
        return res.send(`
            <h2>ลิงก์ยืนยันไม่ถูกต้อง</h2>
        `);
    }

    const sql = `
        SELECT USER_ID
        FROM USER
        WHERE USER_VERIFY_TOKEN = ?
    `;

    db.query(
        sql,
        [token],
        (err, results) => {

            if (err) {
                console.log(err);

                return res.status(500).send(`
                    <h2>เกิดข้อผิดพลาด</h2>
                `);
            }

            if (results.length === 0) {
                return res.send(`
                    <h2>ลิงก์ยืนยันไม่ถูกต้องหรือถูกใช้ไปแล้ว</h2>
                `);
            }

            const userId = results[0].USER_ID;

            const updateSql = `
                UPDATE USER
                SET
                    USER_EMAIL_VERIFIED = 1,
                    USER_VERIFY_TOKEN = NULL
                WHERE USER_ID = ?
            `;

            db.query(
                updateSql,
                [userId],
                (err) => {

                    if (err) {
                        console.log(err);

                        return res.status(500).send(`
                            <h2>ยืนยันอีเมลไม่สำเร็จ</h2>
                        `);
                    }

                    res.redirect("/verify.html");

                }
            );

        }
    );

});

// LOGIN
app.post("/login", (req, res) => {

    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({
            success: false,
            message: "กรุณากรอกชื่อผู้ใช้และรหัสผ่าน"
        });
    }

    const sql = `
        SELECT
            USER_ID,
            USER_USERNAME,
            USER_FNAME,
            USER_LNAME,
            USER_PASSWORD,
            USER_EMAIL_VERIFIED
        FROM USER
        WHERE USER_USERNAME = ?
    `;

    db.query(sql, [username], async (err, results) => {

        if (err) {
            console.log(err);

            return res.status(500).json({
                success: false,
                message: "เกิดข้อผิดพลาดในการเข้าสู่ระบบ"
            });
        }

        if (results.length === 0) {
            return res.status(401).json({
                success: false,
                message: "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง"
            });
        }

        const user = results[0];

        // ตรวจสอบรหัสผ่าน
        const passwordMatch = await bcrypt.compare(
            password,
            user.USER_PASSWORD
        );

        if (!passwordMatch) {
            return res.status(401).json({
                success: false,
                message: "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง"
            });
        }

        // ตรวจสอบการยืนยันอีเมล
      if (Number(user.USER_EMAIL_VERIFIED) !== 1) {
            return res.status(403).json({
                success: false,
                message: "กรุณายืนยันอีเมลก่อนเข้าสู่ระบบ"
            });
        }

        // บันทึกข้อมูลผู้ใช้ลง Session
        req.session.user = {
            id: user.USER_ID,
            username: user.USER_USERNAME,
            fname: user.USER_FNAME,
            lname: user.USER_LNAME
        };

        res.json({
            success: true,
            message: "เข้าสู่ระบบสำเร็จ"
        });

    });

});

// CHECK LOGIN
app.get("/me", (req, res) => {

    if (!req.session.user) {
        return res.json({
            loggedIn: false
        });
    }

    res.json({
        loggedIn: true,
        user: req.session.user
    });

});

// LOGOUT
app.get("/logout", (req, res) => {

    req.session.destroy((err) => {

        if (err) {
            return res.status(500).json({
                success: false,
                message: "ออกจากระบบไม่สำเร็จ"
            });
        }

        res.json({
            success: true,
            message: "ออกจากระบบสำเร็จ"
        });

    });

});

// =========================
// PLACES
// =========================

app.get("/places", (req, res) => {

    const sql = "SELECT * FROM PLACE";

    db.query(sql, (err, results) => {

        if (err) {
            return res.status(500).json({
                error: err.message
            });
        }

        res.json(results);

    });

});

// =========================
// START SERVER
// =========================

app.listen(3000, () => {

    console.log(
        "เว็บไซต์เปิดที่ http://localhost:3000"
    );

});
