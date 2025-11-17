// vulnerable-demo.js
// 🚨 INTENTIONALLY VULNERABLE TEST FILE — DO NOT USE IN PRODUCTION

const http = require("http");
const url = require("url");
const mysql = require("mysql");
const fs = require("fs");

// ❌ Hardcoded secret (Veracode should detect this too)
const API_KEY = "12345-SECRET-KEY-DO-NOT-USE";

// ❌ Vulnerable SQL Injection
function getUser(req, res) {
    const q = url.parse(req.url, true).query;
    const userId = q.id;  // User input not sanitized

    const connection = mysql.createConnection({
        host: "localhost",
        user: "root",
        password: "password",
        database: "testdb"
    });

    connection.connect();

    // 🚨 SQL Injection
    const query = "SELECT * FROM users WHERE id = " + userId;
    connection.query(query, function (error, results) {
        if (error) throw error;
        res.write(JSON.stringify(results));
        res.end();
    });

    connection.end();
}

// ❌ Cross-Site Scripting (XSS)
function serveXSS(req, res) {
    const q = url.parse(req.url, true).query;
    const message = q.msg;  // unsanitized user input

    // 🚨 XSS: Reflected input is directly output to HTML
    res.writeHead(200, { "Content-Type": "text/html" });
    res.write("<h1>Your message:</h1>");
    res.write("<p>" + message + "</p>");  // TRIGGERS XSS
    res.end();
}

// ❌ Server-Side Request Forgery (SSRF)
function ssrfTest(req, res) {
    const q = url.parse(req.url, true).query;
    const target = q.url;  // attacker controls URL

    // 🚨 SSRF: Fetches user-supplied internal or external URL
    http.get(target, (r) => {
        let data = "";
        r.on("data", chunk => data += chunk);
        r.on("end", () => {
            res.write("Fetched data:<br>");
            res.write(data);
            res.end();
        });
    }).on("error", (err) => {
        res.write("Error: " + err.message);
        res.end();
    });
}

// ❌ Insecure cryptography (weak algorithm)
function insecureHash(input) {
    const crypto = require("crypto");
    return crypto.createHash("md5").update(input).digest("hex");  // weak hashing
}

// Simple server with vulnerable endpoints
http.createServer((req, res) => {
    if (req.url.startsWith("/sql")) return getUser(req, res);
    if (req.url.startsWith("/xss")) return serveXSS(req, res);
    if (req.url.startsWith("/ssrf")) return ssrfTest(req, res);

    res.write("Vulnerable test server running.\n");
    res.write("Try:\n");
    res.write("/sql?id=1\n");
    res.write("/xss?msg=<script>alert('xss')</script>\n");
    res.write("/ssrf?url=http://example.com\n");
    res.end();
}).listen(3000);

console.log("Vulnerable test server running on port 3000...");
