const express = require("express")
const multer = require("multer")
const cors = require("cors")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const helmet = require("helmet")
const rateLimit = require("express-rate-limit")
const path = require("path")
const fs = require("fs").promises

const app = express()

// Security middleware
app.use(helmet())
app.use(express.json({ limit: "50mb" }))
app.use(express.urlencoded({ limit: "50mb", extended: true }))

// CORS with restricted origins
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(",") || "*",
  credentials: true
}))

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Too many requests"
})

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  skipSuccessfulRequests: true
})

app.use(limiter)

// Create uploads directory if it doesn't exist
const uploadDir = "uploads"
if (!require("fs").existsSync(uploadDir)) {
  require("fs").mkdirSync(uploadDir)
}

app.use("/uploads", express.static("uploads"))

// Multer with file validation
const upload = multer({
  dest: "uploads/",
  limits: { fileSize: 100 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ["audio/mpeg", "audio/wav", "audio/ogg", "audio/webm"]
    if (!allowed.includes(file.mimetype)) {
      cb(new Error("Invalid file type"))
    } else {
      cb(null, true)
    }
  }
})

const JWT_SECRET = process.env.JWT_SECRET || "your-super-secret-key-change-in-production"
const tokenBlacklist = new Set()

let users = []
let podcasts = []

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1]
  
  if (!token) return res.status(401).send("No token provided")
  if (tokenBlacklist.has(token)) return res.status(401).send("Token revoked")
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET)
    req.user = decoded
    next()
  } catch (err) {
    res.status(401).send("Invalid token")
  }
}

// Input validation helper
const validateEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)

// 🔄 RESET POINTS DAILY
function resetPoints(user) {
  const now = Date.now()
  const oneDay = 86400000

  if (now - user.lastReset > oneDay) {
    user.points = user.plan === "free" ? 100 : Infinity
    user.lastReset = now
  }
}

// 👤 REGISTER
app.post("/register", authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password required" })
    }

    if (!validateEmail(email)) {
      return res.status(400).json({ error: "Invalid email format" })
    }

    if (password.length < 8) {
      return res.status(400).json({ error: "Password must be at least 8 characters" })
    }

    if (users.find(u => u.email === email)) {
      return res.status(409).json({ error: "User already exists" })
    }

    const hashed = await bcrypt.hash(password, 12)

    users.push({
      id: Date.now(),
      email,
      password: hashed,
      plan: "free",
      points: 100,
      lastReset: Date.now()
    })

    res.status(201).json({ message: "User created successfully" })
  } catch (err) {
    res.status(500).json({ error: "Registration failed" })
  }
})

// 🔐 LOGIN
app.post("/login", authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password required" })
    }

    const user = users.find(u => u.email === email)
    if (!user) return res.status(401).json({ error: "Invalid credentials" })

    const valid = await bcrypt.compare(password, user.password)
    if (!valid) return res.status(401).json({ error: "Invalid credentials" })

    const token = jwt.sign(
      { id: user.id, email: user.email, plan: user.plan },
      JWT_SECRET,
      { expiresIn: "7d" }
    )

    res.json({ message: "Logged in", token })
  } catch (err) {
    res.status(500).json({ error: "Login failed" })
  }
})

// 💳 UPGRADE
app.post("/upgrade", verifyToken, (req, res) => {
  try {
    const user = users.find(u => u.id === req.user.id)
    if (!user) return res.status(404).json({ error: "User not found" })

    user.plan = "paid"
    user.points = Infinity

    res.json({ message: "Upgraded to paid plan" })
  } catch (err) {
    res.status(500).json({ error: "Upgrade failed" })
  }
})

// 🎧 UPLOAD PODCAST
app.post("/upload", verifyToken, upload.single("audio"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "No file provided" })
    }

    if (!req.body.title || req.body.title.length > 200) {
      await fs.unlink(req.file.path)
      return res.status(400).json({ error: "Invalid title" })
    }

    const podcast = {
      id: Date.now(),
      userId: req.user.id,
      title: req.body.title,
      audio: `/uploads/${req.file.filename}`,
      createdAt: new Date().toISOString()
    }

    podcasts.push(podcast)
    res.status(201).json(podcast)
  } catch (err) {
    res.status(500).json({ error: "Upload failed" })
  }
})

// 📡 GET PODCASTS
app.get("/podcasts", verifyToken, (req, res) => {
  try {
    const userPodcasts = podcasts.filter(p => p.userId === req.user.id)
    res.json(userPodcasts)
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch podcasts" })
  }
})

// 🤖 GENERATE PODCAST (USES POINTS)
app.post("/generate", verifyToken, (req, res) => {
  try {
    const { topic } = req.body

    if (!topic || topic.length === 0 || topic.length > 500) {
      return res.status(400).json({ error: "Invalid topic" })
    }

    const user = users.find(u => u.id === req.user.id)
    if (!user) return res.status(404).json({ error: "User not found" })

    resetPoints(user)

    if (user.plan === "free" && user.points < 10) {
      return res.status(403).json({ error: "Insufficient points. Upgrade or try tomorrow." })
    }

    if (user.plan === "free") {
      user.points -= 10
    }

    const safeTopic = topic.replace(/[<>]/g, "").substring(0, 500)

    const script = \`
🎙 MAGIC STREAMING PODCAST

Topic: \${safeTopic}

INTRO:
Welcome to Magic Streaming.

MAIN:
\${safeTopic} is an important subject affecting the world.

INSIGHTS:
It continues to grow and influence industries.

FUTURE:
The future of \${safeTopic} looks promising.

OUTRO:
Thanks for listening.
\`

    res.json({
      script,
      points: user.plan === "free" ? user.points : "Unlimited"
    })
  } catch (err) {
    res.status(500).json({ error: "Generation failed" })
  }
})

// 🔓 LOGOUT
app.post("/logout", verifyToken, (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1]
    if (token) tokenBlacklist.add(token)
    res.json({ message: "Logged out" })
  } catch (err) {
    res.status(500).json({ error: "Logout failed" })
  }
})

// 🌐 FRONTEND
app.get("/", (req, res) => {
  res.send(\`
<!DOCTYPE html>
<html>
<head>
<title>Magic Streaming</title>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
  body{font-family:Arial,sans-serif;background:#7a0000;color:white;padding:20px;max-width:600px;margin:0 auto;}
  input,button,textarea{margin:5px;padding:8px;width:100%;box-sizing:border-box;border-radius:4px;border:1px solid #ccc;}
  button{background:#4CAF50;color:white;cursor:pointer;border:none;font-weight:bold;}
  button:hover{background:#45a049;}
  audio{display:block;margin-top:10px;width:100%;}
  textarea{min-height:200px;}
  .section{margin:20px 0;border:1px solid #999;padding:10px;border-radius:4px;}
  .error{color:#ff6b6b;font-weight:bold;}
  .success{color:#51cf66;font-weight:bold;}
</style>
</head>
<body>

<h1>✨ Magic Streaming</h1>

<div class="section">
  <h2>Register / Login</h2>
  <input id="email" placeholder="email" type="email">
  <input id="password" placeholder="password" type="password">
  <button onclick="register()">Register</button>
  <button onclick="login()">Login</button>
  <button onclick="logout()">Logout</button>
</div>

<div id="loggedIn" style="display:none;">
  <h3 id="points"></h3>

  <div class="section">
    <button onclick="upgrade()">Upgrade to Paid</button>
  </div>

  <div class="section">
    <h2>Upload Podcast</h2>
    <input type="file" id="file" accept="audio/*">
    <input id="title" placeholder="title" maxlength="200">
    <button onclick="upload()">Upload</button>
  </div>

  <div class="section">
    <h2>AI Podcast Generator</h2>
    <input id="topic" placeholder="topic" maxlength="500">
    <button onclick="generate()">Generate</button>
    <textarea id="script"></textarea>
    <button onclick="speak()">Narrate</button>
  </div>

  <div class="section">
    <h2>Your Podcasts</h2>
    <div id="list"></div>
  </div>
</div>

<div id="messages"></div>

<script>

let currentToken = localStorage.getItem("token") || null

function showMessage(msg, type = "info") {
  const messages = document.getElementById("messages")
  const p = document.createElement("p")
  p.className = type === "error" ? "error" : type === "success" ? "success" : ""
  p.textContent = msg
  messages.appendChild(p)
  setTimeout(() => p.remove(), 5000)
}

async function register(){
  const email = document.getElementById("email").value
  const password = document.getElementById("password").value
  
  if (!email || !password) {
    showMessage("Please fill all fields", "error")
    return
  }

  try {
    const res = await fetch("/register", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({email, password})
    })
    const data = await res.json()
    if (!res.ok) throw new Error(data.error)
    showMessage("Registered successfully", "success")
  } catch (e) {
    showMessage("Registration failed: " + e.message, "error")
  }
}

async function login(){
  const email = document.getElementById("email").value
  const password = document.getElementById("password").value
  
  if (!email || !password) {
    showMessage("Please fill all fields", "error")
    return
  }

  try {
    const res = await fetch("/login", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({email, password})
    })
    const data = await res.json()
    if (!res.ok) throw new Error(data.error)
    
    currentToken = data.token
    localStorage.setItem("token", currentToken)
    showMessage("Logged in!", "success")
    updateUI()
    load()
  } catch (e) {
    showMessage("Login failed: " + e.message, "error")
  }
}

async function logout(){
  try {
    await fetch("/logout", {
      method: "POST",
      headers: {"Authorization": "Bearer " + currentToken}
    })
    currentToken = null
    localStorage.removeItem("token")
    document.getElementById("loggedIn").style.display = "none"
    showMessage("Logged out", "success")
  } catch (e) {
    showMessage("Logout failed", "error")
  }
}

async function upgrade(){
  try {
    const res = await fetch("/upgrade", {
      method: "POST",
      headers: {"Authorization": "Bearer " + currentToken}
    })
    if (!res.ok) throw new Error("Upgrade failed")
    showMessage("Upgraded to paid!", "success")
  } catch (e) {
    showMessage("Upgrade failed: " + e.message, "error")
  }
}

async function upload(){
  const file = document.getElementById("file").files[0]
  const title = document.getElementById("title").value

  if (!file || !title) {
    showMessage("Please select file and enter title", "error")
    return
  }

  try {
    const formData = new FormData()
    formData.append("audio", file)
    formData.append("title", title)

    const res = await fetch("/upload", {
      method: "POST",
      headers: {"Authorization": "Bearer " + currentToken},
      body: formData
    })
    
    if (!res.ok) throw new Error("Upload failed")
    showMessage("Uploaded!", "success")
    document.getElementById("file").value = ""
    document.getElementById("title").value = ""
    load()
  } catch (e) {
    showMessage("Upload failed: " + e.message, "error")
  }
}

async function load(){
  try {
    const res = await fetch("/podcasts", {
      headers: {"Authorization": "Bearer " + currentToken}
    })
    const data = await res.json()

    const list = document.getElementById("list")
    list.innerHTML=""

    data.forEach(p=>{
      const div = document.createElement("div")
      div.innerHTML = \\\`
        <h3>\\\${p.title}</h3>
        <audio controls src="\\\${p.audio}"></audio>
      \\\`
      list.appendChild(div)
    })
  } catch (e) {
    showMessage("Failed to load podcasts", "error")
  }
}

async function generate(){
  const topic = document.getElementById("topic").value
  
  if (!topic) {
    showMessage("Enter a topic", "error")
    return
  }

  try {
    const res = await fetch("/generate", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + currentToken
      },
      body: JSON.stringify({topic})
    })

    const data = await res.json()
    if (!res.ok) throw new Error(data.error)

    document.getElementById("script").value = data.script
    showMessage("Generated! Points: " + data.points, "success")
  } catch (e) {
    showMessage("Generation failed: " + e.message, "error")
  }
}

function speak(){
  const script = document.getElementById("script").value
  if (!script) {
    showMessage("No script to narrate", "error")
    return
  }

  speechSynthesis.cancel()
  const speech = new SpeechSynthesisUtterance(script)
  speech.rate = 1
  speech.pitch = 1
  speechSynthesis.speak(speech)
}

function updateUI(){
  document.getElementById("loggedIn").style.display = currentToken ? "block" : "none"
  document.getElementById("points").textContent = "Logged in"
}

if (currentToken) {
  updateUI()
  load()
}

</script>

</body>
</html>
  \`)
})

const PORT = process.env.PORT || 3000
app.listen(PORT, () => console.log(\`
╔════════════════════════════════════════╗
║   🎙️  Magic Streaming Server Started   ║
╚════════════════════════════════════════╝

📡 Server running at: http://localhost:\${PORT}
\`))
