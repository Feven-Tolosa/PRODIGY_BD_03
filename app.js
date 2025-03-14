const express = require('express')
const bodyParser = require('body-parser')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')

const app = express()
app.use(bodyParser.json())

let users = []

app.post('/register', async (req, res) => {
  const { username, password, role } = req.body
  const hashedPassword = await bcrypt.hash(password, 8)
  const user = { username, password: hashedPassword, role }
  users.push(user)
  res.status(201).send('User registered')
})

app.post('/login', async (req, res) => {
  const { username, password } = req.body
  const user = users.find((u) => u.username === username)
  if (!user) return res.status(400).send('User not found')

  const validPassword = await bcrypt.compare(password, user.password)
  if (!validPassword) return res.status(400).send('Invalid password')

  const token = jwt.sign(
    { username: user.username, role: user.role },
    'your-secret-key'
  )
  res.send({ token })
})

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(' ')[1]
  if (token == null) return res.sendStatus(401)

  jwt.verify(token, 'your-secret-key', (err, user) => {
    if (err) return res.sendStatus(403)
    req.user = user
    next()
  })
}

app.get('/profile', authenticateToken, (req, res) => {
  res.json({ message: 'Profile accessed', user: req.user })
})

function authorizeRole(role) {
  return (req, res, next) => {
    console.log('User Role:', req.user.role) // Debugging
    console.log('Required Role:', role) // Debugging
    if (req.user.role !== role) return res.sendStatus(403) // Forbidden
    next()
  }
}

app.get('/admin', authenticateToken, authorizeRole('admin'), (req, res) => {
  res.json({ message: 'Admin accessed', user: req.user })
})

app.get('/', (req, res) => {
  res.json({ message: 'Home accessed', user: req.user })
})

const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`)
})
