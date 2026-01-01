const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

const JWT_SECRET = 'KODE_RAHASIA_KITA_123';

// ==========================================
// KONEKSI KE 2 DATABASE (PORT 3306)
// ==========================================
const dbAuth = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: '', // Kosongkan jika pakai XAMPP default
    database: 'db_auth',
    port: 3306
});

const dbProfile = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'db_profile',
    port: 3306
});

// ==========================================
// MIKRO SERVIS 1: AUTH (REGISTER & LOGIN)
// ==========================================

// Register Logic
app.post('/api/auth/register', async (req, res) => {
    const { email, password, full_name } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // 1. Simpan ke db_auth
        const [userResult] = await dbAuth.query(
            "INSERT INTO users (email, password) VALUES (?, ?)", 
            [email, hashedPassword]
        );
        const newUserId = userResult.insertId;

        // 2. Simpan ke db_profile
        await dbProfile.query(
            "INSERT INTO profiles (user_id, full_name, bio) VALUES (?, ?, ?)", 
            [newUserId, full_name, 'Halo, saya pengguna baru!']
        );

        res.status(201).json({ message: "Registrasi berhasil!" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Registrasi gagal, pastikan database sudah siap." });
    }
});

// Login Logic
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const [users] = await dbAuth.query("SELECT * FROM users WHERE email = ?", [email]);
        if (users.length === 0) return res.status(404).json({ message: "User tidak ditemukan" });

        const isMatch = await bcrypt.compare(password, users[0].password);
        if (!isMatch) return res.status(401).json({ message: "Password salah" });

        // Buat Token JWT
        const token = jwt.sign({ id: users[0].id }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token, userId: users[0].id });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==========================================
// MIKRO SERVIS 2: DASHBOARD (PROFILE)
// ==========================================

// Middleware untuk verifikasi Login
const authenticate = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ message: "Akses ditolak" });
    
    const token = authHeader.split(" ")[1];
    try {
        const verified = jwt.verify(token, JWT_SECRET);
        req.user = verified;
        next();
    } catch (err) {
        res.status(400).json({ message: "Token tidak valid" });
    }
};

// Ambil data profil untuk dashboard
app.get('/api/dashboard/profile', authenticate, async (req, res) => {
    try {
        const [profile] = await dbProfile.query(
            "SELECT * FROM profiles WHERE user_id = ?", 
            [req.user.id]
        );
        
        if (profile.length === 0) {
            return res.status(404).json({ message: "Profil tidak ditemukan" });
        }
        
        res.json(profile[0]);
    } catch (err) {
        // PERBAIKAN: Dari 5000 menjadi 500
        res.status(500).json({ error: err.message });
    }
});

// Jalankan Server
const PORT = 5000;
app.listen(PORT, () => {
    console.log(`🚀 Server Mikro berjalan di http://localhost:${PORT}`);
});