import express from 'express';
import pkg from 'pg';
const { Pool } = pkg;
import bcrypt from 'bcrypt';
import session from 'express-session';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import nodemailer from 'nodemailer';
import sharp from 'sharp';
import dotenv from 'dotenv';
import OpenAI, { toFile } from 'openai';
import multer from 'multer';
import cors from 'cors';
import { PrismaClient } from '@prisma/client';

// ============================================================================
// CONFIGURATION & ENVIRONMENT SETUP
// ============================================================================
dotenv.config({ override: true });

const prisma = new PrismaClient();
const app = express();
const upload = multer({ storage: multer.memoryStorage() });

// --- MIDDLEWARES ---
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static('public'));
app.set('view engine', 'ejs');

// ============================================================================
// SESSION & PASSPORT CONFIGURATION
// ============================================================================
app.set('trust proxy', 1);
app.use(session({
    secret: process.env.SESSION_SECRET || 'ada-ai-fallback-secret-key',
    resave: false,
    saveUninitialized: true,
    cookie: {
        maxAge: 24 * 60 * 60 * 1000,
        httpOnly: true,
        secure: false // Lokal testlər və HTTP/HTTPS uyğunluğu üçün
    }
}));

app.use(passport.initialize());
app.use(passport.session());

app.use((req, res, next) => {
    res.locals.user = req.user || null;
    next();
});

// ============================================================================
// EXTERNAL SERVICES SETUP (OPENAI & DATABASE & MAILER)
// ============================================================================
const openai = new OpenAI({
    apiKey: process.env.OPENAI_API_KEY
});

// --- DATABASE CONNECTION POOL ---
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL?.includes('localhost') ? false : { rejectUnauthorized: false }
});

pool.connect()
    .then(() => {
        console.log('✅ Verilənlər bazasına uğurla qoşuldu!');
    })
    .catch(err => {
        console.error('❌ Baza bağlantısı xətası:', err.message);
    });

// --- NODEMAILER TRANSPORTER ---
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.GMAIL_USER || process.env.EMAIL_USER,
        pass: process.env.GMAIL_APP_PASSWORD || process.env.EMAIL_PASS
    }
});

transporter.verify((error) => {
    if (error) {
        console.error('❌ Gmail bağlantısı uğursuz oldu:', error.message);
    } else {
        console.log('✅ Gmail SMTP bağlantısı hazırdır.');
    }
});

// ============================================================================
// AUTHENTICATION MIDDLEWARES & STRATEGIES
// ============================================================================
function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    if (req.path.startsWith('/api/')) {
        return res.status(401).json({ error: "Sessiyanızın vaxtı bitib. Zəhmət olmasa daxil olun." });
    }
    res.redirect('/login');
}

async function ensureAdmin(req, res, next) {
    if (!req.isAuthenticated()) {
        return res.redirect('/login');
    }
    try {
        const userResult = await pool.query('SELECT is_admin FROM users WHERE id = $1', [req.user.id]);
        if (userResult.rows.length > 0 && userResult.rows[0].is_admin) {
            req.user.is_admin = true;
            return next();
        }
        res.status(403).send("Giriş qadağandır: Yalnız adminlər üçün!");
    } catch (err) {
        console.error("Admin yoxlama xətası:", err);
        res.status(500).send("Server xətası");
    }
}

// --- PASSPORT GOOGLE OAUTH STRATEGY ---
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL || 'http://localhost:3000/auth/google/callback'
}, async (accessToken, refreshToken, profile, done) => {
    try {
        const email = profile.emails && profile.emails[0] ? profile.emails[0].value : null;
        if (!email) {
            return done(new Error("Google hesabında e-poçt tapılmadı!"), null);
        }

        const fullname = profile.displayName || 'Google İstifadəçisi';
        const picture = profile.photos && profile.photos[0] ? profile.photos[0].value : null;

        let existingUser = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (existingUser.rows.length > 0) {
            const updatedUser = await pool.query(
                'UPDATE users SET profile_picture = $1 WHERE email = $2 RETURNING *',
                [picture, email]
            );
            return done(null, updatedUser.rows[0]);
        }

        const newUser = await pool.query(
            'INSERT INTO users (fullname, email, password, profile_picture) VALUES ($1, $2, $3, $4) RETURNING *',
            [fullname, email, 'GOOGLE_AUTH_USER', picture]
        );
        return done(null, newUser.rows[0]);
    } catch (err) {
        return done(err, null);
    }
}));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await pool.query('SELECT id, fullname, email, is_admin, profile_picture FROM users WHERE id = $1', [id]);
        if (user.rows.length === 0) {
            return done(null, false);
        }
        done(null, user.rows[0]);
    } catch (err) {
        done(err, null);
    }
});

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================
function escapeHtml(value) {
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function getStars(rating) {
    const number = parseInt(rating);
    if (isNaN(number) || number < 1 || number > 5) return 'Reytinq verilməyib';
    return '★'.repeat(number) + '☆'.repeat(5 - number);
}

// ============================================================================
// SYSTEM PROMPT DEFINITION
// ============================================================================
const SYSTEM_PROMPT = `
Sənin adın ADA-dır. ADA sözünün mənası "Arzulara doğru Ağasiflə" deməkdir.
Sən Ağasif Əliyevin yaratdığı ADA_GROUP çərçivəsində fəaliyyət göstərən peşəkar AI köməkçisən.
ADA_GROUP Rəqəmsal həllər mərkəzi daxilində olan tətbiqlərdən biri də STİM-L-dir.
STİM-L ADA_GROUP tərəfindən 2026-cı ildə istifadəyə buraxılmış şəxsi kurs tətbiqidir (www.stim-l.com və Play Store).
Kursun sahibi və tədrisçi direktoru Cabir Baxşiyevdir (2015-ci ildə qurub, Lənkəranda anadan olub, Kompüter və informatika müəllimi, informatika kitabının müəllifidir).
Ağasif Əliyev 2005-ci ildə Masallıda anadan olub, Lənkəran Dövlət Universitetinin İnformasiya texnologiyaları ixtisasında təhsil alıb, Full-Stack Developer-dir (Code-Academy, Skillwill, Codecloud məzunudur).

Vacib Qaydalar:
1. Söhbətin əvvəlki mesajlarını və konteksti DİQQƏTLƏ izlə. İstifadəçi adını və ya əvvəlki mövzunu soruşursa, tarixdən tapıb dəqiq cavab ver! "Adınızı bilmirəm" demək QADAĞANDIR!
2. Özün və yaradıcıların haqqında yalnız istifadəçi birbaşa soruşduqda məlumat ver.
3. İstifadəçi hansı dildə yazırsa, o dildə aydın, dəqiq və sürətli cavab ver.
4. Kod suallarında işlək və praktik nümunələr ver.
`;

// ============================================================================
// VIEW ROUTES & PAGE RENDERERS
// ============================================================================
app.get('/chat', async (req, res) => {
    let chatHistory = [];
    const isUserLoggedIn = req.isAuthenticated && req.isAuthenticated();

    if (isUserLoggedIn && req.user?.email) {
        try {
            const result = await pool.query(
                'SELECT user_message, ai_response FROM messages WHERE user_email = $1 ORDER BY id ASC',
                [req.user.email]
            );
            chatHistory = result.rows;
        } catch (e) {
            console.error("Baza tarixçə xətası:", e);
        }
    } else {
        // QONAQ İSTİFADƏÇİ: Səhifə yenilənəndə sol paneldəki tarixçə təmizlənir
        req.session.chatHistoryList = [];
        chatHistory = [];
    }

    res.render('chat', { user: req.user || null, chatHistory });
});

app.get('/', (req, res) => res.redirect('/chat'));
app.get('/login', (req, res) => req.isAuthenticated() ? res.redirect('/chat') : res.render('login', { errorMessage: null }));
app.get('/register', (req, res) => req.isAuthenticated() ? res.redirect('/chat') : res.render('register', { errorMessage: null }));
app.get('/ada-pro', (req, res) => res.render('adapro', { user: req.user || null }));
app.get('/adapro', (req, res) => res.render('adapro', { user: req.user || null }));
app.get('/help', (req, res) => res.render('help'));
app.get('/gizlilik', (req, res) => res.render('gizlilik'));
app.get('/fedback', (req, res) => res.render('fedback'));
app.get('/geribildirim', (req, res) => res.render('geribildirim'));

// --- AUTHENTICATION ENDPOINTS ---
app.post('/register', async (req, res) => {
    const { fullname, email, password } = req.body;
    if (!fullname || !email || !password) {
        return res.render('register', { errorMessage: 'Bütün xanaları doldurun!' });
    }
    try {
        const existingUser = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
        if (existingUser.rows.length > 0) {
            return res.render('register', { errorMessage: 'Bu e-poçt ünvanı ilə artıq qeydiyyatdan keçilib!' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query('INSERT INTO users (fullname, email, password) VALUES ($1, $2, $3)', [fullname, email, hashedPassword]);
        res.redirect('/login');
    } catch (err) {
        res.render('register', { errorMessage: 'Xəta baş verdi, zəhmət olmasa yenidən yoxlayın.' });
    }
});

app.post('/login', async (req, res, next) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.render('login', { errorMessage: 'E-poçt və şifrə daxil edilməlidir!' });
    }
    try {
        const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (userResult.rows.length === 0) {
            return res.render('login', { errorMessage: 'Bu e-poçt ilə qeydiyyat tapılmadı!' });
        }
        const user = userResult.rows[0];
        if (user.password === 'GOOGLE_AUTH_USER') {
            return res.render('login', { errorMessage: 'Bu hesab Google ilə yaradılıb.' });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.render('login', { errorMessage: 'Şifrə yanlışdır!' });
        }
        req.logIn(user, (err) => err ? next(err) : res.redirect('/chat'));
    } catch (err) {
        res.render('login', { errorMessage: 'Xəta baş verdi, yenidən yoxlayın.' });
    }
});

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/register' }), (req, res) => res.redirect('/chat'));
app.get('/logout', (req, res, next) => req.logout((err) => err ? next(err) : res.redirect('/login')));

// ============================================================================
// MAIN UNIFIED CHAT API ENDPOINT (LİMİTSİZ)
// ============================================================================
app.post('/api/chat', async (req, res) => {
    try {
        const currentUser = req.user || req.session?.user || req.session?.passport?.user;
        const isUserLoggedIn = req.isAuthenticated && req.isAuthenticated();
        const userEmail = isUserLoggedIn ? req.user.email : null;

        const message = typeof req.body.message === 'string' ? req.body.message.trim() : '';
        const image = typeof req.body.image === 'string' ? req.body.image : null;

        if (!message && !image) {
            return res.status(400).json({
                type: 'text',
                reply: 'Zəhmət olmasa sualınızı yazın və ya şəkil göndərin.'
            });
        }

        // --- 1. SİMVOL LİMİTİ (MAX 2000) ---
        const MAX_CHAR_LIMIT = 2000;
        if (message.length > MAX_CHAR_LIMIT) {
            return res.status(400).json({
                type: 'text',
                reply: `⚠️ Mesajınız çox uzundur (${message.length} simvol). Zəhmət olmasa maksimum ${MAX_CHAR_LIMIT} simvol daxil edin.`
            });
        }

        // --- 2. ŞƏKİL ANALİZİ VƏ YA REDAKTƏSİ ---
        if (image) {
            const editingWords = ['redaktə', 'edit', 'dəyiş', 'dəyişdir', 'fon', 'background', 'rəng', 'sil', 'əlavə et'];
            const wantsEdit = message && editingWords.some(word => message.toLowerCase().includes(word));

            if (wantsEdit) {
                try {
                    const base64Data = image.replace(/^data:image\/\w+;base64,/, '');
                    const imgBuffer = Buffer.from(base64Data, 'base64');
                    const pngBuffer = await sharp(imgBuffer).resize(1024, 1024, { fit: 'inside' }).png().toBuffer();
                    const imageFile = await toFile(pngBuffer, 'image.png', { type: 'image/png' });

                    const result = await openai.images.edit({
                        model: 'dall-e-2',
                        image: imageFile,
                        prompt: message,
                        n: 1,
                        size: '1024x1024',
                        response_format: 'b64_json'
                    });

                    const base64Output = result.data?.[0]?.b64_json;
                    const outputImage = `data:image/png;base64,${base64Output}`;
                    return res.json({
                        type: 'image',
                        reply: `Şəkil redaktə edildi.\n\n![Redaktə olunmuş şəkil](${outputImage})`,
                        image: outputImage
                    });
                } catch (err) {
                    console.error('Şəkil redaktə xətası:', err.message);
                    return res.status(500).json({ type: 'text', reply: 'Şəkli redaktə edərkən xəta baş verdi.' });
                }
            }

            // Şəkil Analizi (gpt-4o-mini)
            const visionResponse = await openai.chat.completions.create({
                model: 'gpt-4o-mini',
                messages: [
                    { role: 'system', content: SYSTEM_PROMPT },
                    { role: 'user', content: [{ type: 'text', text: message || 'Bu şəkli analiz et.' }, { type: 'image_url', image_url: { url: image } }] }
                ],
                max_tokens: 1000
            });
            const reply = visionResponse.choices[0]?.message?.content || 'Şəkli analiz etmək mümkün olmadı.';
            return res.json({ type: 'text', reply });
        }

        // --- 3. ŞƏKİL YARATMA (DALL-E 3) ---
        const creationRegex = /^(şəkil|foto|şəkli|resm|rəsm|picture|image|logo|photo)\s+(yarat|düzəlt|çək|generate|draw|hazırla)/i;
        if (creationRegex.test(message) || /^yarat\s+/i.test(message)) {
            try {
                const imgResult = await openai.images.generate({
                    model: 'dall-e-3',
                    prompt: message,
                    n: 1,
                    size: '1024x1024',
                    response_format: 'b64_json'
                });
                const base64Image = imgResult.data?.[0]?.b64_json;
                const imageUrl = `data:image/png;base64,${base64Image}`;
                return res.json({
                    type: 'image',
                    reply: `İstədiyiniz şəkil yaradıldı.\n\n![Yaradılmış şəkil](${imageUrl})`,
                    image: imageUrl
                });
            } catch (err) {
                return res.status(500).json({ type: 'text', reply: 'Şəkil yaradılarkən xəta baş verdi.' });
            }
        }

        // --- 4. SÖHBƏT TARİXÇƏSİ (KONTEKST YADDAŞI) ---
        let conversationHistory = [];

        if (isUserLoggedIn && userEmail) {
            try {
                const historyRes = await pool.query(
                    'SELECT user_message, ai_response FROM messages WHERE user_email = $1 ORDER BY id DESC LIMIT 8',
                    [userEmail]
                );
                const pastRows = historyRes.rows.reverse();
                for (const row of pastRows) {
                    if (row.user_message) conversationHistory.push({ role: 'user', content: row.user_message });
                    if (row.ai_response) conversationHistory.push({ role: 'assistant', content: row.ai_response });
                }
            } catch (e) {
                console.error("Tarixçə oxunma xətası:", e);
            }
        } else {
            if (!req.session.chatHistory) req.session.chatHistory = [];
            conversationHistory = req.session.chatHistory.slice(-8);
        }

        // --- 5. OPENAI CHAT COMPLETION ---
        const chatCompletion = await openai.chat.completions.create({
            model: 'gpt-4o-mini',
            messages: [
                { role: 'system', content: SYSTEM_PROMPT },
                ...conversationHistory,
                { role: 'user', content: message }
            ],
            temperature: 0.7,
            max_tokens: 1500
        });

        const reply = chatCompletion.choices[0]?.message?.content || 'Cavab yaratmaq mümkün olmadı.';

        // --- 6. MESAJIN SAXLANMASI VƏ SOL PANEL SİYAHISI ---
        if (isUserLoggedIn && userEmail) {
            try {
                await pool.query(
                    'INSERT INTO messages (user_email, user_message, ai_response) VALUES ($1, $2, $3)',
                    [userEmail, message, reply]
                );
            } catch (e) {
                console.error("Baza mesaj saxlama xətası:", e);
            }
        } else {
            if (!req.session.chatHistory) req.session.chatHistory = [];
            req.session.chatHistory.push({ role: 'user', content: message });
            req.session.chatHistory.push({ role: 'assistant', content: reply });

            if (!req.session.chatHistoryList) req.session.chatHistoryList = [];
            req.session.chatHistoryList.push({ user_message: message, ai_response: reply });
        }

        let currentList = [];
        if (isUserLoggedIn && userEmail) {
            const allRes = await pool.query('SELECT user_message, ai_response FROM messages WHERE user_email = $1 ORDER BY id ASC', [userEmail]);
            currentList = allRes.rows;
        } else {
            currentList = req.session.chatHistoryList;
        }

        return res.json({ type: 'text', reply, chatHistory: currentList });

    } catch (error) {
        console.error('Ümumi /api/chat xətası:', error);
        return res.status(500).json({
            type: 'text',
            reply: 'ADA AI hazırda cavab verə bilmədi. Bir neçə saniyə sonra yenidən cəhd edin.'
        });
    }
});

// ============================================================================
// ADMIN PANEL ROUTES
// ============================================================================
app.get('/ddaam', ensureAdmin, async (req, res) => {
    try {
        const [usersCount, messagesCount, usersList, allMessages] = await Promise.all([
            pool.query('SELECT COUNT(*) FROM users'),
            pool.query('SELECT COUNT(*) FROM messages'),
            pool.query('SELECT id, fullname, email, is_admin, created_at FROM users ORDER BY id DESC'),
            pool.query('SELECT * FROM messages ORDER BY created_at DESC LIMIT 100')
        ]);
        res.render('ddaam', {
            stats: { totalUsers: usersCount.rows[0].count, totalChats: messagesCount.rows[0].count },
            users: usersList.rows,
            messages: allMessages.rows
        });
    } catch (err) {
        res.status(500).send("Server xətası");
    }
});

app.post('/ddaam/users/:id/toggle-admin', ensureAdmin, async (req, res) => {
    try {
        if (parseInt(req.params.id) === req.user.id) return res.status(400).send("Öz statusunuzu dəyişə bilməzsiniz!");
        await pool.query('UPDATE users SET is_admin = NOT is_admin WHERE id = $1', [req.params.id]);
        res.redirect('/ddaam');
    } catch (err) {
        res.status(500).send("Əməliyyat xətası");
    }
});

app.post('/ddaam/users/:id/delete', ensureAdmin, async (req, res) => {
    try {
        if (parseInt(req.params.id) === req.user.id) return res.status(400).send("Öz hesabınızı silə bilməzsiniz!");
        await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
        res.redirect('/ddaam');
    } catch (err) {
        res.status(500).send("Silinmə xətası");
    }
});

app.post('/ddaam/chats/:id/delete', ensureAdmin, async (req, res) => {
    try {
        await pool.query('DELETE FROM messages WHERE id = $1', [req.params.id]);
        res.redirect('/ddaam');
    } catch (err) {
        res.status(500).send("Söhbət silinmədi");
    }
});

// ============================================================================
// PASSWORD RESET & FEEDBACK ROUTES
// ============================================================================
app.get('/reset-password', (req, res) => {
    res.render('reset-password', { errorMessage: null, message: null });
});

app.post('/reset-password', async (req, res) => {
    const { email } = req.body;
    const resetLink = `http://localhost:3000/new-password?email=${encodeURIComponent(email)}`;
    try {
        await transporter.sendMail({
            from: `ADA AI <${process.env.GMAIL_USER}>`,
            to: email,
            subject: 'Şifrənin bərpası - ADA AI',
            html: `<h3>Şifrənizi sıfırlamaq üçün klikləyin:</h3><a href="${resetLink}">Şifrəni sıfırla</a>`
        });
        res.render('reset-password', { message: 'Sıfırlama linki e-poçtunuza göndərildi!', errorMessage: null });
    } catch (e) {
        res.render('reset-password', { errorMessage: 'E-poçt göndərilərkən xəta baş verdi.', message: null });
    }
});

app.get('/new-password', (req, res) => {
    res.render('new-password', { email: req.query.email });
});

app.post('/new-password', async (req, res) => {
    try {
        const { email, newPassword } = req.body;
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await pool.query('UPDATE users SET password = $1 WHERE email = $2', [hashedPassword, email]);
        res.redirect('/login');
    } catch (e) {
        res.status(500).send('Şifrə yenilənərkən xəta baş verdi.');
    }
});

app.post('/geribildirim', async (req, res) => {
    try {
        const { feedbackType, feedbackSubject, rating, feedbackMessage, feedbackEmail } = req.body;
        if (!feedbackMessage || feedbackMessage.trim().length < 5) {
            return res.status(400).json({ success: false, message: 'Geribildiriminizi yazın.' });
        }
        await transporter.sendMail({
            from: `"ADA Student AI" <${process.env.GMAIL_USER}>`,
            to: process.env.GMAIL_USER,
            subject: `ADA Student AI | Yeni Geribildirim`,
            text: feedbackMessage
        });
        res.json({ success: true, message: 'Geribildiriminiz uğurla göndərildi.' });
    } catch (e) {
        res.status(500).json({ success: false, message: 'Xəta baş verdi.' });
    }
});

// ============================================================================
// SERVER LAUNCH
// ============================================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server işləyir: port ${PORT}`);
});