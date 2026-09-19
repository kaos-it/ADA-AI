import express from 'express';
import pkg from 'pg';
const { Pool } = pkg;

import bcrypt from 'bcrypt';
import session from 'express-session';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import Replicate from 'replicate';
import nodemailer from 'nodemailer';
import sharp from 'sharp';
import dotenv from 'dotenv';
import OpenAI from 'openai';
import cors from 'cors';
import { franc } from 'franc';
import { PrismaClient } from '@prisma/client';

dotenv.config();

const prisma = new PrismaClient();
const app = express();


// ============================================================
// BASIC EXPRESS SETTINGS
// ============================================================

app.set('trust proxy', 1);

app.use(cors());

app.use(express.json({
    limit: '50mb'
}));

app.use(express.urlencoded({
    limit: '50mb',
    extended: true
}));

app.use(express.static('public'));

app.set('view engine', 'ejs');


// ============================================================
// ENV
// ============================================================

const apiKey = process.env.OPENAI_API_KEY;


// ============================================================
// LANGUAGE DETECTION
// ============================================================

const detectLanguage = (text) => {

    if (!text) {
        return 'az';
    }

    if (/[а-яА-ЯёЁ]/.test(text)) {
        return 'ru';
    }

    if (/[əıöğşçƏIÖĞŞÇ]/.test(text)) {
        return 'az';
    }

    if (/[ıöğşçİÖĞŞÇ]/.test(text)) {
        return 'tr';
    }

    const englishWords = [
        'hello',
        'hi',
        'how',
        'what',
        'is',
        'the',
        'can',
        'you',
        'please',
        'help'
    ];

    const lowerText = text.toLowerCase();

    const isEnglish = englishWords.some(word =>
        lowerText.split(/\s+/).includes(word)
    );

    if (isEnglish) {
        return 'en';
    }

    const langCode = franc(text);

    return langCode === 'aze'
        ? 'az'
        : 'en';
};


// ============================================================
// REPLICATE
// ============================================================

const replicate = new Replicate({
    auth: process.env.REPLICATE_API_TOKEN
});


// ============================================================
// OPENAI
// ============================================================

const openai = new OpenAI({
    apiKey: process.env.OPENAI_API_KEY
});


// ============================================================
// SESSION
// ============================================================

app.use(
    session({
        secret:
            process.env.SESSION_SECRET ||
            'ada-ai-fallback-secret-key',

        resave: false,

        saveUninitialized: false,

        cookie: {
            maxAge: 24 * 60 * 60 * 1000,

            httpOnly: true,

            secure:
                process.env.NODE_ENV === 'production',

            sameSite: 'lax'
        }
    })
);


// ============================================================
// PASSPORT
// ============================================================

app.use(passport.initialize());

app.use(passport.session());


// ============================================================
// GLOBAL USER
// ============================================================

app.use((req, res, next) => {

    res.locals.user = req.user || null;

    next();
});


// ============================================================
// POSTGRESQL
// ============================================================

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,

    ssl:
        process.env.DATABASE_URL?.includes('localhost')
            ? false
            : {
                rejectUnauthorized: false
            }
});

pool.connect()
    .then(client => {

        console.log(
            '✅ Verilənlər bazasına uğurla qoşuldu!'
        );

        client.release();

    })
    .catch(err => {

        console.error(
            '❌ Baza bağlantısı xətası:',
            err.message
        );

    });


// ============================================================
// AUTH MIDDLEWARE
// ============================================================

function ensureAuthenticated(req, res, next) {

    if (req.isAuthenticated()) {
        return next();
    }

    if (req.path.startsWith('/api/')) {

        return res.status(401).json({
            error:
                'Sessiyanızın vaxtı bitib. Zəhmət olmasa daxil olun.'
        });
    }

    return res.redirect('/login');
}


// ============================================================
// ADMIN MIDDLEWARE
// ============================================================

async function ensureAdmin(req, res, next) {

    if (!req.isAuthenticated()) {
        return res.redirect('/login');
    }

    try {

        const userResult = await pool.query(
            `
            SELECT is_admin
            FROM users
            WHERE id = $1
            `,
            [req.user.id]
        );

        if (
            userResult.rows.length > 0 &&
            userResult.rows[0].is_admin
        ) {

            req.user.is_admin = true;

            return next();
        }

        return res
            .status(403)
            .send(
                'Giriş qadağandır: Yalnız adminlər üçün!'
            );

    } catch (err) {

        console.error(
            'Admin yoxlama xətası:',
            err
        );

        return res
            .status(500)
            .send('Server xətası');
    }
}


// ============================================================
// GOOGLE OAUTH STRATEGY
// ============================================================

passport.use(

    new GoogleStrategy(

        {
            clientID:
                process.env.GOOGLE_CLIENT_ID,

            clientSecret:
                process.env.GOOGLE_CLIENT_SECRET,

            callbackURL:
                process.env.GOOGLE_CALLBACK_URL
        },

        async (
            accessToken,
            refreshToken,
            profile,
            done
        ) => {

            try {

                console.log('');
                console.log(
                    '=========================================='
                );
                console.log(
                    'GOOGLE OAUTH CALLBACK İŞLƏYİR'
                );
                console.log(
                    'Google ID:',
                    profile.id
                );
                console.log(
                    'Google Name:',
                    profile.displayName
                );
                console.log(
                    'Google Email:',
                    profile.emails?.[0]?.value
                );
                console.log(
                    '=========================================='
                );


                // ----------------------------------------
                // EMAIL
                // ----------------------------------------

                const email =
                    profile.emails?.[0]?.value;


                if (!email) {

                    console.error(
                        '❌ Google hesabında email yoxdur.'
                    );

                    return done(
                        new Error(
                            'Google hesabında email tapılmadı.'
                        ),
                        null
                    );
                }


                // ----------------------------------------
                // FULLNAME
                // ----------------------------------------

                const fullname =
                    profile.displayName ||
                    'Google İstifadəçisi';


                // ----------------------------------------
                // PROFILE PHOTO
                // ----------------------------------------

                const picture =
                    profile.photos?.[0]?.value ||
                    null;


                // ----------------------------------------
                // USER AXTAR
                // ----------------------------------------

                const existingUser =
                    await pool.query(
                        `
                        SELECT *
                        FROM users
                        WHERE email = $1
                        `,
                        [email]
                    );


                // ----------------------------------------
                // USER VARSA
                // ----------------------------------------

                if (
                    existingUser.rows.length > 0
                ) {

                    console.log(
                        '✅ Mövcud istifadəçi tapıldı.'
                    );

                    const updatedUser =
                        await pool.query(
                            `
                            UPDATE users
                            SET
                                fullname = COALESCE(
                                    $1,
                                    fullname
                                ),
                                profile_picture = $2
                            WHERE email = $3
                            RETURNING *
                            `,
                            [
                                fullname,
                                picture,
                                email
                            ]
                        );


                    return done(
                        null,
                        updatedUser.rows[0]
                    );
                }


                // ----------------------------------------
                // YENİ USER YARAT
                // ----------------------------------------

                console.log(
                    '🆕 Yeni Google istifadəçisi yaradılır...'
                );


                const newUser =
                    await pool.query(
                        `
                        INSERT INTO users
                        (
                            fullname,
                            email,
                            password,
                            profile_picture
                        )
                        VALUES
                        (
                            $1,
                            $2,
                            NULL,
                            $3
                        )
                        RETURNING *
                        `,
                        [
                            fullname,
                            email,
                            picture
                        ]
                    );


                console.log(
                    '✅ Yeni Google istifadəçisi yaradıldı.'
                );


                return done(
                    null,
                    newUser.rows[0]
                );


            } catch (error) {

                console.error('');
                console.error(
                    '❌ GOOGLE AUTH ERROR'
                );
                console.error(
                    error
                );
                console.error(
                    '=========================================='
                );

                return done(
                    error,
                    null
                );
            }
        }
    )
);


// ============================================================
// GOOGLE CALLBACK
// YALNIZ 1 DƏNƏ OLMALIDIR
// ============================================================

app.get(

    '/auth/google/callback',

    passport.authenticate(
        'google',
        {
            failureRedirect: '/login'
        }
    ),

    (req, res) => {

        console.log('');
        console.log(
            '=========================================='
        );
        console.log(
            '✅ GOOGLE LOGIN UĞURLUDUR'
        );
        console.log(
            'User ID:',
            req.user?.id
        );
        console.log(
            'User:',
            req.user
        );
        console.log(
            '=========================================='
        );

        res.redirect('/chat');
    }
);


// ============================================================
// GOOGLE LOGIN
// ============================================================

app.get(

    '/auth/google',

    passport.authenticate(
        'google',
        {
            scope: [
                'profile',
                'email'
            ]
        }
    )
);


// ============================================================
// PASSPORT SERIALIZE
// ============================================================

passport.serializeUser(
    (user, done) => {

        console.log(
            '🔐 Serialize user:',
            user.id
        );

        done(
            null,
            user.id
        );
    }
);


// ============================================================
// PASSPORT DESERIALIZE
// ============================================================

passport.deserializeUser(
    async (id, done) => {

        try {

            const user =
                await pool.query(
                    `
                    SELECT
                        id,
                        fullname,
                        email,
                        is_admin,
                        profile_picture
                    FROM users
                    WHERE id = $1
                    `,
                    [id]
                );


            if (
                user.rows.length === 0
            ) {

                console.log(
                    '❌ Deserialize: istifadəçi tapılmadı.'
                );

                return done(
                    null,
                    false
                );
            }


            done(
                null,
                user.rows[0]
            );


        } catch (err) {

            console.error(
                '❌ Deserialize xətası:',
                err
            );

            done(
                err,
                null
            );
        }
    }
);


// ============================================================
// BASE ROUTING
// ============================================================

app.get(
    '/',
    (req, res) =>
        res.redirect('/login')
);


app.get(
    '/chat',
    (req, res) =>
        res.render(
            'chat',
            {
                user:
                    req.user || null
            }
        )
);


app.get(
    '/login',
    (req, res) => {

        if (
            req.isAuthenticated()
        ) {

            return res.redirect(
                '/chat'
            );
        }

        return res.render(
            'login',
            {
                errorMessage:
                    null
            }
        );
    }
);


app.get(
    '/register',
    (req, res) => {

        if (
            req.isAuthenticated()
        ) {

            return res.redirect(
                '/chat'
            );
        }

        return res.render(
            'register',
            {
                errorMessage:
                    null
            }
        );
    }
);


// ============================================================
// REGISTER
// ============================================================

app.post(
    '/register',
    async (req, res) => {

        const {
            fullname,
            email,
            password
        } = req.body;


        if (
            !fullname ||
            !email ||
            !password
        ) {

            return res.render(
                'register',
                {
                    errorMessage:
                        'Bütün xanaları doldurun!'
                }
            );
        }


        try {

            const existingUser =
                await pool.query(
                    `
                    SELECT id
                    FROM users
                    WHERE email = $1
                    `,
                    [email]
                );


            if (
                existingUser.rows.length > 0
            ) {

                return res.render(
                    'register',
                    {
                        errorMessage:
                            'Bu e-poçt ünvanı ilə artıq qeydiyyatdan keçilib!'
                    }
                );
            }


            const hashedPassword =
                await bcrypt.hash(
                    password,
                    10
                );


            await pool.query(
                `
                INSERT INTO users
                (
                    fullname,
                    email,
                    password
                )
                VALUES
                (
                    $1,
                    $2,
                    $3
                )
                `,
                [
                    fullname,
                    email,
                    hashedPassword
                ]
            );


            res.redirect(
                '/login'
            );


        } catch (err) {

            console.error(
                'Register xətası:',
                err
            );

            res.render(
                'register',
                {
                    errorMessage:
                        'Xəta baş verdi, zəhmət olmasa yenidən yoxlayın.'
                }
            );
        }
    }
);


// ============================================================
// NORMAL LOGIN
// ============================================================

app.post(
    '/login',
    async (req, res, next) => {

        const {
            email,
            password
        } = req.body;


        console.log('');
        console.log(
            '================================'
        );
        console.log(
            'LOGIN REQUEST'
        );
        console.log(
            'Email:',
            email
        );
        console.log(
            '================================'
        );


        if (
            !email ||
            !password
        ) {

            return res.render(
                'login',
                {
                    errorMessage:
                        'E-poçt və şifrə daxil edilməlidir!'
                }
            );
        }


        try {

            const userResult =
                await pool.query(
                    `
                    SELECT *
                    FROM users
                    WHERE email = $1
                    `,
                    [email]
                );


            console.log(
                'User tapıldı:',
                userResult.rows.length
            );


            if (
                userResult.rows.length === 0
            ) {

                return res.render(
                    'login',
                    {
                        errorMessage:
                            'Bu e-poçt ilə qeydiyyat tapılmadı!'
                    }
                );
            }


            const user =
                userResult.rows[0];


            console.log(
                'User ID:',
                user.id
            );

            console.log(
                'User email:',
                user.email
            );


            // ----------------------------------------
            // GOOGLE ACCOUNT
            // ----------------------------------------

            if (
                !user.password
            ) {

                return res.render(
                    'login',
                    {
                        errorMessage:
                            'Bu hesab Google ilə yaradılıb. Google ilə daxil olun.'
                    }
                );
            }


            // ----------------------------------------
            // PASSWORD CHECK
            // ----------------------------------------

            const isMatch =
                await bcrypt.compare(
                    password,
                    user.password
                );


            console.log(
                'Password match:',
                isMatch
            );


            if (!isMatch) {

                return res.render(
                    'login',
                    {
                        errorMessage:
                            'Şifrə yanlışdır!'
                    }
                );
            }


            // ----------------------------------------
            // CREATE SESSION
            // ----------------------------------------

            req.logIn(
                user,
                (err) => {

                    if (err) {

                        console.error(
                            '❌ req.logIn XƏTASI:'
                        );

                        console.error(
                            err
                        );

                        return next(
                            err
                        );
                    }


                    console.log(
                        '✅ Login uğurlu oldu'
                    );


                    return res.redirect(
                        '/chat'
                    );
                }
            );


        } catch (err) {

            console.error(
                '❌ LOGIN XƏTASI:'
            );

            console.error(
                err
            );


            return res
                .status(500)
                .send(`
                    <h1>Internal Server Error</h1>
                    <pre>${err.stack || err.message}</pre>
                `);
        }
    }
);


// ============================================================
// LOGOUT
// ============================================================

app.get(
    '/logout',
    (req, res, next) => {

        req.logout(
            (err) => {

                if (err) {
                    return next(err);
                }


                req.session.destroy(
                    (sessionError) => {

                        if (sessionError) {

                            console.error(
                                'Session destroy xətası:',
                                sessionError
                            );
                        }


                        res.clearCookie(
                            'connect.sid'
                        );


                        return res.redirect(
                            '/login'
                        );
                    }
                );
            }
        );
    }
);


// ============================================================
// DAILY AI LIMIT
// ============================================================

async function checkAndIncrementLimit(
    userId
) {

    if (!userId) {

        return {
            allowed: true
        };
    }


    try {

        const userRes =
            await pool.query(
                `
                SELECT
                    daily_requests
                FROM users
                WHERE id = $1
                `,
                [userId]
            );


        if (
            userRes.rows.length === 0
        ) {

            return {
                allowed: false
            };
        }


        const currentRequests =
            userRes.rows[0].daily_requests || 0;


        const maxLimit = 10;


        if (
            currentRequests >= maxLimit
        ) {

            return {
                allowed: false,
                currentRequests,
                maxLimit
            };
        }


        const updateRes =
            await pool.query(
                `
                UPDATE users
                SET
                    daily_requests =
                    COALESCE(
                        daily_requests,
                        0
                    ) + 1
                WHERE id = $1
                RETURNING daily_requests
                `,
                [userId]
            );


        return {
            allowed: true,

            currentRequests:
                updateRes.rows[0]
                    .daily_requests,

            maxLimit
        };


    } catch (err) {

        console.error(
            'Limit yoxlanılarkən xəta:',
            err
        );


        return {
            allowed: true
        };
    }
}


// ============================================================
// MULTIMEDIA UNIFIED CHAT API
// ============================================================

app.post(
    '/api/chat',
    async (req, res) => {

        try {

            const currentUser =
                req.user ||
                req.session?.user ||
                req.session?.passport?.user;


            const userId =
                currentUser?.id ||
                currentUser?._id;


            const isUserLoggedIn =
                req.isAuthenticated &&
                req.isAuthenticated();


            const userEmail =
                isUserLoggedIn
                    ? req.user.email
                    : null;


            // ==========================================
            // DAILY LIMIT
            // ==========================================

            if (
                isUserLoggedIn &&
                userId
            ) {

                const limitResult =
                    await checkAndIncrementLimit(
                        userId
                    );


                if (
                    !limitResult.allowed
                ) {

                    return res
                        .status(429)
                        .json({

                            type: 'limit',

                            error:
                                'Gündəlik AI sorğu limitiniz bitib. ADA Pro-ya keçid edərək limitsiz istifadə edə bilərsiniz.',

                            message:
                                'Gündəlik limitiniz tamamlanıb. Daha çox istifadə üçün ADA Pro-ya keçid edə bilərsiniz.',

                            currentRequests:
                                limitResult.currentRequests,

                            maxLimit:
                                limitResult.maxLimit,

                            redirectUrl:
                                '/adapro'
                        });
                }
            }


            // ==========================================
            // MESSAGE
            // ==========================================

            const message =
                typeof req.body.message === 'string'
                    ? req.body.message.trim()
                    : '';


            const image =
                typeof req.body.image === 'string'
                    ? req.body.image
                    : null;


            if (
                !message &&
                !image
            ) {

                return res
                    .status(400)
                    .json({

                        type: 'text',

                        reply:
                            'Zəhmət olmasa sualınızı yazın və ya şəkil göndərin.'
                    });
            }


            // ==========================================
            // IMAGE
            // ==========================================

            if (image) {

                // --------------------------------------
                // IMAGE EDIT
                // --------------------------------------

                const editingWords = [

                    'redaktə',
                    'edit',
                    'dəyiş',
                    'dəyişdir',
                    'fon',
                    'background',
                    'rəng',
                    'rəngi',
                    'sil',
                    'əlavə et',
                    'əlavə',
                    'çıxart',
                    'təmizlə',
                    'professional',
                    'peşəkar',
                    'gözəlləşdir',
                    'keyfiyyət',
                    'quality',
                    'enhance',
                    'enhance et',
                    'kəs',
                    'crop',
                    'ölçü',
                    'resize',
                    'ağ fon',
                    'qara fon',
                    'şəffaf fon'
                ];


                const wantsEdit =
                    message &&
                    editingWords.some(
                        word =>
                            message
                                .toLowerCase()
                                .includes(word)
                    );


                if (wantsEdit) {

                    try {

                        const result =
                            await openai.images.edit({

                                model:
                                    'gpt-image-1',

                                image,

                                prompt: `
Sən ADA AI üçün professional şəkil redaktə sistemisən.

İstifadəçinin tələbini mümkün qədər dəqiq yerinə yetir.

İstifadəçi tələbi:
${message}

Əsas qaydalar:

- Mövcud şəklin əsas obyektini mümkün qədər qoruyub saxla.
- İstifadəçi xüsusi dəyişiklik istəyirsə həmin dəyişiklikləri professional şəkildə həyata keçir.
- Fon dəyişdirilməsi istənirsə fonu dəyiş.
- Obyekt silinməsi istənirsə həmin obyekti sil.
- Obyekt əlavə edilməsi istənirsə realistik şəkildə əlavə et.
- Rəng düzəlişi istənirsə rəngləri professional şəkildə düzəlt.
- Keyfiyyət artırılması istənirsə daha təmiz və professional görünüş yarat.
- "professional et" kimi ümumi tələb varsa şəkli daha keyfiyyətli, balanslı, təmiz və vizual olaraq professional et.
- İnsan üzlərini lazımsız şəkildə dəyişmə.
- Mətn varsa mümkün qədər qoruyub saxla.
`,

                                size:
                                    '1024x1024'
                            });


                        const base64Image =
                            result.data?.[0]?.b64_json;


                        if (!base64Image) {

                            throw new Error(
                                'OpenAI redaktə olunmuş şəkil qaytarmadı.'
                            );
                        }


                        const outputImage =
                            `data:image/png;base64,${base64Image}`;


                        const responseData = {

                            type:
                                'image',

                            reply:
                                `Şəkil istəyinizə uyğun olaraq redaktə edildi.\n\n![Redaktə olunmuş şəkil](${outputImage})`,

                            image:
                                outputImage
                        };


                        if (
                            isUserLoggedIn &&
                            userEmail
                        ) {

                            try {

                                await pool.query(
                                    `
                                    INSERT INTO messages
                                    (
                                        user_email,
                                        user_message,
                                        ai_response
                                    )
                                    VALUES
                                    (
                                        $1,
                                        $2,
                                        $3
                                    )
                                    `,
                                    [
                                        userEmail,
                                        message || '[Şəkil]',
                                        responseData.reply
                                    ]
                                );

                            } catch (dbErr) {

                                console.error(
                                    'DB mesaj saxlama xətası:',
                                    dbErr
                                );
                            }
                        }


                        return res.json(
                            responseData
                        );


                    } catch (imageError) {

                        console.error(
                            'AI şəkil redaktə xətası:',
                            imageError
                        );


                        return res
                            .status(500)
                            .json({

                                type:
                                    'error',

                                error:
                                    'Şəkil redaktə edilərkən xəta baş verdi: ' +
                                    (
                                        imageError.message ||
                                        'Naməlum xəta'
                                    )
                            });
                    }
                }


                // --------------------------------------
                // IMAGE ONLY
                // --------------------------------------

                if (!message) {

                    try {

                        const response =
                            await openai.responses.create({

                                model:
                                    'gpt-5.6-luna',

                                input: [

                                    {
                                        role:
                                            'user',

                                        content: [

                                            {
                                                type:
                                                    'input_text',

                                                text: `
Bu şəkli ətraflı analiz et.

Şəkildə nə olduğunu izah et.
Görünən obyektləri təsvir et.
Əgər şəkildə mətn varsa oxu.
Şəkil haqqında istifadəçiyə faydalı məlumat ver.
`
                                            },

                                            {
                                                type:
                                                    'input_image',

                                                image_url:
                                                    image
                                            }
                                        ]
                                    }
                                ]
                            });


                        const reply =
                            response.output_text ||
                            'Şəkli analiz etmək mümkün olmadı.';


                        const responseData = {

                            type:
                                'text',

                            reply
                        };


                        if (
                            isUserLoggedIn &&
                            userEmail
                        ) {

                            await pool.query(
                                `
                                INSERT INTO messages
                                (
                                    user_email,
                                    user_message,
                                    ai_response
                                )
                                VALUES
                                (
                                    $1,
                                    $2,
                                    $3
                                )
                                `,
                                [
                                    userEmail,
                                    '[Şəkil analizi]',
                                    reply
                                ]
                            );
                        }


                        return res.json(
                            responseData
                        );


                    } catch (visionError) {

                        console.error(
                            'Şəkil analiz xətası:',
                            visionError
                        );


                        return res
                            .status(500)
                            .json({

                                error:
                                    'Şəkil analiz edilərkən xəta baş verdi.'
                            });
                    }
                }


                // --------------------------------------
                // IMAGE + MESSAGE
                // --------------------------------------

                try {

                    const response =
                        await openai.responses.create({

                            model:
                                'gpt-5.6-luna',

                            input: [

                                {
                                    role:
                                        'system',

                                    content: `
Sənin adın ADA-dır.

Sən ADA Group tərəfindən yaradılmış peşəkar AI köməkçisisən.

İstifadəçinin sualına dəqiq və faydalı cavab ver.

Azərbaycan dilində sual verilirsə Azərbaycan dilində,
ingilis dilində verilirsə ingilis dilində,
rus dilində verilirsə rus dilində cavab ver.

Şəkildəki məlumatı nəzərə al.
`
                                },

                                {
                                    role:
                                        'user',

                                    content: [

                                        {
                                            type:
                                                'input_text',

                                            text:
                                                message
                                        },

                                        {
                                            type:
                                                'input_image',

                                            image_url:
                                                image
                                        }
                                    ]
                                }
                            ]
                        });


                    const reply =
                        response.output_text ||
                        'Cavab yaratmaq mümkün olmadı.';


                    const responseData = {

                        type:
                            'text',

                        reply
                    };


                    if (
                        isUserLoggedIn &&
                        userEmail
                    ) {

                        await pool.query(
                            `
                            INSERT INTO messages
                            (
                                user_email,
                                user_message,
                                ai_response
                            )
                            VALUES
                            (
                                $1,
                                $2,
                                $3
                            )
                            `,
                            [
                                userEmail,
                                message,
                                reply
                            ]
                        );
                    }


                    return res.json(
                        responseData
                    );


                } catch (visionChatError) {

                    console.error(
                        'Şəkilli chat xətası:',
                        visionChatError
                    );


                    return res
                        .status(500)
                        .json({

                            error:
                                'Şəkilli sorğu emal edilərkən xəta baş verdi.'
                        });
                }
            }


            // ==========================================
            // IMAGE CREATION
            // ==========================================

            const creationRegex =
                /^(şəkil|foto|şəkli|resm|picture|image|logo|photo)\s+(yarat|düzəlt|çək|generate|draw|hazırla)/i;


            const wantsImage =
                creationRegex.test(message) ||
                /^yarat\s+/i.test(message) ||
                /^generate\s+/i.test(message) ||
                /şəkil yarat/i.test(message);


            if (wantsImage) {

                try {

                    const result =
                        await openai.images.generate({

                            model:
                                'gpt-image-1',

                            prompt:
                                message,

                            size:
                                '1024x1024'
                        });


                    const base64Image =
                        result.data?.[0]?.b64_json;


                    if (!base64Image) {

                        throw new Error(
                            'Şəkil yaradılmadı.'
                        );
                    }


                    const imageUrl =
                        `data:image/png;base64,${base64Image}`;


                    const responseData = {

                        type:
                            'image',

                        reply:
                            `İstədiyiniz şəkil yaradıldı.\n\n![Yaradılmış şəkil](${imageUrl})`,

                        image:
                            imageUrl
                    };


                    if (
                        isUserLoggedIn &&
                        userEmail
                    ) {

                        await pool.query(
                            `
                            INSERT INTO messages
                            (
                                user_email,
                                user_message,
                                ai_response
                            )
                            VALUES
                            (
                                $1,
                                $2,
                                $3
                            )
                            `,
                            [
                                userEmail,
                                message,
                                responseData.reply
                            ]
                        );
                    }


                    return res.json(
                        responseData
                    );


                } catch (imageCreateError) {

                    console.error(
                        'Şəkil yaratma xətası:',
                        imageCreateError
                    );


                    return res
                        .status(500)
                        .json({

                            error:
                                'Şəkil yaradılarkən xəta baş verdi.'
                        });
                }
            }


            // ==========================================
            // NORMAL AI CHAT
            // ==========================================

            try {

                const response =
                    await openai.responses.create({

                        model:
                            'gpt-5.6-luna',

                        tools: [

                            {
                                type:
                                    'web_search'
                            }
                        ],

                        input: [

                            {
                                role:
                                    'system',

                                content: `
Sənin adın ADA-dır.

Sən Ağasif Əliyevin yaratdığı
ADA Group çərçivəsində fəaliyyət göstərən
peşəkar AI köməkçisən.

ADA Universiteti ilə əlaqən yoxdur.

İstifadəçinin sualına mümkün qədər dəqiq,
aydın və faydalı cavab ver.

İstifadəçi hansı dildə yazırsa həmin dildə cavab ver.

Cari və dəyişən məlumat tələb edən suallarda
web search imkanından istifadə et.

Məsələn:

- xəbərlər
- hava
- valyuta
- idman
- texnologiya xəbərləri
- şirkət məlumatları
- qiymətlər
- son hadisələr
- aktual qanunlar
- cari tarixlə bağlı məlumatlar

Məlumatı uydurma.
Əmin olmadığın məlumatı fakt kimi təqdim etmə.

Kod suallarında işlək və praktik nümunələr ver.
`
                            },

                            {
                                role:
                                    'user',

                                content:
                                    message
                            }
                        ]
                    });


                const reply =
                    response.output_text ||
                    'Cavab yaratmaq mümkün olmadı.';


                const responseData = {

                    type:
                        'text',

                    reply
                };


                if (
                    isUserLoggedIn &&
                    userEmail
                ) {

                    try {

                        await pool.query(
                            `
                            INSERT INTO messages
                            (
                                user_email,
                                user_message,
                                ai_response
                            )
                            VALUES
                            (
                                $1,
                                $2,
                                $3
                            )
                            `,
                            [
                                userEmail,
                                message,
                                reply
                            ]
                        );

                    } catch (dbErr) {

                        console.error(
                            'Mesaj DB-yə yazılmadı:',
                            dbErr
                        );
                    }
                }


                return res.json(
                    responseData
                );


            } catch (aiError) {

                console.error(
                    'OpenAI API xətası:',
                    aiError
                );


                return res
                    .status(500)
                    .json({

                        error:
                            'ADA AI hazırda cavab verə bilmədi. Bir neçə saniyə sonra yenidən cəhd edin.'
                    });
            }


        } catch (error) {

            console.error(
                'Ümumi /api/chat xətası:',
                error
            );


            return res
                .status(500)
                .json({

                    error:
                        'Serverdə xəta baş verdi.'
                });
        }
    }
);


// ============================================================
// ADMIN PANEL
// ============================================================

app.get(
    '/ddaam',
    ensureAdmin,
    async (req, res) => {

        try {

            const [
                usersCount,
                messagesCount,
                usersList,
                allMessages
            ] =
                await Promise.all([

                    pool.query(
                        'SELECT COUNT(*) FROM users'
                    ),

                    pool.query(
                        'SELECT COUNT(*) FROM messages'
                    ),

                    pool.query(
                        `
                        SELECT
                            id,
                            fullname,
                            email,
                            is_admin,
                            created_at
                        FROM users
                        ORDER BY id DESC
                        `
                    ),

                    pool.query(
                        `
                        SELECT *
                        FROM messages
                        ORDER BY created_at DESC
                        LIMIT 100
                        `
                    )
                ]);


            res.render(
                'ddaam',
                {
                    stats: {
                        totalUsers:
                            usersCount.rows[0].count,

                        totalChats:
                            messagesCount.rows[0].count
                    },

                    users:
                        usersList.rows,

                    messages:
                        allMessages.rows
                }
            );


        } catch (err) {

            console.error(
                'Admin panel xətası:',
                err
            );

            res
                .status(500)
                .send(
                    'Server xətası'
                );
        }
    }
);


// ============================================================
// ADMIN TOGGLE
// ============================================================

app.post(
    '/ddaam/users/:id/toggle-admin',
    ensureAdmin,
    async (req, res) => {

        try {

            if (
                parseInt(req.params.id) ===
                req.user.id
            ) {

                return res
                    .status(400)
                    .send(
                        'Öz statusunuzu dəyişə bilməzsiniz!'
                    );
            }


            await pool.query(
                `
                UPDATE users
                SET is_admin = NOT is_admin
                WHERE id = $1
                `,
                [req.params.id]
            );


            res.redirect(
                '/ddaam'
            );


        } catch (err) {

            console.error(err);

            res
                .status(500)
                .send(
                    'Əməliyyat xətası'
                );
        }
    }
);


// ============================================================
// ADMIN DELETE USER
// ============================================================

app.post(
    '/ddaam/users/:id/delete',
    ensureAdmin,
    async (req, res) => {

        try {

            if (
                parseInt(req.params.id) ===
                req.user.id
            ) {

                return res
                    .status(400)
                    .send(
                        'Öz hesabınızı silə bilməzsiniz!'
                    );
            }


            await pool.query(
                `
                DELETE FROM users
                WHERE id = $1
                `,
                [req.params.id]
            );


            res.redirect(
                '/ddaam'
            );


        } catch (err) {

            console.error(err);

            res
                .status(500)
                .send(
                    'Silinmə xətası'
                );
        }
    }
);


// ============================================================
// ADMIN DELETE CHAT
// ============================================================

app.post(
    '/ddaam/chats/:id/delete',
    ensureAdmin,
    async (req, res) => {

        try {

            await pool.query(
                `
                DELETE FROM chats
                WHERE id = $1
                `,
                [req.params.id]
            );


            res.redirect(
                '/ddaam'
            );


        } catch (err) {

            console.error(err);

            res
                .status(500)
                .send(
                    'Söhbət silinmədi'
                );
        }
    }
);


// ============================================================
// PASSWORD RESET
// ============================================================

app.get(
    '/reset-password',
    (req, res) => {

        res.render(
            'reset-password',
            {
                errorMessage:
                    null,

                message:
                    null
            }
        );
    }
);


app.post(
    '/reset-password',
    async (req, res) => {

        const {
            email
        } = req.body;


        const resetLink =
            `https://orca-app-prkkq.ondigitalocean.app/new-password?email=${encodeURIComponent(email)}`;


        const resetTransporter =
            nodemailer.createTransport({

                service:
                    'gmail',

                auth: {

                    user:
                        process.env.EMAIL_USER,

                    pass:
                        process.env.EMAIL_PASS
                }
            });


        const mailOptions = {

            from:
                `ADA AI <${process.env.EMAIL_USER}>`,

            to:
                email,

            subject:
                'Şifrənin bərpası - ADA AI',

            html:
                `
                <h3>
                    Şifrənizi sıfırlamaq üçün
                    aşağıdakı linkə klikləyin:
                </h3>

                <a href="${resetLink}">
                    Şifrəni sıfırla
                </a>
                `
        };


        try {

            await resetTransporter.sendMail(
                mailOptions
            );


            return res.render(
                'reset-password',
                {

                    message:
                        'Sıfırlama linki e-poçtunuza göndərildi!',

                    errorMessage:
                        null
                }
            );


        } catch (error) {

            console.error(
                error
            );


            return res.render(
                'reset-password',
                {

                    errorMessage:
                        'E-poçt göndərilərkən xəta baş verdi.',

                    message:
                        null
                }
            );
        }
    }
);


// ============================================================
// NEW PASSWORD
// ============================================================

app.get(
    '/new-password',
    (req, res) => {

        const {
            email
        } = req.query;


        res.render(
            'new-password',
            {
                email
            }
        );
    }
);


app.post(
    '/new-password',
    async (req, res) => {

        try {

            const {
                email,
                newPassword
            } = req.body;


            const hashedPassword =
                await bcrypt.hash(
                    newPassword,
                    10
                );


            await prisma.user.update({

                where: {
                    email
                },

                data: {
                    password:
                        hashedPassword
                }
            });


            res.redirect(
                '/login'
            );


        } catch (error) {

            console.error(
                error
            );


            res
                .status(500)
                .send(
                    'Şifrə yenilənərkən xəta baş verdi.'
                );
        }
    }
);


// ============================================================
// ADA PRO
// ============================================================

app.get(
    '/ada-pro',
    (req, res) => {

        res.render(
            'adapro',
            {
                user:
                    req.user || null
            }
        );
    }
);


app.get(
    '/adapro',
    (req, res) => {

        res.render(
            'adapro',
            {
                user:
                    req.user || null
            }
        );
    }
);


// ============================================================
// LIMIT PAGE
// ============================================================

app.get(
    '/limit',
    async (req, res) => {

        const currentUser =
            req.user ||
            req.session?.user ||
            req.session?.passport?.user;


        let userLimit = 0;


        if (
            currentUser &&
            currentUser.id
        ) {

            try {

                const result =
                    await pool.query(
                        `
                        SELECT *
                        FROM users
                        WHERE id = $1
                        `,
                        [currentUser.id]
                    );


                if (
                    result.rows.length > 0
                ) {

                    userLimit =
                        result.rows[0]
                            .daily_requests ||
                        result.rows[0]
                            .requestCount ||
                        result.rows[0]
                            .query_count ||
                        0;
                }


            } catch (err) {

                console.error(
                    'Limit oxunarkən xəta:',
                    err
                );
            }
        }


        const maxLimit = 10;


        const percentage =
            Math.min(
                (userLimit / maxLimit) * 100,
                100
            );


        res.render(
            'limit',
            {

                user:
                    currentUser || null,

                userLimit,

                maxLimit,

                percentage
            }
        );
    }
);


// ============================================================
// OTHER PAGES
// ============================================================

app.get(
    '/help',
    (req, res) => {
        res.render('help');
    }
);


app.get(
    '/gizlilik',
    (req, res) => {
        res.render('gizlilik');
    }
);


app.get(
    '/fedback',
    (req, res) => {
        res.render('fedback');
    }
);


// ============================================================
// GMAIL TRANSPORTER
// ============================================================

const transporter =
    nodemailer.createTransport({

        service:
            'gmail',

        auth: {

            user:
                process.env.GMAIL_USER,

            pass:
                process.env.GMAIL_APP_PASSWORD
        }
    });


// ============================================================
// GMAIL TEST
// ============================================================

transporter.verify(
    (error, success) => {

        if (error) {

            console.error(
                '❌ Gmail bağlantısı uğursuz oldu:'
            );

            console.error(
                error.message
            );

        } else {

            console.log(
                '✅ Gmail SMTP bağlantısı hazırdır.'
            );
        }
    }
);


// ============================================================
// FEEDBACK PAGE
// ============================================================

app.get(
    '/geribildirim',
    (req, res) => {

        res.render(
            'geribildirim'
        );
    }
);


// ============================================================
// FEEDBACK SEND
// ============================================================

app.post(
    '/geribildirim',
    async (req, res) => {

        try {

            const {
                feedbackType,
                feedbackSubject,
                rating,
                feedbackMessage,
                feedbackEmail
            } = req.body;


            if (
                !feedbackMessage ||
                feedbackMessage.trim().length < 5
            ) {

                return res
                    .status(400)
                    .json({

                        success:
                            false,

                        message:
                            'Zəhmət olmasa geribildiriminizi yazın.'
                    });
            }


            const type =
                feedbackType ||
                'Ümumi rəy';


            const subject =
                feedbackSubject ||
                'Mövzu qeyd edilməyib';


            const userRating =
                rating ||
                'Verilməyib';


            const email =
                feedbackEmail ||
                'Email qeyd edilməyib';


            const message =
                feedbackMessage.trim();


            const emailHTML = `

<!DOCTYPE html>

<html lang="az">

<head>

<meta charset="UTF-8">

</head>

<body style="
margin:0;
padding:30px;
background:#f1f5f9;
font-family:Arial,Helvetica,sans-serif;
">

<div style="
max-width:700px;
margin:auto;
background:#ffffff;
border-radius:18px;
overflow:hidden;
box-shadow:0 10px 30px rgba(0,0,0,0.08);
">

<div style="
background:linear-gradient(135deg,#2563eb,#4f46e5);
padding:30px;
color:#ffffff;
">

<h1 style="
margin:0;
font-size:26px;
">
ADA Student AI
</h1>

<p style="
margin:8px 0 0;
opacity:.9;
font-size:15px;
">
Yeni geribildirim
</p>

</div>


<div style="
padding:30px;
">

<div style="
margin-bottom:22px;
padding:18px;
background:#f8fafc;
border-radius:12px;
">

<strong>
Geribildirim növü
</strong>

<div style="
margin-top:7px;
color:#475569;
">

${escapeHtml(type)}

</div>

</div>


<div style="
margin-bottom:22px;
padding:18px;
background:#f8fafc;
border-radius:12px;
">

<strong>
Mövzu
</strong>

<div style="
margin-top:7px;
color:#475569;
">

${escapeHtml(subject)}

</div>

</div>


<div style="
margin-bottom:22px;
padding:18px;
background:#f8fafc;
border-radius:12px;
">

<strong>
Reytinq
</strong>

<div style="
margin-top:8px;
font-size:20px;
">

${getStars(userRating)}

</div>

</div>


<div style="
margin-bottom:22px;
padding:18px;
background:#f8fafc;
border-radius:12px;
">

<strong>
İstifadəçi emaili
</strong>

<div style="
margin-top:7px;
color:#475569;
">

${escapeHtml(email)}

</div>

</div>


<div style="
padding:20px;
background:#eff6ff;
border-left:4px solid #2563eb;
border-radius:10px;
">

<strong style="color:#1e3a8a;">

Geribildirim

</strong>

<p style="
margin:12px 0 0;
color:#334155;
line-height:1.7;
white-space:pre-wrap;
">

${escapeHtml(message)}

</p>

</div>

</div>


<div style="
padding:20px 30px;
background:#f8fafc;
border-top:1px solid #e2e8f0;
color:#64748b;
font-size:13px;
">

Bu mesaj ADA Student AI platformunun
geribildirim sistemi tərəfindən göndərilib.

</div>

</div>

</body>

</html>

`;


            const mailSubject =
                `ADA Student AI | Yeni Geribildirim | ${type}`;


            await transporter.sendMail({

                from:
                    `"ADA Student AI" <${process.env.GMAIL_USER}>`,

                to:
                    process.env.GMAIL_USER,

                replyTo:
                    feedbackEmail &&
                    feedbackEmail.includes('@')
                        ? feedbackEmail
                        : undefined,

                subject:
                    mailSubject,

                html:
                    emailHTML
            });


            console.log(
                '✅ Geribildirim Gmail-ə göndərildi.'
            );


            return res.json({

                success:
                    true,

                message:
                    'Geribildiriminiz uğurla göndərildi.'
            });


        } catch (error) {

            console.error(
                '❌ Geribildirim göndərilərkən xəta:'
            );

            console.error(
                error
            );


            return res
                .status(500)
                .json({

                    success:
                        false,

                    message:
                        'Geribildirim göndərilmədi. Zəhmət olmasa bir qədər sonra yenidən cəhd edin.'
                });
        }
    }
);


// ============================================================
// HELPER FUNCTIONS
// ============================================================

function escapeHtml(value) {

    return String(value)

        .replace(
            /&/g,
            '&amp;'
        )

        .replace(
            /</g,
            '&lt;'
        )

        .replace(
            />/g,
            '&gt;'
        )

        .replace(
            /"/g,
            '&quot;'
        )

        .replace(
            /'/g,
            '&#039;'
        );
}


function getStars(rating) {

    const number =
        parseInt(rating);


    if (
        isNaN(number) ||
        number < 1 ||
        number > 5
    ) {

        return 'Reytinq verilməyib';
    }


    return (
        '★'.repeat(number) +
        '☆'.repeat(5 - number)
    );
}


// ============================================================
// SERVER
// ============================================================

const PORT =
    process.env.PORT || 3000;


app.listen(
    PORT,
    '0.0.0.0',
    () => {

        console.log('');
        console.log(
            '=========================================='
        );

        console.log(
            `🚀 Server qlobal olaraq işləyir: port ${PORT}`
        );

        console.log(
            `🌐 NODE_ENV: ${process.env.NODE_ENV || 'development'}`
        );

        console.log(
            `🔐 Google Callback: ${process.env.GOOGLE_CALLBACK_URL || 'TƏYİN EDİLMƏYİB'}`
        );

        console.log(
            '=========================================='
        );
    }
);