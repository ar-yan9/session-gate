# Session Gate, zero se

## Ye kis kaam ka hai?

Login page ka design akela login system nahi hota. Browser ko server se poochna
padta hai: account hai? password match hua? session abhi valid hai? Session Gate
me ye actual backend aur SQL tables ke saath hota hai. Sirf learning ke fake
accounts use kar. Apne Gmail ka password yahan mat daal.

## Words ko simple rakh

- **Frontend**: jo form browser me dikhta hai. HTML structure, CSS look, JS actions.
- **Backend**: Python process jo rules check karke response deta hai.
- **API**: frontend/backend ke beech agreed URL aur request/response format.
- **HTTP GET**: data read karne ki request. **POST**: action bhejne ki request.
- **JSON**: named fields wala data format, jaise `{ "email": "a@example.com" }`.
- **SQL**: relational database se rows read/write karne ki language.
- **SQLite**: isi laptop ki ek file me SQL database. MySQL alag database server hai.
- **Table / row / column**: data ka group / ek record / ek field.
- **Hash**: one-way password check value. Hash ko decrypt karke password nahi milta.
- **Salt**: har password hash ke saath random value, same passwords bhi same hash nahi.
- **Argon2id**: CPU aur memory use karke guessing ko mehenga banane wala password hash.
- **Cookie**: browser ka chhota value jo same app ko request ke saath jaata hai.
- **Session**: server ka temporary record: is random cookie ka user kaun hai?
- **CSRF**: doosri site se tere browser ki existing login cookie ka misuse karna.
- **Rate limit**: limited time me attempts ki upper bound. Permanent ban nahi.

## Kaun si file kya karti hai?

| File | Kaam |
| --- | --- |
| `run.py` | Settings read, FastAPI app create,127.0.0.1:8000 pe start |
| `app.py` | Route functions, field validation, hash verify, session, CSRF |
| `database.py` | Har operation ka SQL connection/transaction, atomic limits |
| `schema.sql` | `users`, `sessions`, `rate_limits` tables create |
| `static/index.html` | Sign in/register form aur account screen |
| `static/style.css` | Green theme, spacing, phone layout, focus ring |
| `static/app.js` | Fetch requests, CSRF header, loading/error, safe text display |
| `test_auth.py` | Fake accounts/temp database se expected behavior check |
| `.github/workflows/tests.yml` | GitHub push pe Windows/Ubuntu tests |
| `.env.example` | Optional config ka sample; password/key nahi |

## 1. Page kholne par

1. Browser GET `/` karta hai. HTML, CSS aur JS isi server se aate hain.
2. JS GET `/api/session` karta hai.
3. Cookie valid nahi hai to server random anonymous session aur CSRF token banata hai.
4. Cookie HttpOnly hai: JavaScript usse read nahi kar sakta. Browser bhej sakta hai.
5. JS CSRF token ko sirf memory me rakhta hai. Ye user password ya login token nahi.
6. SQL me session-cookie ka digest hai, raw cookie nahi. Anonymous expiry 30 min hai.

## 2. Register ka flow

1. Form me name, email, unique 12-128 character passphrase.
2. JS POST `/api/register`, JSON body aur `X-CSRF-Token` header bhejta hai.
3. Server origin, body-size/type, fields, session/CSRF aur attempt limit check karta hai.
4. Password ka Argon2id hash banta hai. Raw password SQL me store nahi hota.
5. SQL query values ko placeholders se bind karti hai:

```python
conn.execute(
    "INSERT OR IGNORE INTO users(email,name,password_hash,created_at) VALUES(?,?,?,?)",
    (email, name, hashed, timestamp),
)
```

`?` SQL command ka hissa fix rakhta hai. Tuple ke values data hain, SQL code nahi.
Email unique hai. Same email dobara register ho to old password replace nahi hota.
Response dono cases me same hai, taaki registration se account list na mile.
Ab sign in kar; registration khud login nahi karta. Email verify/send nahi hota.

## 3. Login ka flow

1. POST `/api/login` me normalized email aur exact password aata hai.
2. Per-email aur per-client attempt windows check hote hain, SQL transaction me.
3. `SELECT * FROM users WHERE email=?` se row milti hai.
4. Argon2 hash verify karta hai. Wrong email/password ka same error milta hai.
5. Match par naya random session ID banta hai. Purana anonymous ID delete hota hai.
6. Server HttpOnly cookie set karta hai. JS ko sirf safe user fields aur CSRF milta hai.
7. Account screen GET `/api/me` se identity dobara fetch karti hai. Backend authorize karta hai.
8. Page refresh par session valid rahega, lekin 8 hours baad absolute expiry hai.

## 4. Logout aur SQL injection

Logout POST + CSRF ke baad current session SQL se delete hota hai, cookie expire
hoti hai. Sirf screen hide nahi hoti: purani cookie se `/api/me`401 dega.

SQL injection tab ho sakti hai jab input ko SQL command me jod diya jaaye:

```python
# BAD illustration. Project me aisa query build nahi hota.
query = "SELECT * FROM users WHERE email='" + email + "'"
```

Is project me query fixed aur values bound hain. Quote wala input query ki grammar
nahi badalta. Email validation bhi hai, par validation parameter binding ka
replacement nahi. Tests SQL-like name ko data ke roop me store karte hain aur
injection-like login se authentication bypass na hone ko check karte hain.
Ye claim sirf in query paths ka hai, har future code ka automatic protection nahi.

## Khud samajhne ke liye dry-run

1. Fake address `learner@example.com` aur nayi test passphrase se register kar.
2. Wrong password se login: generic error. Sahi se login: account screen.
3. Refresh: signed in. Sign out: session revoked.
4. Same address register kar: neutral response, old password unchanged.
5. Five login requests/10 min ke baad next attempt 429. Sahi password bhi window
   khatam hone tak wait karega. Demo se pehle unnecessary repeats mat kar.
6. Tests chala; woh real users ko touch nahi karte, temp SQL databases use karte hain.

## Interview me honest paragraph

"I built a local SQL-backed authentication app with FastAPI and SQLite. It uses
parameterized SQL, Argon2id password hashing, opaque server-side sessions,
session rotation, CSRF checks and persistent attempt limits. I tested injection
strings, cookie replay after logout, expiry and concurrent limiter updates.
It is a learning project, not a production identity provider. Email verification,
password recovery, MFA and deployment hardening remain separate work."
