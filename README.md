# FirebaseAuth — Firebase Authentication REST API (Token-Based)

A professional authentication system built using the **Firebase Authentication REST API** (Identity Toolkit) with **token-based authentication**.  
This project intentionally **does NOT use the Firebase JavaScript SDK** and demonstrates direct API consumption using `fetch()` and manual token handling.

---

##  Project Description

This project demonstrates a complete **authentication lifecycle** using Firebase Authentication **REST endpoints**, including:

- Email & Password **Sign Up**
- Email & Password **Sign In**
- **Email Verification**
- Protected **Profile Lookup**
- **Profile Update**
- **Password Reset**
- **Password Change**
- **Token Refresh**
- **Account Deletion**
- Client-side **session management**
- Comprehensive **error handling**
- Mandatory **Postman API testing**

All API requests are implemented using `fetch()` with `async/await`. Authentication is handled using **ID tokens** and **refresh tokens**.

---

##  Tech Stack

- HTML5  
- CSS3  
- Vanilla JavaScript (ES6+)  
- Firebase Authentication REST API  
- Postman  

 No Firebase SDK  
 No npm packages  
 No backend server  

---

##  Authentication Method

**Token-Based Authentication**

- `idToken` — used for protected API requests  
- `refreshToken` — used to obtain a new `idToken`  
- Tokens are stored locally and never committed  
- Auto token refresh when near expiration  

---

## Base URLs
```
https://identitytoolkit.googleapis.com/v1

https://securetoken.googleapis.com/v1

```


---

## 🔗 API Endpoints Used

| Endpoint | Description |
|--------|------------|
| POST /accounts:signUp | Create new email/password account |
| POST /accounts:signInWithPassword | Authenticate user |
| POST /accounts:lookup | Retrieve user profile (protected) |
| POST /accounts:update | Update profile or password |
| POST /accounts:sendOobCode | Send password reset / email verification |
| POST /accounts:delete | Permanently delete user |
| POST /token | Refresh expired ID token |

---

## 📥 Required Parameters

### Sign Up / Sign In
```json
{
  "email": "user@email.com",
  "password": "password123",
  "returnSecureToken": true
}
```
Protected Requests

```
{
  "idToken": "USER_ID_TOKEN"
}
```
Token Refresh

```
grant_type=refresh_token
refresh_token=REFRESH_TOKEN
```

