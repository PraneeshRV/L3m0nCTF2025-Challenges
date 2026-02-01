# 🧪 Lemon Tube

**Category:** Web Exploitation  
**Objective:** Exploit vulnerabilities in the web application to steal the admin session cookie and retrieve the flag.

---

## 🧠 Challenge Overview

Lemon Tube is a multi-stage web exploitation challenge that requires chaining the following vulnerabilities:

1. Stored Cross-Site Scripting (XSS)
2. Session Hijacking
3. Server-Side Template Injection (SSTI)

The goal is to abuse user-controlled inputs that are later viewed by an admin, steal the admin’s session cookie, gain access to the admin panel, and finally exploit an SSTI vulnerability to extract the flag.

---

## 🔐 Initial Access – Signup & Login

We begin by signing up and logging in as a normal user.

![Signup and Login](https://github.com/user-attachments/assets/34b6cadd-7aaa-43ba-953a-70b1ec88c514)
![User Dashboard](https://github.com/user-attachments/assets/7390e6ba-8d89-4818-914e-802897c8247d)

After logging in, we notice:
- A normal user dashboard
- An **admin login page**, but without valid credentials

![Admin Login Page](https://github.com/user-attachments/assets/f0c8d608-140d-474f-add2-2cca64374183)
![Admin Login Error](https://github.com/user-attachments/assets/8009556f-7e88-43c3-82e6-043506d427a7)

Direct admin login is not possible, so we move on to reconnaissance.

---

## 🔎 Recon & Endpoint Testing

We start testing all accessible endpoints that accept user input, such as:
- Contact Us
- Feedback forms
- Other user-facing input fields

Multiple XSS payloads were tested, but none of them executed successfully. These inputs were either sanitized or never rendered back to an admin.

At this point, instead of brute-forcing payloads, we shift focus to **admin behavior**.

---

## 💣 Stored XSS via Community Section

The **Community section** allows users to post comments, and these comments are reviewed by the admin.

This creates an ideal scenario for a **stored XSS vulnerability**.

![Community Section](https://github.com/user-attachments/assets/467ba369-3b2b-41c6-b3d1-f43c7b06bd61)

We submit a malicious XSS payload as a community comment.

![XSS Payload Submission](https://github.com/user-attachments/assets/80a410d2-e6a9-403a-8e9f-ee4314d06b42)

Since this is stored XSS, the payload does not execute immediately. It waits until the admin views the page.

---

## 📡 Admin Cookie Exfiltration

When the admin visits the Community section, the stored XSS payload executes and sends the admin’s session cookie to our webhook.

![Webhook Triggered](https://github.com/user-attachments/assets/ff608268-ff69-478d-b435-01fd27855b7b)

The webhook response reveals the **admin session ID**.

![Admin Session Cookie](https://github.com/user-attachments/assets/991d60ea-c0e7-464d-9f10-566bb962b600)

---

## 🕵️ Session Hijacking

Using the stolen session ID:
1. Open browser developer tools
2. Replace the current session cookie with the admin’s session value
3. Refresh the page

Result:  
✅ Access to the **Admin Panel**

---

## 🛠️ Admin Panel Enumeration

Inside the admin panel, we notice an interesting endpoint:

**Template Editor**

![Admin Panel](https://github.com/user-attachments/assets/93baec96-14d8-449e-86c8-4d8500f6864d)

Based on the name and functionality, this endpoint strongly suggests a **Server-Side Template Injection (SSTI)** vulnerability.

![Template Editor](https://github.com/user-attachments/assets/684a24b6-74bb-438a-9a4f-60c33c38ebcb)

---

## 🔥 Exploiting SSTI

We begin testing common SSTI payloads to identify the template engine and confirm code execution.

After trying multiple payloads, one successfully executed server-side logic.

### Final Payload – Flag Extraction

The final SSTI payload allowed us to access server-side objects and read the flag.

![SSTI Payload](https://github.com/user-attachments/assets/6391fcf2-0ef3-4afb-822e-717d818c45c5)
![Flag Retrieved](https://github.com/user-attachments/assets/6054b155-f284-42fd-8052-34c50c2ad2df)

🎯 **Flag successfully retrieved.**

---

## 🏁 Exploit Chain Summary

1. Register and login as a normal user  
2. Identify Community section as admin-viewed content  
3. Inject stored XSS payload  
4. Steal admin session cookie via webhook  
5. Hijack admin session  
6. Access admin panel  
7. Discover Template Editor  
8. Exploit SSTI  
9. Retrieve the flag  

---

## 🧠 Key Takeaways

- Stored XSS is extremely dangerous when admins view user-generated content
- Session cookies = authentication
- Understanding admin behavior is critical in real-world attacks
- Unsandboxed template editors are high-impact vulnerabilities
- Realistic web exploitation relies on chaining bugs, not single flaws

---

**Challenge completed successfully.**
