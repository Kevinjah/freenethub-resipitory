FreeNetHub-API
Ready for GitHub -> Render deployment.

Quick start (local):
1. npm install
2. copy .env.example .env and fill keys (optional)
3. node server.js
4. Visit http://localhost:3000 and call /api/status

Deploy to Render (mobile):
1. Create repo FreeNetHub-API and upload these files.
2. On Render: New -> Web Service -> connect repo
3. Build command: npm install
4. Start command: node server.js
5. Add env vars on Render (JWT_SECRET, MPESA_*, PAYPAL_*, GOOGLE_* etc.)
6. Deploy and test endpoints

Security: Do NOT commit .env with secrets. Use Render environment variables.
