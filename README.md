# Nexora API

Express + MongoDB API for the Jharkhand Social Innovation Portal. It models the complete `exp1` lifecycle: citizen challenges, AI classification and HEI routing, university proposals, company/CSR sponsorship, milestones, government allocation, notifications, and state analytics.

## Local setup

1. Copy `.env.example` to `.env` and fill every value.
2. Use a MongoDB Atlas connection string (or local MongoDB during development).
3. Run `npm install`, then `npm run dev`.

The first startup creates the administrator from `ADMIN_EMAIL`, `ADMIN_PASSWORD`, and `ADMIN_NAME` when that email does not already exist. Keep `.env` private and use a long, unique `JWT_SECRET` and administrator password.

## Deploy to Render

Create a Web Service using this directory as the root. Use build command `npm install` and start command `npm start`. Add `MONGODB_URI`, `JWT_SECRET`, `ADMIN_EMAIL`, `ADMIN_PASSWORD`, and `CLIENT_URL` as Render environment variables. `CLIENT_URL` must match the deployed Vercel URL, for example `https://your-site.vercel.app`; comma-separate multiple allowed frontend URLs if needed. Trailing slashes are ignored.

Challenge evidence (up to four JPG, PNG, WebP, or PDF files) is stored as bounded data in MongoDB and served through challenge evidence routes.

## Main API groups

- `GET`/`POST /api/challenges` — browse and submit AI-routed challenges.
- `POST /api/challenges/:code/upvote` — register community support.
- `POST /api/challenges/:code/proposal` — submit an HEI team proposal (university/admin account).
- `POST /api/challenges/:code/sponsorship` — pledge CSR support (company/admin account).
- `PATCH /api/challenges/:code/milestones/:milestoneId` — update project delivery.
- `PATCH /api/admin/challenges/:code` and `GET /api/admin/analytics` — government operations.
- `GET /api/notifications` — portal notifications.
