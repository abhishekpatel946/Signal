# Submission checklist (Firmable)

## Done in repo

- Ingest + score on **800k** scan records → **7,777** accounts in `app/data/accounts.json`
- Next.js queue, account evidence pages, method page (static export build succeeds)
- `README.md` + `eval/metrics.json` + `eval/gold.json`
- Git commit on `main`

## Your two steps for deliverables

### 1. Host on Vercel (root directory = `app`)

```bash
cd app
npm install
npm run build
npx vercel login
npx vercel --prod
```

Set **Root Directory** to `app` in the Vercel project settings if you import from GitHub.

Alternative: deploy only the static folder after build:

```bash
npx vercel deploy out --prod
```

Put the live URL in your email to Firmable and in `README.md` (first line).

### 2. Push to GitHub

Create an empty repo, then:

```bash
cd "G:\firmable assignment"
git remote add origin <your-github-url>
git push -u origin main
```

Do **not** push `b2_download_file_by_id` (gitignored).
