# GOOGLE SEARCH CONSOLE SETUP

## Step 1: Get Verification Code

1. Go to: https://search.google.com/search-console
2. Click "Add property"
3. Enter your URL: `https://parallaxdominion.vercel.app`
4. Choose "HTML tag" method
5. Copy the verification meta tag

## Step 2: Update the Code

Once you have the verification code, update `index.html`:

```html
<meta name="google-site-verification" content="YOUR_CODE_HERE">
```

Replace `YOUR_GSC_VERIFICATION_CODE` with the actual code from Google.

## Step 3: Verify

1. Go back to Google Search Console
2. Click "Verify"
3. If successful, click "Submit" to request indexing

## Step 4: Submit Sitemap

1. In Search Console, go to Sitemaps
2. Enter: `https://parallaxdominion.vercel.app/sitemap.xml`
3. Click Submit

## What to Submit for Indexing

Request indexing for these important pages:
- Homepage: /
- Services: /services.html
- Sandbox: /sandbox.html
- Agent Swarm: /agent-swarm.html
- Media Generator: /media-gen.html
- Pricing: /pricing.html

## Improve SEO

1. **Add keywords** - Already optimized
2. **Speed** - Site is fast on Vercel
3. **Mobile** - Fully responsive
4. **Links** - Submit to directories

## Quick Wins

- Submit to Google: https://search.google.com/search-console/submission-tool
- Use URL Inspection tool to request indexing

## Monitor

Check these in Search Console:
- Performance → See search impressions/clicks
- Index → Ensure pages are indexed
- Core Web Vitals → Monitor speed
