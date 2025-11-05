# FoodHub

A small demo food ordering web application (FoodHub) built with Express.js and a static React frontend (via CDN). This project is intentionally simple and beginner-friendly.

Features
- Landing page with search box
- Login and registration (passwords hashed with bcrypt)
- Menu display with featured dishes
- Detailed dish view with quantity selector and Add to Cart / Place Order
- Simple cart with item summary and total
- Checkout with delivery details and payment selection
- Admin product CRUD (requires admin account)

Seed data
- Admin user: username `admin` password `admin123`
- Sample products: Margherita Pizza, Chicken Burger, Pad Thai

Run (Windows PowerShell)

1. Install dependencies:

```powershell
cd "e:\food order"
npm install
```

2. Start server:

```powershell
npm start
```

3. Open http://localhost:3000 in your browser.

Notes
- This demo uses a JSON file `db.json` (lowdb) for storage. For production use a real database.
- JWT secret and other secrets are in code for demo; move to env vars for real apps.
- Tailwind is loaded via CDN for quick styling.

Next steps (optional):
- Move frontend to React+Vite for a modern dev flow.
- Add input validation and better error handling.
- Add order history page.
