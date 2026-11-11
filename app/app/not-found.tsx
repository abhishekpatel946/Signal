export default function NotFound() {
  return (
    <main className="wrap">
      <h1>Account not in this batch</h1>
      <p className="lede">
        That domain is not in the precomputed queue. Go back to the ranked list.
      </p>
      <a className="back" href="/">
        ← Accounts
      </a>
    </main>
  );
}
