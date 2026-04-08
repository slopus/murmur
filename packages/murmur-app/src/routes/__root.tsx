import { createRootRoute, Link, Outlet } from '@tanstack/react-router'

export const Route = createRootRoute({
  component: () => (
    <>
      <nav style={{ padding: '1rem', borderBottom: '1px solid #eee', display: 'flex', gap: '1rem' }}>
        <Link to="/" style={{ fontWeight: 'bold', textDecoration: 'none' }}>
          Murmur
        </Link>
        <Link to="/about" style={{ textDecoration: 'none' }}>
          About
        </Link>
      </nav>
      <main style={{ padding: '1rem' }}>
        <Outlet />
      </main>
    </>
  ),
})
