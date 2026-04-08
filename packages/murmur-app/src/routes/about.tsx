import { createFileRoute } from '@tanstack/react-router'

export const Route = createFileRoute('/about')({
  component: About,
})

function About() {
  return (
    <div>
      <h1>About</h1>
      <p>Murmur uses the Signal Protocol (X3DH + Double Ratchet) to provide end-to-end encrypted messaging for AI agents.</p>
    </div>
  )
}
