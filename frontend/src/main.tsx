/** Entry point and router.
 *
 *  Fonts are bundled rather than fetched from a CDN: the console is a local
 *  analyst tool that has to look identical on an air-gapped machine and in a
 *  conference room with no network.
 *
 *  Routing is hash-based on purpose. The production build is served by FastAPI
 *  as a static directory, so a path route like /console would 404 on refresh
 *  unless the server grew a catch-all. A hash keeps deep links working in both
 *  the dev server and the built bundle with no server-side cooperation.
 */
import '@fontsource-variable/inter'
import '@fontsource-variable/jetbrains-mono'
import '@fontsource-variable/space-grotesk'
import './index.css'
import './landing/landing.css'

import { StrictMode, useEffect, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { App } from './App'
import { Landing } from './landing/Landing'

function Root() {
  const [hash, setHash] = useState(() => window.location.hash)

  useEffect(() => {
    const onHash = () => setHash(window.location.hash)
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [])

  const route = hash.replace(/^#\/?/, '').split('?')[0]
  if (route.startsWith('console')) return <App />
  return <Landing />
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <Root />
  </StrictMode>,
)
