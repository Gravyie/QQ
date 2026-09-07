import { useEffect, useRef } from 'react'

interface Node {
  x: number
  y: number
  vx: number
  vy: number
  radius: number
  phase: number
}

export function QuantumCanvas({
  className = '',
  nodeCount = 45,
  connectDistance = 140,
  interactive = true,
}: {
  className?: string
  nodeCount?: number
  connectDistance?: number
  interactive?: boolean
}) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    const reducedMotion = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches
    if (reducedMotion) return

    let animId = 0
    let width = (canvas.width = canvas.parentElement?.clientWidth || window.innerWidth)
    let height = (canvas.height = canvas.parentElement?.clientHeight || window.innerHeight)

    const onResize = () => {
      if (!canvas) return
      width = canvas.width = canvas.parentElement?.clientWidth || window.innerWidth
      height = canvas.height = canvas.parentElement?.clientHeight || window.innerHeight
    }
    window.addEventListener('resize', onResize)

    // Mouse coordinates
    let mouse = { x: -1000, y: -1000 }
    const onMouseMove = (e: MouseEvent) => {
      const rect = canvas.getBoundingClientRect()
      mouse.x = e.clientX - rect.left
      mouse.y = e.clientY - rect.top
    }
    const onMouseLeave = () => {
      mouse = { x: -1000, y: -1000 }
    }

    if (interactive) {
      window.addEventListener('mousemove', onMouseMove)
      window.addEventListener('mouseleave', onMouseLeave)
    }

    // Initialize lattice nodes
    const nodes: Node[] = []
    for (let i = 0; i < nodeCount; i++) {
      nodes.push({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.4,
        vy: (Math.random() - 0.5) * 0.4,
        radius: Math.random() * 1.6 + 1.2,
        phase: Math.random() * Math.PI * 2,
      })
    }

    let t = 0
    const render = () => {
      t += 0.015
      ctx.clearRect(0, 0, width, height)

      // Update and draw nodes
      for (let i = 0; i < nodes.length; i++) {
        const n = nodes[i]
        n.x += n.vx
        n.y += n.vy

        // Wrap or bounce at boundaries
        if (n.x < 0) { n.x = 0; n.vx *= -1 }
        if (n.x > width) { n.x = width; n.vx *= -1 }
        if (n.y < 0) { n.y = 0; n.vy *= -1 }
        if (n.y > height) { n.y = height; n.vy *= -1 }

        // Subtle mouse influence
        if (interactive && mouse.x > 0) {
          const dx = mouse.x - n.x
          const dy = mouse.y - n.y
          const dist = Math.sqrt(dx * dx + dy * dy)
          if (dist < 180) {
            const force = ((180 - dist) / 180) * 0.02
            n.vx += dx * force * 0.1
            n.vy += dy * force * 0.1
          }
        }

        // Dampen velocity slightly
        n.vx *= 0.99
        n.vy *= 0.99
        if (Math.abs(n.vx) < 0.12) n.vx += (Math.random() - 0.5) * 0.1
        if (Math.abs(n.vy) < 0.12) n.vy += (Math.random() - 0.5) * 0.1

        // Draw node with quantum breathing oscillation
        const pulse = 0.5 + 0.5 * Math.sin(t + n.phase)
        ctx.beginPath()
        ctx.arc(n.x, n.y, n.radius * (0.85 + 0.3 * pulse), 0, Math.PI * 2)
        ctx.fillStyle = `rgba(94, 106, 210, ${0.4 + 0.35 * pulse})`
        ctx.shadowBlur = 8
        ctx.shadowColor = 'rgba(94, 106, 210, 0.5)'
        ctx.fill()
        ctx.shadowBlur = 0
      }

      // Draw lattice interconnects
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const a = nodes[i]
          const b = nodes[j]
          const dx = a.x - b.x
          const dy = a.y - b.y
          const dist = Math.sqrt(dx * dx + dy * dy)

          if (dist < connectDistance) {
            const alpha = (1 - dist / connectDistance) * 0.22
            ctx.beginPath()
            ctx.moveTo(a.x, a.y)
            ctx.lineTo(b.x, b.y)
            ctx.strokeStyle = `rgba(138, 155, 255, ${alpha})`
            ctx.lineWidth = 0.75
            ctx.stroke()
          }
        }
      }

      animId = requestAnimationFrame(render)
    }

    render()

    return () => {
      cancelAnimationFrame(animId)
      window.removeEventListener('resize', onResize)
      if (interactive) {
        window.removeEventListener('mousemove', onMouseMove)
        window.removeEventListener('mouseleave', onMouseLeave)
      }
    }
  }, [nodeCount, connectDistance, interactive])

  return (
    <canvas
      ref={canvasRef}
      className={`quantum-canvas ${className}`}
      style={{
        position: 'absolute',
        top: 0,
        left: 0,
        width: '100%',
        height: '100%',
        zIndex: 0,
        pointerEvents: 'none',
      }}
    />
  )
}
