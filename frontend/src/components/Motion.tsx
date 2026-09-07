import React, { useState } from 'react'
import { motion } from 'framer-motion'

const GLYPHS = '01#*+=-~<>[]{}01'

export function GlitchText({
  text,
  className = '',
  glitchOnHover = true,
}: {
  text: string
  className?: string
  glitchOnHover?: boolean
}) {
  const [display, setDisplay] = useState(text)
  const [isGlitching, setIsGlitching] = useState(false)

  const triggerGlitch = () => {
    if (isGlitching) return
    setIsGlitching(true)
    let iter = 0
    const maxIter = text.length
    const interval = setInterval(() => {
      setDisplay(
        text
          .split('')
          .map((char, index) => {
            if (char === ' ') return ' '
            if (index < iter) return text[index]
            return GLYPHS[Math.floor(Math.random() * GLYPHS.length)]
          })
          .join('')
      )

      if (iter >= maxIter) {
        clearInterval(interval)
        setDisplay(text)
        setIsGlitching(false)
      }
      iter += 1 / 2.5
    }, 32)
  }

  return (
    <span
      className={`glitch-word ${className} ${isGlitching ? 'glitching' : ''}`}
      onMouseEnter={glitchOnHover ? triggerGlitch : undefined}
      style={{
        display: 'inline-flex',
        alignItems: 'baseline',
        whiteSpace: 'nowrap',
        verticalAlign: 'baseline',
      }}
    >
      {text.split('').map((char, index) => {
        const charDisplay = isGlitching ? (display[index] ?? char) : char
        if (char === ' ') {
          return <span key={index}>&nbsp;</span>
        }
        return (
          <span
            key={index}
            style={{
              display: 'inline-block',
              position: 'relative',
              textAlign: 'center',
              lineHeight: 'inherit',
            }}
          >
            {/* Ghost char locking exact sub-pixel width & height */}
            <span style={{ visibility: 'hidden', userSelect: 'none' }} aria-hidden="true">
              {char}
            </span>
            {/* Rendered character slot */}
            <span
              style={{
                position: 'absolute',
                top: 0,
                left: 0,
                right: 0,
                bottom: 0,
                display: 'flex',
                alignItems: 'baseline',
                justifyContent: 'center',
                overflow: 'hidden',
                color: isGlitching && charDisplay !== char ? 'var(--cyan)' : 'inherit',
                textShadow: isGlitching && charDisplay !== char ? '0 0 8px var(--cyan)' : 'none',
              }}
            >
              {charDisplay}
            </span>
          </span>
        )
      })}
    </span>
  )
}

export function FadeIn({
  children,
  delay = 0,
  duration = 0.45,
  direction = 'up',
  className = '',
  style = {},
}: {
  children: React.ReactNode
  delay?: number
  duration?: number
  direction?: 'up' | 'down' | 'none'
  className?: string
  style?: React.CSSProperties
}) {
  const yOffset = direction === 'up' ? 14 : direction === 'down' ? -14 : 0

  return (
    <motion.div
      initial={{ opacity: 0, y: yOffset }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -yOffset }}
      transition={{ duration, delay, ease: [0.25, 0.9, 0.35, 1] }}
      className={className}
      style={style}
    >
      {children}
    </motion.div>
  )
}

export function StaggerContainer({
  children,
  className = '',
  staggerDelay = 0.07,
}: {
  children: React.ReactNode
  className?: string
  staggerDelay?: number
}) {
  return (
    <motion.div
      initial="hidden"
      animate="show"
      variants={{
        hidden: {},
        show: {
          transition: {
            staggerChildren: staggerDelay,
          },
        },
      }}
      className={className}
    >
      {children}
    </motion.div>
  )
}

export function StaggerItem({
  children,
  className = '',
}: {
  children: React.ReactNode
  className?: string
}) {
  return (
    <motion.div
      variants={{
        hidden: { opacity: 0, y: 12 },
        show: { opacity: 1, y: 0, transition: { duration: 0.38, ease: [0.22, 1, 0.36, 1] } },
      }}
      className={className}
    >
      {children}
    </motion.div>
  )
}
