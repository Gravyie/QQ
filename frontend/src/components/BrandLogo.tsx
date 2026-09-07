import { motion } from 'framer-motion'

export function BrandLogo({
  variant = 'console',
  onClick,
}: {
  variant?: 'landing' | 'console'
  onClick?: () => void
}) {
  return (
    <motion.div
      layoutId="mainBrandLogo"
      className={variant === 'landing' ? 'lp-mark' : 'brand'}
      onClick={onClick}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        cursor: 'pointer',
        userSelect: 'none',
        textDecoration: 'none',
        flexShrink: 0,
      }}
      transition={{
        type: 'spring',
        stiffness: 320,
        damping: 30,
        mass: 0.8,
      }}
    >
      <motion.svg
        layoutId="mainBrandLogoIcon"
        width="20"
        height="20"
        viewBox="0 0 20 20"
        fill="none"
        aria-hidden="true"
        style={{
          flex: 'none',
          display: 'block',
          filter: 'drop-shadow(0 0 8px rgba(0, 240, 255, 0.6))',
        }}
        transition={{
          type: 'spring',
          stiffness: 320,
          damping: 30,
        }}
      >
        <path d="M10 1.6 18 6v8l-8 4.4L2 14V6l8-4.4Z" stroke="var(--cyan)" strokeWidth="1.3" opacity="0.9" />
        <path d="M10 6.2 14 8.4v4.2L10 14.8 6 12.6V8.4l4-2.2Z" stroke="var(--accent)" strokeWidth="1.1" opacity="0.8" />
        <circle cx="10" cy="10.5" r="1.8" fill="var(--cyan)" />
      </motion.svg>

      <motion.b
        layoutId="mainBrandLogoText"
        style={{
          fontFamily: 'var(--display)',
          fontSize: '15px',
          fontWeight: 600,
          letterSpacing: '-0.3px',
          color: 'var(--t1)',
          marginLeft: '8px',
          display: 'inline-block',
          lineHeight: 1,
        }}
        transition={{
          type: 'spring',
          stiffness: 320,
          damping: 30,
        }}
      >
        Quantum Atlas
      </motion.b>

      <motion.span
        layoutId="mainBrandLogoBadge"
        style={{
          fontFamily: 'var(--mono)',
          fontSize: '9.5px',
          letterSpacing: '1px',
          color: 'var(--cyan)',
          marginLeft: '8px',
          padding: '2px 6px',
          borderRadius: '4px',
          border: '1px solid rgba(0, 240, 255, 0.25)',
          background: 'rgba(0, 240, 255, 0.06)',
          fontWeight: 600,
          display: 'inline-block',
          lineHeight: 1,
        }}
        transition={{
          type: 'spring',
          stiffness: 320,
          damping: 30,
        }}
      >
        {variant === 'landing' ? 'ECDAT 26164' : 'ECDAT'}
      </motion.span>
    </motion.div>
  )
}
