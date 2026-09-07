export function Scanlines() {
  return <div className="cyber-scanlines" aria-hidden="true" />
}

export function GridPattern({ opacity = 0.04 }: { opacity?: number }) {
  return (
    <div
      className="cyber-grid-pattern"
      style={{ opacity }}
      aria-hidden="true"
    />
  )
}

export function ImageBackdrop({
  src,
  opacity = 0.1,
  blendMode = 'screen',
  invert = false,
  position = 'center',
  size = 'cover',
  className = '',
}: {
  src: string
  opacity?: number
  blendMode?: 'screen' | 'overlay' | 'lighten' | 'color-dodge' | 'soft-light'
  invert?: boolean
  position?: string
  size?: string
  className?: string
}) {
  return (
    <div
      className={`cyber-backdrop-image ${className}`}
      style={{
        position: 'absolute',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        width: '100%',
        height: '100%',
        backgroundImage: `url(${src})`,
        backgroundPosition: position,
        backgroundSize: size,
        backgroundRepeat: 'no-repeat',
        opacity,
        mixBlendMode: blendMode,
        filter: invert ? 'invert(1) contrast(1.2)' : 'contrast(1.15)',
        pointerEvents: 'none',
        zIndex: 0,
      }}
      aria-hidden="true"
    />
  )
}
