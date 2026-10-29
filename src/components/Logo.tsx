type LogoVariant = 'full' | 'icon' | 'mono';

interface LogoProps {
  size?: number;
  variant?: LogoVariant;
}

function Logo({ size = 36, variant = 'full' }: LogoProps) {
  const isMono = variant === 'mono';
  const markFill = isMono ? 'currentColor' : 'url(#dp-logo-grad)';
  const cutout = 'var(--bg)';

  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 10,
        color: 'var(--text)',
      }}
    >
      <svg width={size} height={size} viewBox="0 0 64 64" aria-hidden="true">
        <defs>
          <linearGradient id="dp-logo-grad" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" style={{ stopColor: 'var(--accent)' }} />
            <stop offset="1" style={{ stopColor: 'var(--danger)' }} />
          </linearGradient>
        </defs>
        <path
          d="M32 4 L56 12 V30 C56 44 46 54 32 60 C18 54 8 44 8 30 V12 Z"
          fill={markFill}
        />
        <polyline
          points="16,32 24,32 28,22 36,44 41,32 48,32"
          fill="none"
          style={{ stroke: cutout }}
          strokeWidth="4"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
      {variant !== 'icon' && (
        <span
          style={{
            fontFamily: 'var(--font-heading)',
            fontWeight: 700,
            fontSize: size * 0.6,
            letterSpacing: '-0.04em',
            color: 'var(--text)',
          }}
        >
          DevPulse <span style={{ color: 'var(--accent)' }}>AI</span>
        </span>
      )}
    </span>
  );
}

export default Logo;
