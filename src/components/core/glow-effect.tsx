import { motion, type Transition } from 'framer-motion';
import type { CSSProperties } from 'react';

export type GlowEffectProps = {
  className?: string;
  style?: CSSProperties;
  colors?: string[];
  mode?:
    'rotate' | 'pulse' | 'breathe' | 'colorShift' | 'flowHorizontal' | 'static';
  blur?:
    | number
    | 'softest'
    | 'soft'
    | 'medium'
    | 'strong'
    | 'stronger'
    | 'strongest'
    | 'none';
  transition?: Transition;
  scale?: number;
  duration?: number;
};

export function GlowEffect({
  className,
  style,
  colors = ['#B6FF2E'],
  mode = 'breathe',
  blur = 'strong',
  transition,
  scale = 1,
  duration = 12,
}: GlowEffectProps) {
  const baseTransition = {
    repeat: Infinity,
    duration,
    ease: 'linear' as const,
  };

  const animations = {
    rotate: {
      background: [
        `conic-gradient(from 0deg at 50% 50%, ${colors.join(', ')})`,
        `conic-gradient(from 360deg at 50% 50%, ${colors.join(', ')})`,
      ],
      transition: {
        ...(transition ?? baseTransition),
      },
    },

    pulse: {
      background: colors.map(
        (color) =>
          `radial-gradient(circle at 50% 50%, ${color} 0%, transparent 100%)`,
      ),
      scale: [scale, scale * 1.08, scale],
      opacity: [0.18, 0.32, 0.18],
      transition: {
        ...(transition ?? {
          ...baseTransition,
          repeatType: 'mirror' as const,
        }),
      },
    },

    breathe: {
      background: colors.map(
        (color) =>
          `radial-gradient(circle at 50% 50%, ${color} 0%, transparent 100%)`,
      ),
      scale: [scale, scale * 1.05, scale],
      opacity: [0.16, 0.28, 0.16],
      transition: {
        ...(transition ?? {
          ...baseTransition,
          repeatType: 'mirror' as const,
        }),
      },
    },

    colorShift: {
      background: colors.map((color, index) => {
        const nextColor = colors[(index + 1) % colors.length];

        return `conic-gradient(
          from 0deg at 50% 50%,
          ${color} 0%,
          ${nextColor} 50%,
          ${color} 100%
        )`;
      }),
      transition: {
        ...(transition ?? {
          ...baseTransition,
          repeatType: 'mirror' as const,
        }),
      },
    },

    flowHorizontal: {
      background: colors.map((color, index) => {
        const nextColor = colors[(index + 1) % colors.length];

        return `linear-gradient(
          to right,
          ${color},
          ${nextColor}
        )`;
      }),
      transition: {
        ...(transition ?? {
          ...baseTransition,
          repeatType: 'mirror' as const,
        }),
      },
    },

    static: {
      background: `linear-gradient(to right, ${colors.join(', ')})`,
    },
  };

  const getBlurClass = (value: GlowEffectProps['blur']) => {
    if (typeof value === 'number') {
      return `blur-[${value}px]`;
    }

    const presets = {
      softest: 'blur-xs',
      soft: 'blur-sm',
      medium: 'blur-md',
      strong: 'blur-lg',
      stronger: 'blur-xl',
      strongest: 'blur-xl',
      none: 'blur-none',
    };

    return presets[value ?? 'strong'];
  };

  const activeMode = mode ?? 'breathe';

  return (
    <motion.div
      style={
        {
          ...style,
          '--scale': scale,
          willChange: 'transform',
          backfaceVisibility: 'hidden',
        } as CSSProperties
      }
      animate={animations[activeMode]}
      className={[
        'pointer-events-none absolute inset-0 h-full w-full',
        'scale-[var(--scale)] transform-gpu',
        getBlurClass(blur),
        className,
      ]
        .filter(Boolean)
        .join(' ')}
    />
  );
}
