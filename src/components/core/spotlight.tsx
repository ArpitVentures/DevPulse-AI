import { useCallback, useEffect, useRef, useState } from 'react';
import {
  motion,
  useSpring,
  useTransform,
  type SpringOptions,
} from 'framer-motion';

export type SpotlightProps = {
  className?: string;
  size?: number;
  springOptions?: SpringOptions;
};

export function Spotlight({
  className = '',
  size = 200,
  springOptions = {
    bounce: 0.15,
    duration: 0.2,
  },
}: SpotlightProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [isInside, setIsInside] = useState(false);

  const mouseX = useSpring(0, springOptions);
  const mouseY = useSpring(0, springOptions);

  const spotlightLeft = useTransform(mouseX, (x) => `${x - size / 2}px`);
  const spotlightTop = useTransform(mouseY, (y) => `${y - size / 2}px`);

  const handleMouseMove = useCallback(
    (event: MouseEvent) => {
      const element = containerRef.current;
      if (!element) return;

      const parent = element.parentElement;
      if (!parent) return;

      const rect = parent.getBoundingClientRect();

      const x = event.clientX - rect.left;
      const y = event.clientY - rect.top;

      const inside =
        event.clientX >= rect.left &&
        event.clientX <= rect.right &&
        event.clientY >= rect.top &&
        event.clientY <= rect.bottom;

      setIsInside(inside);

      if (inside) {
        mouseX.set(x);
        mouseY.set(y);
      }
    },
    [mouseX, mouseY],
  );

  useEffect(() => {
    window.addEventListener('mousemove', handleMouseMove);

    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
    };
  }, [handleMouseMove]);

  return (
    <motion.div
      ref={containerRef}
      className={`pointer-events-none absolute rounded-full blur-3xl ${className}`}
      style={{
        width: size,
        height: size,
        left: spotlightLeft,
        top: spotlightTop,
        background:
          'radial-gradient(circle at center, currentColor 0%, transparent 72%)',
        opacity: isInside ? 0.07 : 0,
        zIndex: 1,
      }}
      animate={{
        scale: isInside ? 1 : 0.8,
      }}
      transition={{
        duration: 0.4,
        ease: 'easeOut',
      }}
    />
  );
}
