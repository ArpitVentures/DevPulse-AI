import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import haikeiBackground from '../assets/low-poly-grid-haikei.svg';
import { GlowEffect } from './core/glow-effect';

type EngineStatus =
  | 'ENGINE READY'
  | 'ANALYZING REPOSITORY'
  | 'RESEARCHING SECURITY INTELLIGENCE'
  | 'GENERATING REPORT'
  | 'SCAN COMPLETE';

interface SecurityEnvironmentProps {
  active?: boolean;
  status?: EngineStatus;
}

const engineStages = [
  {
    label: 'REPOSITORY',
    meta: 'SOURCE INPUT',
    critical: false,
  },
  {
    label: 'STATIC ANALYSIS',
    meta: 'CODE INTELLIGENCE',
    critical: false,
  },
  {
    label: 'DEPENDENCY INTELLIGENCE',
    meta: 'PACKAGE AUDIT',
    critical: false,
  },
  {
    label: 'LIVE CVE RESEARCH',
    meta: 'TAVILY / SECURITY INTEL',
    critical: true,
  },
  {
    label: 'AI REMEDIATION',
    meta: 'NEMOTRON',
    critical: false,
  },
];

function SecurityEnvironment({
  active = false,
  status = 'ENGINE READY',
}: SecurityEnvironmentProps) {
  const targetStage =
    status === 'ENGINE READY'
      ? 0
      : status === 'ANALYZING REPOSITORY'
        ? 1
        : status === 'RESEARCHING SECURITY INTELLIGENCE'
          ? 3
          : status === 'GENERATING REPORT'
            ? 4
            : 5;

  const [displayedStage, setDisplayedStage] = useState(targetStage);

  useEffect(() => {
    if (displayedStage > targetStage) {
      setDisplayedStage(targetStage);
      return;
    }

    if (displayedStage < targetStage) {
      const timer = window.setTimeout(() => {
        setDisplayedStage((current) => Math.min(current + 1, targetStage));
      }, 900);

      return () => window.clearTimeout(timer);
    }
  }, [targetStage, displayedStage]);

  const activeStage = displayedStage;
  const visualActive = active || displayedStage < targetStage;

  return (
    <div
      className={`security-environment ${active ? 'active' : ''}`}
      aria-hidden="true"
    >
      {/* Haikei environment texture */}
      <img className="security-haikei" src={haikeiBackground} alt="" />

      <div className="environment-glow environment-glow-primary">
        <GlowEffect
          colors={['#B6FF2E']}
          mode="breathe"
          blur="strong"
          duration={14}
          scale={1}
        />
      </div>

      <div className="environment-glow environment-glow-threat">
        <GlowEffect
          colors={['#FF4696']}
          mode="breathe"
          blur="stronger"
          duration={18}
          scale={1}
        />
      </div>

      {/* Atmospheric grid */}
      <div className="security-grid" />

      <motion.div
        className="ambient-orb ambient-orb-one"
        animate={{
          x: [0, 45, -25, 0],
          y: [0, -30, 35, 0],
          scale: [1, 1.08, 0.94, 1],
          opacity: active ? [0.16, 0.24, 0.12, 0.16] : [0.1, 0.16, 0.08, 0.1],
        }}
        transition={{
          duration: active ? 10 : 20,
          repeat: Infinity,
          ease: 'easeInOut',
        }}
      />

      <motion.div
        className="ambient-orb ambient-orb-two"
        animate={{
          x: [0, -35, 25, 0],
          y: [0, 30, -20, 0],
          scale: [1, 0.94, 1.08, 1],
          opacity: active ? [0.08, 0.15, 0.06, 0.08] : [0.05, 0.1, 0.04, 0.05],
        }}
        transition={{
          duration: active ? 13 : 24,
          repeat: Infinity,
          ease: 'easeInOut',
        }}
      />

      {/* Vertical scan */}
      <motion.div
        className="scan-line"
        animate={{
          y: ['-120%', '220%'],
          opacity: active ? [0, 0.7, 0] : [0, 0.28, 0],
        }}
        transition={{
          duration: active ? 2.8 : 9,
          repeat: Infinity,
          ease: 'linear',
        }}
      />

      {/* Horizontal intelligence sweep */}
      <motion.div
        className="scan-sweep"
        animate={{
          x: ['-120%', '220%'],
          opacity: active ? [0, 0.35, 0] : [0, 0.12, 0],
        }}
        transition={{
          duration: active ? 4 : 12,
          repeat: Infinity,
          ease: 'linear',
          delay: 1.5,
        }}
      />

      {/* ─────────────────────────────────────────
          SECURITY ENGINE
      ───────────────────────────────────────── */}

      <div className="security-engine">
        <div className="security-engine-header">
          <div>
            <span className="security-engine-kicker">DEV-PULSE / CORE</span>
            <span className="security-engine-title">SECURITY ENGINE</span>
          </div>

          <motion.span
            className="security-engine-state"
            animate={{
              opacity: [0.45, 1, 0.45],
            }}
            transition={{
              duration: active ? 0.8 : 2.4,
              repeat: Infinity,
              ease: 'easeInOut',
            }}
          >
            <span className="security-engine-state-dot" />
            {active || displayedStage < targetStage ? 'PROCESSING' : 'STANDBY'}
          </motion.span>
        </div>

        <div className="security-engine-flow">
          {engineStages.map((stage, index) => (
            <div className="security-stage-wrapper" key={stage.label}>
              <motion.div
                className={`security-stage ${
                  stage.critical ? 'security-stage-critical' : ''
                } ${
                  index < activeStage
                    ? 'security-stage-complete'
                    : index === activeStage
                      ? 'security-stage-active'
                      : ''
                }`}
                animate={
                  visualActive
                    ? {
                        y: [0, -2, 0],
                      }
                    : undefined
                }

                transition={{
                  duration: 2.4,
                  delay: index * 0.28,
                  repeat: Infinity,
                  ease: 'easeInOut',
                }}
              >
                <div className="security-stage-indicator">
                  {index < activeStage ? (
                    <span className="security-stage-check">✓</span>
                  ) : (
                    <motion.span
                      animate={{
                        scale:
                          index === activeStage && visualActive
                            ? [1, 1.45, 1]
                            : [1, 1.1, 1],
                        opacity:
                          index === activeStage && visualActive
                            ? [0.5, 1, 0.5]
                            : [0.4, 0.7, 0.4],
                      }}
                      transition={{
                        duration: index === activeStage ? 1.1 : 2.6,
                        repeat: Infinity,
                        ease: 'easeInOut',
                      }}
                    />
                  )}
                </div>

                <div className="security-stage-copy">
                  <span className="security-stage-label">{stage.label}</span>
                  <span className="security-stage-meta">{stage.meta}</span>
                </div>

                <span className="security-stage-index">0{index + 1}</span>
              </motion.div>

              {index < engineStages.length - 1 && (
                <div className="security-stage-connector">
                  <motion.span
                    animate={{
                      y: active ? ['-20%', '120%'] : ['-20%', '80%'],
                      opacity: active ? [0, 1, 0] : [0, 0.35, 0],
                    }}
                    transition={{
                      duration: active ? 1.2 : 3.5,
                      delay: index * 0.35,
                      repeat: Infinity,
                      ease: 'linear',
                    }}
                  />
                </div>
              )}
            </div>
          ))}
        </div>

        {/* Bottom intelligence rail */}
        <div className="security-engine-footer">
          <span>ANALYSIS PIPELINE</span>
          <span className="security-engine-footer-line" />
          <span>
            {active ? 'LIVE SECURITY INTELLIGENCE' : 'AWAITING REPOSITORY'}
          </span>
        </div>
      </div>

      {/* ─────────────────────────────────────────
          HUD
      ───────────────────────────────────────── */}

      <div className="environment-telemetry">
        <motion.span
          animate={{
            opacity: [0.3, 1, 0.3],
          }}
          transition={{
            duration: active ? 0.9 : 2,
            repeat: Infinity,
            ease: 'easeInOut',
          }}
        >
          ●
        </motion.span>

        <span>
          {active ? 'SECURITY ENGINE ACTIVE' : 'SECURITY ENGINE ONLINE'}
        </span>
      </div>

      <div className="environment-corner environment-corner-tl" />
      <div className="environment-corner environment-corner-tr" />
      <div className="environment-corner environment-corner-bl" />
      <div className="environment-corner environment-corner-br" />

      <div className="environment-rail">
        <span>DEV-PULSE / CORE</span>

        <motion.span
          animate={{
            opacity: [0.35, 0.8, 0.35],
          }}
          transition={{
            duration: active ? 0.8 : 2.5,
            repeat: Infinity,
            ease: 'easeInOut',
          }}
        >
          {active ? 'PROCESSING' : 'STANDBY'}
        </motion.span>
      </div>
    </div>
  );
}

export default SecurityEnvironment;
