/**
 * Tenant Branding Loader
 *
 * Loads tenant-specific branding (theme CSS variables, logo, store name)
 * from TENANT_CONFIGS and CANONICAL_INPUTS KV namespaces.
 *
 * Used to render branded login/register pages that match each tenant's theme.
 *
 * Fallback: Aurora brand + first available style if tenant not found.
 */
import type { Env } from './types.js';

// ─── Types ──────────────────────────────────────────────────

export interface BrandTheme {
  id: string;
  type: 'brand';
  modes: {
    light: { colors: Record<string, string> };
    dark: { colors: Record<string, string> };
  };
  typography: {
    heading: string[];
    body: string[];
    mono: string[];
    baseSize?: number;
    headingWeight?: number;
    bodyWeight?: number;
  };
  icons?: { strokeWidth?: number };
}

export interface StyleTheme {
  id: string;
  type: 'style';
  label?: string;
  radius: { small: number; default: number; large: number };
  spacing?: { unit: number; rhythm?: string };
  elevation: { policy?: string; card: string; popover: string; focus: string };
  motion: { fast: number; base: number; slow: number; ease: string; emphasisEase: string };
  affordance?: { buttonVariant?: string; interactionFeedback?: string; focusPolicy?: string };
  controls: { height: number; buttonRadius: number };
  interaction?: {
    hover?: { transform?: string; opacity?: number };
    active?: { transform?: string; scale?: number };
    focusVisible?: { ringWidth?: number };
  };
  surface?: { opacity?: number; blur?: number; innerHighlight?: number };
  section?: { gap?: string };
  cssVariables?: {
    light?: Record<string, string>;
    dark?: Record<string, string>;
    reducedTransparency?: Record<string, string>;
  };
}

export interface TenantBranding {
  tenantId: string;
  storeName: string;
  logoUrl: string | null;
  cssVariables: string; // Inline <style> block content
  googleFontsLinks: string; // <link> tags for Google Fonts
}

// ─── Default Fallbacks ──────────────────────────────────────

const DEFAULT_BRAND_ID = 'brand-aurora';
const DEFAULT_STYLE_ID = 'style-material';

// ─── Main Loader ────────────────────────────────────────────

/**
 * Load tenant branding from KV.
 *
 * @param tenantId - Tenant identifier from query param
 * @param env - Worker environment bindings
 * @returns Resolved tenant branding with CSS variables
 */
export async function loadTenantBranding(
  tenantId: string | null,
  env: Env
): Promise<TenantBranding> {
  // 1. Load tenant config to get theme selections + store info
  let brandThemeId = DEFAULT_BRAND_ID;
  let styleThemeId = DEFAULT_STYLE_ID;
  let storeName = 'Store';
  let logoUrl: string | null = null;

  if (tenantId) {
    try {
      // KV key uses `tenant:{id}` prefix (aligned with runtime + D1→KV sync)
      const record = await env.TENANT_CONFIGS.get(`tenant:${tenantId}`, 'json') as Record<string, unknown> | null;
      // D1→KV sync stores TenantConfigRecord wrapper — extract inner config.
      // Fallback to record itself for legacy KV entries without a wrapper.
      const tenantConfig = (record?.config ?? record) as Record<string, unknown> | null;
      if (tenantConfig) {
        // Extract theme IDs from tenant config
        const rawBrand = typeof tenantConfig.brandThemeId === 'string' ? tenantConfig.brandThemeId : '';
        const rawStyle = typeof tenantConfig.styleThemeId === 'string' ? tenantConfig.styleThemeId : '';
        brandThemeId = rawBrand
          ? (rawBrand.startsWith('brand-') ? rawBrand : `brand-${rawBrand}`)
          : DEFAULT_BRAND_ID;
        styleThemeId = rawStyle
          ? (rawStyle.startsWith('style-') ? rawStyle : `style-${rawStyle}`)
          : DEFAULT_STYLE_ID;

        // Extract store info
        const site = tenantConfig.site as Record<string, unknown> | undefined;
        if (site) {
          if (typeof site.title === 'string') storeName = site.title;
          if (typeof site.logoUrl === 'string') logoUrl = site.logoUrl;
        }
        // Also check top-level name
        if (typeof tenantConfig.name === 'string') storeName = tenantConfig.name;
      }
    } catch (err) {
      console.error(`Failed to load tenant config for "${tenantId}":`, err);
      // Fall through to defaults
    }
  }

  // 2. Load brand and style themes from CANONICAL_INPUTS KV
  const [brandTheme, styleTheme] = await Promise.all([
    loadBrandTheme(brandThemeId, env),
    loadStyleTheme(styleThemeId, env),
  ]);

  // 3. Generate CSS variables
  const cssVariables = generateCssVariables(brandTheme, styleTheme);
  const googleFontsLinks = generateGoogleFontsLinks(brandTheme);

  return {
    tenantId: tenantId || '__default__',
    storeName,
    logoUrl,
    cssVariables,
    googleFontsLinks,
  };
}

// ─── KV Loaders ─────────────────────────────────────────────

async function loadBrandTheme(id: string, env: Env): Promise<BrandTheme> {
  try {
    const key = `brands:${id}`;
    const data = await env.CANONICAL_INPUTS.get(key, 'json') as BrandTheme | null;
    if (data) return data;
  } catch (err) {
    console.error(`Failed to load brand theme "${id}":`, err);
  }
  // Return hardcoded Aurora fallback
  return getAuroraFallback();
}

async function loadStyleTheme(id: string, env: Env): Promise<StyleTheme> {
  try {
    const key = `styles:${id}`;
    const data = await env.CANONICAL_INPUTS.get(key, 'json') as StyleTheme | null;
    if (data) return data;
  } catch (err) {
    console.error(`Failed to load style theme "${id}":`, err);
  }
  // Return hardcoded material fallback
  return getMaterialFallback();
}

// ─── CSS Generation ─────────────────────────────────────────

/**
 * Generate CSS custom properties from brand + style themes.
 * Matches the pattern in centerpiece-site-runtime/src/core/rendering/cssVariables.ts
 */
function generateCssVariables(brand: BrandTheme, style: StyleTheme): string {
  const lines: string[] = [];

  // ── Light mode + shared tokens ──
  lines.push(':root, [data-mode="light"] {');

  // Brand colors (light)
  if (brand.modes?.light?.colors) {
    for (const [key, value] of Object.entries(brand.modes.light.colors)) {
      lines.push(`  --${camelToKebab(key)}: ${value};`);
    }
  }

  // Typography
  if (brand.typography) {
    if (brand.typography.heading) {
      lines.push(`  --font-heading: ${brand.typography.heading.join(', ')};`);
    }
    if (brand.typography.body) {
      lines.push(`  --font-sans: ${brand.typography.body.join(', ')};`);
    }
    if (brand.typography.mono) {
      lines.push(`  --font-mono: ${brand.typography.mono.join(', ')};`);
    }
    if (brand.typography.headingWeight != null) {
      lines.push(`  --font-heading-weight: ${brand.typography.headingWeight};`);
    }
    if (brand.typography.bodyWeight != null) {
      lines.push(`  --font-body-weight: ${brand.typography.bodyWeight};`);
    }
  }

  // Style tokens
  if (style.radius) {
    lines.push(`  --radius-sm: ${style.radius.small}px;`);
    lines.push(`  --radius-md: ${style.radius.default}px;`);
    lines.push(`  --radius-lg: ${style.radius.large}px;`);
  }

  if (style.controls) {
    lines.push(`  --control-height: ${style.controls.height}px;`);
    lines.push(`  --button-radius: ${style.controls.buttonRadius}px;`);
  }

  if (style.elevation) {
    lines.push(`  --shadow-card: ${style.elevation.card};`);
    lines.push(`  --shadow-popover: ${style.elevation.popover};`);
    lines.push(`  --shadow-focus: ${style.elevation.focus};`);
  }

  if (style.motion) {
    lines.push(`  --motion-fast: ${style.motion.fast}ms;`);
    lines.push(`  --motion-base: ${style.motion.base}ms;`);
    lines.push(`  --motion-slow: ${style.motion.slow}ms;`);
    lines.push(`  --motion-ease: ${style.motion.ease};`);
    lines.push(`  --motion-emphasis: ${style.motion.emphasisEase};`);
  }

  if (style.spacing?.unit != null) {
    lines.push(`  --spacing-unit: ${style.spacing.unit}px;`);
  }

  if (style.interaction) {
    if (style.interaction.hover) {
      if (style.interaction.hover.transform) lines.push(`  --hover-transform: ${style.interaction.hover.transform};`);
      if (style.interaction.hover.opacity != null) lines.push(`  --hover-opacity: ${style.interaction.hover.opacity};`);
    }
    if (style.interaction.active) {
      if (style.interaction.active.transform) lines.push(`  --active-transform: ${style.interaction.active.transform};`);
      if (style.interaction.active.scale != null) lines.push(`  --active-scale: ${style.interaction.active.scale};`);
    }
    if (style.interaction.focusVisible?.ringWidth != null) {
      lines.push(`  --focus-ring-width: ${style.interaction.focusVisible.ringWidth}px;`);
    }
  }

  if (style.surface) {
    if (style.surface.opacity != null) lines.push(`  --surface-opacity: ${style.surface.opacity};`);
    if (style.surface.blur != null) lines.push(`  --surface-blur: ${style.surface.blur}px;`);
    if (style.surface.innerHighlight != null) lines.push(`  --surface-highlight: ${style.surface.innerHighlight};`);
  }

  if (style.section?.gap) {
    lines.push(`  --section-gap: ${style.section.gap};`);
  }

  // Style CSS variable overrides (light)
  if (style.cssVariables?.light) {
    for (const [key, value] of Object.entries(style.cssVariables.light)) {
      lines.push(`  ${key}: ${value};`);
    }
  }

  lines.push('}');

  // ── Dark mode overrides ──
  lines.push('[data-mode="dark"] {');

  if (brand.modes?.dark?.colors) {
    for (const [key, value] of Object.entries(brand.modes.dark.colors)) {
      lines.push(`  --${camelToKebab(key)}: ${value};`);
    }
  }

  // Style CSS variable overrides (dark)
  if (style.cssVariables?.dark) {
    for (const [key, value] of Object.entries(style.cssVariables.dark)) {
      lines.push(`  ${key}: ${value};`);
    }
  }

  lines.push('}');

  // ── Reduced transparency ──
  if (style.cssVariables?.reducedTransparency && Object.keys(style.cssVariables.reducedTransparency).length > 0) {
    lines.push('@media (prefers-reduced-transparency) {');
    lines.push('  :root {');
    for (const [key, value] of Object.entries(style.cssVariables.reducedTransparency)) {
      lines.push(`    ${key}: ${value};`);
    }
    lines.push('  }');
    lines.push('}');
  }

  return lines.join('\n');
}

/**
 * Generate Google Fonts <link> tags for the brand's typography.
 */
function generateGoogleFontsLinks(brand: BrandTheme): string {
  const fontFamilies = new Set<string>();

  const extractFontNames = (fonts: string[]) => {
    for (const font of fonts) {
      // Strip quotes, skip system fonts
      const name = font.replace(/['"]/g, '').trim();
      if (
        name &&
        !name.startsWith('system-') &&
        !name.startsWith('-apple-') &&
        name !== 'BlinkMacSystemFont' &&
        !name.includes('monospace') &&
        !name.includes('sans-serif') &&
        !name.includes('serif') &&
        !name.startsWith('ui-')
      ) {
        fontFamilies.add(name);
      }
    }
  };

  if (brand.typography?.heading) extractFontNames(brand.typography.heading);
  if (brand.typography?.body) extractFontNames(brand.typography.body);
  if (brand.typography?.mono) extractFontNames(brand.typography.mono);

  if (fontFamilies.size === 0) return '';

  const families = Array.from(fontFamilies)
    .map((name) => `family=${name.replace(/\s+/g, '+')}:wght@300;400;500;600;700`)
    .join('&');

  return `<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?${families}&display=swap" rel="stylesheet">`;
}

// ─── Utilities ──────────────────────────────────────────────

/** Convert camelCase to kebab-case (e.g., primaryForeground → primary-foreground). */
function camelToKebab(str: string): string {
  return str.replace(/[A-Z]/g, (letter) => `-${letter.toLowerCase()}`);
}

// ─── Hardcoded Fallbacks ────────────────────────────────────

function getAuroraFallback(): BrandTheme {
  return {
    id: 'brand-aurora',
    type: 'brand',
    modes: {
      light: {
        colors: {
          primary: '221 83% 53%',
          primaryForeground: '0 0% 100%',
          secondary: '217 33% 90%',
          secondaryForeground: '222 47% 11%',
          accent: '160 84% 39%',
          accentForeground: '0 0% 100%',
          destructive: '0 84% 60%',
          destructiveForeground: '0 0% 100%',
          success: '142 72% 29%',
          successForeground: '0 0% 100%',
          warning: '38 92% 50%',
          warningForeground: '0 0% 0%',
          info: '201 96% 32%',
          infoForeground: '0 0% 100%',
          background: '210 20% 98%',
          foreground: '222 47% 11%',
          muted: '220 14% 96%',
          mutedForeground: '221 15% 38%',
          border: '218 15% 85%',
          ring: '221 83% 53%',
        },
      },
      dark: {
        colors: {
          primary: '217 91% 60%',
          primaryForeground: '222 47% 11%',
          secondary: '222 14% 25%',
          secondaryForeground: '210 20% 98%',
          accent: '160 84% 39%',
          accentForeground: '0 0% 0%',
          destructive: '0 72% 51%',
          destructiveForeground: '0 0% 100%',
          success: '142 72% 45%',
          successForeground: '0 0% 0%',
          warning: '38 92% 60%',
          warningForeground: '0 0% 0%',
          info: '201 96% 45%',
          infoForeground: '0 0% 0%',
          background: '222 47% 11%',
          foreground: '210 20% 98%',
          muted: '222 14% 25%',
          mutedForeground: '215 20% 80%',
          border: '217 15% 35%',
          ring: '217 91% 60%',
        },
      },
    },
    typography: {
      heading: ["'Cal Sans'", "'Poppins'", "'Inter'", 'system-ui', 'sans-serif'],
      body: ["'Inter'", "'Source Sans 3'", 'system-ui', '-apple-system', 'BlinkMacSystemFont', 'sans-serif'],
      mono: ["'IBM Plex Mono'", "'Fira Code'", "'JetBrains Mono'", 'ui-monospace', 'SFMono-Regular', 'monospace'],
      baseSize: 16,
      headingWeight: 600,
      bodyWeight: 400,
    },
  };
}

function getMaterialFallback(): StyleTheme {
  return {
    id: 'style-material',
    type: 'style',
    label: 'Material',
    radius: { small: 4, default: 8, large: 16 },
    spacing: { unit: 4 },
    elevation: {
      card: '0 2px 4px -1px rgba(0,0,0,0.06), 0 4px 6px -1px rgba(0,0,0,0.1)',
      popover: '0 10px 15px -3px rgba(0,0,0,0.1), 0 4px 6px -2px rgba(0,0,0,0.05)',
      focus: '0 0 0 3px rgba(66, 133, 244, 0.3)',
    },
    motion: {
      fast: 150,
      base: 250,
      slow: 500,
      ease: 'cubic-bezier(0.4, 0, 0.2, 1)',
      emphasisEase: 'cubic-bezier(0, 0, 0.2, 1)',
    },
    controls: { height: 40, buttonRadius: 8 },
  };
}
