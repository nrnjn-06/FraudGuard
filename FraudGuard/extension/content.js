/**
 * FraudGuard: Browser-Based Deceptive UI and E-Commerce Fraud Detection System
 * Advanced Deceptive UI Detection (Urgency, Scarcity, Social Proof, Countdown, Recurring Payment)
 * 
 * Architecture Notes:
 * - Operates entirely client-side without interfering with website functionality.
 * - Inspects visible DOM elements for deceptive UI text patterns and pre-selected recurring payment controls.
 * - Identifies the smallest (deepest) DOM element containing the suspicious message.
 * - Non-destructively highlights elements and provides an educational warning badge/tooltip.
 * - Structured to provide DOM signals cleanly for UI Safety & Store Trust scoring engines.
 */

(function () {
  'use strict';

  // Prevent multiple injections of content script
  if (window.__FRAUDGUARD_INITIALIZED__) {
    return;
  }
  window.__FRAUDGUARD_INITIALIZED__ = true;

  // Initial startup announcement
  console.log('[FraudGuard] Extension loaded');

  /* ==========================================================================
     1. DETECTION CONFIGURATION & REGULAR EXPRESSIONS
     ========================================================================== */

  // Countdown timer patterns (HH:MM:SS, MM:SS, interval representation, countdown keywords)
  const COUNTDOWN_REGEX = /\b(?:(?:sale|offer|deal|discount|promo(?:tion)?|flash\s*sale|lightning\s*deal|hurry|order\s+within|countdown)\b[^.\n\r]*?\b(?:ends?|expires?|closing|left|remaining)?\s*[:\-]?\s*(?:(?:\d{1,2}:)?(?:[0-5]?\d):(?:[0-5]\d)|\d{1,2}\s*h(?:rs?|ours?)?\s*\d{1,2}\s*m(?:ins?|inutes?)?(?:\s*\d{1,2}\s*s(?:ecs?|econds?)?)?|\d{1,2}\s*m(?:ins?|inutes?)?\s*\d{1,2}\s*s(?:ecs?|econds?)?|\d+\s*(?:minutes?|mins?|seconds?|secs?)\s*(?:left|remaining))|(?:ends?|expires?|closing)\s+in\s*[:\-]?\s*(?:(?:\d{1,2}:)?(?:[0-5]?\d):(?:[0-5]\d)|\d{1,2}\s*h(?:rs?|ours?)?\s*\d{1,2}\s*m(?:ins?|inutes?)?(?:\s*\d{1,2}\s*s(?:ecs?|econds?)?)?|\d{1,2}\s*m(?:ins?|inutes?)?\s*\d{1,2}\s*s(?:ecs?|econds?)?|\d+\s*(?:hours?|hrs?|minutes?|mins?|seconds?|secs?))|only\s+\d+\s*(?:minutes?|mins?|seconds?|secs?|hours?)\s*(?:left|remaining)|time\s+(?:remaining|left)\s*[:\-]?\s*(?:(?:\d{1,2}:)?(?:[0-5]?\d):(?:[0-5]\d)|\d{1,2}\s*h|\d{1,2}\s*m))\b/i;

  // Patterns to explicitly reject (timestamps, store hours, general delivery windows)
  const FALSE_TIME_REGEX = /\b(?:\d{1,2}:\d{2}\s*(?:am|pm|a\.m\.|p\.m\.)|\d{1,2}\s*(?:am|pm)\s*-\s*\d{1,2}\s*(?:am|pm)|store\s+hours|customer\s+support|available\s+\d+\s+hours|delivery\s+(?:in|by|on)\s+\d+\s+days?|estimated\s+delivery|delivered\s+within)\b/i;

  const DETECTION_RULES = [
    {
      category: 'COUNTDOWN',
      severity: 'medium',
      title: 'Potential Countdown Signal',
      explanation: 'FraudGuard detected a countdown or time-pressure element that may encourage immediate action.',
      notice: 'A countdown does not necessarily indicate fraud. It is treated as a potential deceptive UI signal and will later be combined with other signals.',
      regex: COUNTDOWN_REGEX,
      validate: (text) => !FALSE_TIME_REGEX.test(text)
    },
    {
      category: 'SCARCITY',
      severity: 'low',
      title: 'Potential Scarcity Signal',
      explanation: 'FraudGuard detected language suggesting limited availability or depleting inventory.',
      notice: 'Persuasive language does not necessarily indicate a fraudulent website. Store legitimacy and deceptive UI are evaluated as separate risk factors.',
      regex: /\b(?:only\s+(\d+|one|two|three|four|five|few)\s+(?:item[s]?\s+|piece[s]?\s+)?(?:left|remaining)(?:\s+in\s+stock)?|only\s+a\s+few\s+left(?:\s+in\s+stock)?|limited\s+(?:stock|quantity|inventory|availability|quantities)|selling\s+fast|almost\s+gone|few\s+items\s+left|few\s+left\s+in\s+stock|low\s+stock|running\s+out\s+fast|in\s+high\s+demand|back\s+in\s+stock\s+soon)\b/i
    },
    {
      category: 'URGENCY',
      severity: 'low',
      title: 'Potential Urgency Signal',
      explanation: 'FraudGuard detected language encouraging immediate action through artificial or perceived time pressure.',
      notice: 'Persuasive language does not necessarily indicate a fraudulent website. Store legitimacy and deceptive UI are evaluated as separate risk factors.',
      regex: /\b(?:hurry(?:\s+up)?|act\s+now|last\s+chance|limited\s+time(?:\s+only|\s+offer|\s+deal)?|offer\s+ends(?:\s+soon|\s+in\s+[\w\s:]+)?|deal\s+ends(?:\s+soon|\s+in\s+[\w\s:]+)?|sale\s+ends(?:\s+soon|\s+in\s+[\w\s:]+)?|don'?t\s+miss\s+out|buy\s+now\s+before\s+it'?s\s+too\s+late|ending\s+soon|ends\s+in\s+\d+|clock\s+is\s+ticking|time\s+is\s+running\s+out|flash\s+sale|lightning\s+deal|deal\s+of\s+the\s+day|expires\s+(?:soon|in\s+\d+)|order\s+within\s+[\w\s:]+)\b/i
    },
    {
      category: 'SOCIAL_PROOF',
      severity: 'low',
      title: 'Potential Social-Proof Manipulation',
      explanation: 'FraudGuard detected messaging highlighting peer activity to create herd pressure or validate purchase intent.',
      notice: 'Persuasive language does not necessarily indicate a fraudulent website. Store legitimacy and deceptive UI are evaluated as separate risk factors.',
      regex: /\b(?:\d+\s+(?:people|shoppers|customers|users)?\s*(?:are\s+)?viewing(?:\s+this(?:\s+product|\s+item|\s+page)?)?|\d+\s+people\s+viewing|\d+\s+(?:people|shoppers|customers|users)?\s*bought\s+this(?:\s+today|\s+in\s+the\s+last\s+\d+\s+hours?|\s+recently)?|over\s+\d+\+?\s+bought\s+in\s+(?:past|the\s+last)\s+(?:month|week|day)|\d+\s+(?:people|others|shoppers)\s+have\s+this\s+in\s+their\s+cart[s]?|in\s+\d+\s+people'?s\s+cart[s]?|trending\s+now|popular\s+right\s+now|popular\s+pick|high\s+demand\s+item)\b/i
    }
  ];

  // Configuration for Pre-selected Recurring Payment detection
  const RECURRING_PAYMENT_CONFIG = {
    category: 'RECURRING_PAYMENT',
    severity: 'high',
    title: 'Potential Pre-selected Recurring Charge',
    explanation: 'FraudGuard detected a pre-selected option that may add a recurring charge or subscription. Review the selection before continuing.',
    notice: 'A pre-selected subscription does not automatically mean the website is fraudulent. It is treated as a potential deceptive UI signal.',
    recurringTermsRegex: /\b(?:monthly|per\s+month|\/\s*month|\/\s*mo\b|yearly|per\s+year|\/\s*year|\/\s*yr\b|annual|annually|subscription|subscribe|membership|recurring|renewal|auto-renew|automatically\s+renew|renews\s+automatically)\b/i,
    paymentContextRegex: /(?:[₹$€£]\s*\d+(?:\.\d{2})?|\d+\s*(?:inr|usd|eur|gbp|bucks)|add\s+(?:protection|premium|warranty|membership)|protection\s+plan|extended\s+warranty|premium\s+(?:membership|plan)|annual\s+membership|subscription\s+fee|\/\s*(?:month|mo|year|yr))/i,
    benignRegex: /^(?:remember\s+me|i\s+agree|terms|save\s+this|keep\s+me\s+signed\s+in|use\s+this\s+address|save\s+card|default\s+payment|newsletter|send\s+me\s+updates|marketing)/i
  };

  // DOM Selectors to scan for text-based patterns
  const CANDIDATE_SELECTOR = 'p, span, div, label, button, li, strong, b, em, small, a, td, th, h1, h2, h3, h4, h5, h6';

  // Elements and subtrees to strictly ignore for safety and performance
  const IGNORED_TAG_NAMES = new Set([
    'SCRIPT', 'STYLE', 'NOSCRIPT', 'TEMPLATE', 'IFRAME', 'OBJECT',
    'EMBED', 'SVG', 'CANVAS', 'VIDEO', 'AUDIO', 'HEAD', 'META', 'LINK'
  ]);

  // Sensitive form elements to strictly avoid reading or interacting with
  // Note: checkboxes and radio buttons are permitted for subscription inspection,
  // but passwords, credit card inputs, CVV, and general text entries remain strictly ignored.
  const SENSITIVE_SELECTOR = 'input:not([type="checkbox"]):not([type="radio"]), textarea, select, [contenteditable="true"], [type="password"], [autocomplete*="cc-"], [autocomplete*="card"], [autocomplete*="cvv"]';

  // In-memory catalog of detections for extensible scoring engine access
  window.__FRAUDGUARD_STATE__ = {
    detections: [],
    processedElements: new WeakSet(),
    domainIntelligence: null,
    scores: null,
    scoreStatus: 'idle',
    riskAssessment: null,
    riskStatus: 'idle',
    isPanelOpen: false
  };

  // Flag to avoid infinite mutation loops triggered by FraudGuard's own DOM modifications
  let isFraudGuardMutating = false;

  /* ==========================================================================
     2. FLOATING TOOLTIP PORTAL (Non-destructive, never clipped by overflow:hidden)
     ========================================================================== */

  let tooltipPortal = null;
  let hideTooltipTimeout = null;
  let activeTooltipTarget = null;
  let activeTooltipDetection = null;

  function initTooltipPortal() {
    if (document.getElementById('fraudguard-tooltip-portal')) {
      tooltipPortal = document.getElementById('fraudguard-tooltip-portal');
      return;
    }

    tooltipPortal = document.createElement('div');
    tooltipPortal.id = 'fraudguard-tooltip-portal';
    tooltipPortal.className = 'fraudguard-tooltip fraudguard-tooltip-hidden';
    tooltipPortal.setAttribute('data-fraudguard-ignore', 'true');
    tooltipPortal.setAttribute('role', 'dialog');
    tooltipPortal.setAttribute('aria-live', 'polite');

    // Prevent closing when mouse moves into the tooltip itself
    tooltipPortal.addEventListener('mouseenter', () => {
      if (hideTooltipTimeout) {
        clearTimeout(hideTooltipTimeout);
        hideTooltipTimeout = null;
      }
    });

    tooltipPortal.addEventListener('mouseleave', () => {
      scheduleHideTooltip();
    });

    isFraudGuardMutating = true;
    document.body.appendChild(tooltipPortal);
    isFraudGuardMutating = false;
  }

  function showTooltip(targetElement, detection) {
    if (!tooltipPortal) initTooltipPortal();
    if (hideTooltipTimeout) {
      clearTimeout(hideTooltipTimeout);
      hideTooltipTimeout = null;
    }

    activeTooltipTarget = targetElement;
    activeTooltipDetection = detection;

    // Build educational, neutral explanation HTML
    const categoryTitle = detection.title || 'Potential Persuasive Signal';
    const categoryKey = detection.category.toUpperCase().replace('-', '_');
    const notice = detection.notice || 'Persuasive language does not necessarily indicate a fraudulent website. Store legitimacy and deceptive UI are evaluated as separate risk factors.';
    const severityKey = (detection.severity || 'low').toUpperCase();

    let severityEmoji = '🟢';
    if (severityKey === 'MEDIUM') {
      severityEmoji = '🟡';
    } else if (severityKey === 'HIGH') {
      severityEmoji = '🔴';
    }

    // Machine learning text classification status pill
    let mlPillHtml = '';
    if (detection.mlStatus === 'success' && detection.mlPrediction) {
      const isDark = detection.mlPrediction === 'DARK_PATTERN';
      const labelText = isDark ? 'Dark Pattern' : 'Not Dark Pattern';
      const pct = Math.round((detection.mlConfidence || 0) * 100);
      const pillClass = isDark ? 'fraudguard-pill-ml-dark' : 'fraudguard-pill-ml-benign';
      mlPillHtml = `<span class="fraudguard-badge-pill fraudguard-pill-ml ${pillClass}">🤖 ML: ${labelText} (${pct}%)</span>`;
    } else if (detection.mlStatus === 'pending') {
      mlPillHtml = `<span class="fraudguard-badge-pill fraudguard-pill-ml">🤖 ML: Analyzing...</span>`;
    }

    // Apply severity color theme to the tooltip popover
    tooltipPortal.classList.remove('fraudguard-severity-low', 'fraudguard-severity-medium', 'fraudguard-severity-high');
    tooltipPortal.classList.add(`fraudguard-severity-${severityKey.toLowerCase()}`);

    tooltipPortal.innerHTML = `
      <div class="fraudguard-tooltip-header">
        <span class="fraudguard-tooltip-icon">⚠️</span>
        <span class="fraudguard-tooltip-title">${escapeHtml(categoryTitle)}</span>
      </div>
      <div class="fraudguard-tooltip-body">
        <div class="fraudguard-tooltip-section-label">Detected message:</div>
        <div class="fraudguard-tooltip-quote">"${escapeHtml(detection.message)}"</div>
        <p class="fraudguard-tooltip-explanation">${escapeHtml(detection.explanation)}</p>
      </div>
      <div class="fraudguard-tooltip-meta">
        <span class="fraudguard-badge-pill fraudguard-pill-category">Category: ${escapeHtml(categoryKey)}</span>
        <span class="fraudguard-badge-pill fraudguard-pill-severity">${severityEmoji} Severity: ${escapeHtml(severityKey)}</span>
        ${mlPillHtml}
      </div>
      <div class="fraudguard-tooltip-notice">
        <strong>Notice:</strong> ${escapeHtml(notice)}
      </div>
    `;

    // Position dynamically relative to target element / badge
    positionTooltip(targetElement);

    tooltipPortal.classList.remove('fraudguard-tooltip-hidden');
    tooltipPortal.classList.add('fraudguard-tooltip-visible');
  }

  function positionTooltip(targetElement) {
    if (!tooltipPortal || !targetElement) return;

    const targetRect = targetElement.getBoundingClientRect();
    const tooltipWidth = 320; // Matches CSS max-width
    const padding = 12;

    // Default: position above target
    let top = targetRect.top - tooltipPortal.offsetHeight - 10;
    // If not enough room at top of viewport, flip to below target
    if (top < padding) {
      top = targetRect.bottom + 10;
    }

    // Center horizontally relative to target
    let left = targetRect.left + (targetRect.width / 2) - (tooltipWidth / 2);

    // Keep within viewport boundaries
    if (left < padding) {
      left = padding;
    } else if (left + tooltipWidth > window.innerWidth - padding) {
      left = window.innerWidth - tooltipWidth - padding;
    }

    tooltipPortal.style.top = `${Math.round(top)}px`;
    tooltipPortal.style.left = `${Math.round(left)}px`;
  }

  function scheduleHideTooltip() {
    if (hideTooltipTimeout) clearTimeout(hideTooltipTimeout);
    hideTooltipTimeout = setTimeout(() => {
      if (tooltipPortal) {
        tooltipPortal.classList.remove('fraudguard-tooltip-visible');
        tooltipPortal.classList.add('fraudguard-tooltip-hidden');
      }
    }, 200);
  }

  /* ==========================================================================
     3. DOM UTILITIES & FILTERING
     ========================================================================== */

  /**
   * Checks if an element is currently visible in the DOM
   */
  function isElementVisible(el) {
    if (!el || el.nodeType !== Node.ELEMENT_NODE) return false;

    // Check basic dimensions
    const rect = el.getBoundingClientRect();
    if (rect.width === 0 && rect.height === 0) return false;

    // Check computed styles
    const style = window.getComputedStyle(el);
    if (style.display === 'none' || style.visibility === 'hidden' || parseFloat(style.opacity) === 0) {
      return false;
    }

    // Verify offsetParent (valid unless element is fixed/sticky)
    if (el.offsetParent === null && style.position !== 'fixed' && style.position !== 'sticky') {
      return false;
    }

    return true;
  }

  /**
   * Sanitizes text to escape HTML entities
   */
  function escapeHtml(str) {
    if (!str) return '';
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  /**
   * Determines if the element is inside a sensitive or ignored context
   */
  function isIgnoredOrSensitive(el) {
    if (!el || el.nodeType !== Node.ELEMENT_NODE) return true;

    if (IGNORED_TAG_NAMES.has(el.tagName)) return true;

    // Ignore FraudGuard injected UI
    if (el.hasAttribute('data-fraudguard-ignore') || el.closest('[data-fraudguard-ignore="true"]')) {
      return true;
    }

    // Never inspect text inputs, passwords, or credit card fields
    if (el.matches && el.matches(SENSITIVE_SELECTOR)) return true;
    if (el.closest && el.closest(SENSITIVE_SELECTOR)) return true;

    return false;
  }

  /**
   * Extracts the concise detected message or sentence containing the match
   */
  function extractExactMessage(fullText, regex) {
    const trimmed = (fullText || '').trim();
    if (!trimmed) return '';

    // If the element's entire text is concise (under 120 chars), use it directly
    if (trimmed.length <= 120) {
      return trimmed;
    }

    // Otherwise, isolate the sentence or clause containing the pattern
    const match = trimmed.match(regex);
    if (!match) return trimmed.slice(0, 120);

    const matchIndex = match.index;
    const matchLength = match[0].length;

    // Expand to punctuation boundaries around the match
    const start = Math.max(0, trimmed.lastIndexOf('.', matchIndex) + 1);
    let end = trimmed.indexOf('.', matchIndex + matchLength);
    if (end === -1) end = trimmed.length;

    const sentence = trimmed.slice(start, end).trim();
    return sentence.length > 0 ? sentence : match[0];
  }

  /**
   * Identifies the SMALLEST / DEEPEST useful DOM element containing the message.
   * If a candidate child inside element also matches the rule regex, this element
   * is an ancestor container and should NOT be highlighted.
   */
  function isDeepestMatchingElement(element, rule) {
    const children = element.querySelectorAll(CANDIDATE_SELECTOR);
    for (let i = 0; i < children.length; i++) {
      const child = children[i];
      if (isIgnoredOrSensitive(child)) continue;

      const childText = (child.textContent || '').trim();
      if (childText.length > 0 && rule.regex.test(childText)) {
        if (typeof rule.validate !== 'function' || rule.validate(childText)) {
          // A child also contains the match, so current element is not the deepest
          return false;
        }
      }
    }
    return true;
  }

  /* ==========================================================================
     4. DETECTION & UI HIGHLIGHTING ENGINE
     ========================================================================== */

  /**
   * Inspects a single candidate element against all text detection rules
   */
  function inspectElement(element) {
    if (!element || element.nodeType !== Node.ELEMENT_NODE) return;

    // Check if already processed
    if (element.hasAttribute('data-fraudguard-processed') || window.__FRAUDGUARD_STATE__.processedElements.has(element)) {
      return;
    }

    // Skip ignored or sensitive elements
    if (isIgnoredOrSensitive(element)) return;

    // Fast textContent preliminary check (avoids layout thrashing)
    const textContent = (element.textContent || '').trim();
    if (!textContent || textContent.length === 0 || textContent.length > 400) {
      return;
    }

    // Check rules
    for (let i = 0; i < DETECTION_RULES.length; i++) {
      const rule = DETECTION_RULES[i];

      if (rule.regex.test(textContent)) {
        // Run rule-specific validator if defined (e.g. countdown rejecting clock timestamps)
        if (typeof rule.validate === 'function' && !rule.validate(textContent)) {
          continue;
        }

        // Element matches regex. Now verify if it's visible in the rendered DOM
        if (!isElementVisible(element)) {
          return;
        }

        // Verify this is the SMALLEST / DEEPEST DOM element containing the message
        if (!isDeepestMatchingElement(element, rule)) {
          return;
        }

        // Check innerText to ensure text is truly rendered
        const innerText = (element.innerText || textContent).trim();
        if (!rule.regex.test(innerText)) {
          return;
        }
        if (typeof rule.validate === 'function' && !rule.validate(innerText)) {
          return;
        }

        // Mark as processed
        element.setAttribute('data-fraudguard-processed', 'true');
        window.__FRAUDGUARD_STATE__.processedElements.add(element);

        // Construct standard detection data structure
        const exactMessage = extractExactMessage(innerText, rule.regex);
        const detection = {
          category: rule.category,
          severity: rule.severity,
          message: exactMessage,
          title: rule.title,
          explanation: rule.explanation,
          notice: rule.notice,
          element: element,
          timestamp: new Date().toISOString(),
          mlPrediction: null,
          mlConfidence: null,
          mlDarkPatternProb: null,
          mlStatus: 'pending'
        };

        // Store detection
        window.__FRAUDGUARD_STATE__.detections.push(detection);
        updateGlobalWidget();

        // Log detection formatted exactly as requested
        logDetection(detection);

        // Apply visual highlight and warning indicator
        applyVisualHighlight(element, detection);

        // Request machine learning text classification
        requestMlAnalysis(detection);

        // Stop checking other rules for this element
        break;
      }
    }
  }

  /**
   * Inspects a checked checkbox or custom toggle control for pre-selected recurring charge patterns
   */
  function inspectSelectedCheckbox(control) {
    if (!control || control.nodeType !== Node.ELEMENT_NODE) return;
    if (control.hasAttribute('data-fraudguard-processed') || window.__FRAUDGUARD_STATE__.processedElements.has(control)) {
      return;
    }

    // Verify control is actually selected
    const isChecked = control.checked === true ||
      control.getAttribute('aria-checked') === 'true' ||
      control.classList.contains('checked') ||
      control.getAttribute('data-checked') === 'true';

    if (!isChecked) return;

    // Find the associated option container or label
    let targetElement = null;
    let fullText = '';

    // Strategy 1: Checkbox is inside an enclosing <label>
    const parentLabel = control.closest('label');
    if (parentLabel) {
      targetElement = parentLabel;
      fullText = (parentLabel.innerText || parentLabel.textContent || '').trim();
    }

    // Strategy 2: Explicit <label for="id">
    if (!targetElement && control.id) {
      try {
        const idLabel = document.querySelector(`label[for="${CSS.escape(control.id)}"]`);
        if (idLabel) {
          targetElement = idLabel;
          fullText = (idLabel.innerText || idLabel.textContent || '').trim();
        }
      } catch (e) {
        // In case of unusual ID selector
      }
    }

    // Strategy 3: Nearest semantic option wrapper (.checkbox, .form-check, li, etc.)
    if (!targetElement) {
      const wrapper = control.closest('.checkbox, .form-check, .form-group, .option, .addon, .plan, .item, li');
      if (wrapper) {
        const wText = (wrapper.innerText || wrapper.textContent || '').trim();
        if (wText.length > 0 && wText.length < 350) {
          targetElement = wrapper;
          fullText = wText;
        }
      }
    }

    // Strategy 4: Direct sibling container or parent
    if (!targetElement) {
      if (control.nextElementSibling && (control.nextElementSibling.innerText || '').trim().length > 0) {
        targetElement = control.nextElementSibling;
        fullText = targetElement.innerText.trim();
      } else if (control.parentElement && (control.parentElement.innerText || '').trim().length < 300) {
        targetElement = control.parentElement;
        fullText = control.parentElement.innerText.trim();
      }
    }

    if (!targetElement || !fullText || fullText.length === 0) return;

    // Ensure element is visible
    if (!isElementVisible(targetElement) && !isElementVisible(control)) return;

    // Filter out standard benign checkboxes (Remember me, Terms, Save address, etc.)
    if (RECURRING_PAYMENT_CONFIG.benignRegex.test(fullText)) {
      return;
    }

    // Must satisfy both: Recurring Payment Term AND Payment/Add-on Context
    const hasRecurring = RECURRING_PAYMENT_CONFIG.recurringTermsRegex.test(fullText);
    const hasPayment = RECURRING_PAYMENT_CONFIG.paymentContextRegex.test(fullText);

    if (hasRecurring && hasPayment) {
      // Mark as processed
      control.setAttribute('data-fraudguard-processed', 'true');
      targetElement.setAttribute('data-fraudguard-processed', 'true');
      window.__FRAUDGUARD_STATE__.processedElements.add(control);
      window.__FRAUDGUARD_STATE__.processedElements.add(targetElement);

      const exactMessage = extractExactMessage(fullText, RECURRING_PAYMENT_CONFIG.recurringTermsRegex);

      const detection = {
        category: RECURRING_PAYMENT_CONFIG.category,
        severity: RECURRING_PAYMENT_CONFIG.severity,
        message: exactMessage,
        title: RECURRING_PAYMENT_CONFIG.title,
        explanation: RECURRING_PAYMENT_CONFIG.explanation,
        notice: RECURRING_PAYMENT_CONFIG.notice,
        element: targetElement,
        timestamp: new Date().toISOString(),
        mlPrediction: null,
        mlConfidence: null,
        mlDarkPatternProb: null,
        mlStatus: 'pending'
      };

      window.__FRAUDGUARD_STATE__.detections.push(detection);
      updateGlobalWidget();
      logDetection(detection);
      applyVisualHighlight(targetElement, detection);
      requestMlAnalysis(detection);
    }
  }

  /**
   * Scans a root container for pre-selected checkboxes
   */
  function scanCheckboxes(root) {
    if (!root || isIgnoredOrSensitive(root)) return;

    // If root itself is a selected checkbox
    if (root.matches && (root.matches('input[type="checkbox"]:checked') || root.matches('[role="checkbox"][aria-checked="true"]'))) {
      inspectSelectedCheckbox(root);
    }

    // Query all checked checkboxes in container
    if (root.querySelectorAll) {
      const selectedControls = root.querySelectorAll('input[type="checkbox"]:checked, [role="checkbox"][aria-checked="true"], input[type="radio"]:checked');
      for (let i = 0; i < selectedControls.length; i++) {
        inspectSelectedCheckbox(selectedControls[i]);
      }
    }
  }

  /**
   * Logs detection details to DevTools console
   */
  function logDetection(detection) {
    const formattedCat = detection.category.toUpperCase().replace('-', '_');
    console.log(
      `[FraudGuard] Detection\nCategory: ${formattedCat}\nMessage: "${detection.message}"\nSeverity: ${detection.severity.toUpperCase()}`
    );
  }

  /**
   * Applies non-destructive visual highlight and attaches warning indicator
   */
  function applyVisualHighlight(element, detection) {
    // 1. Add warning highlight class to the detected element
    element.classList.add('fraudguard-warning');
    element.setAttribute('data-fraudguard-category', detection.category);

    // 2. Create small, non-intrusive warning icon (⚠)
    const iconBadge = document.createElement('span');
    const badgeCategoryClass = detection.category.toLowerCase().replace('_', '-');
    const severityClass = (detection.severity || 'low').toLowerCase();

    iconBadge.className = `fraudguard-icon-badge fraudguard-icon-${badgeCategoryClass} fraudguard-icon-severity-${severityClass}`;
    iconBadge.setAttribute('data-fraudguard-ignore', 'true');
    iconBadge.setAttribute('role', 'button');
    iconBadge.setAttribute('tabindex', '0');
    iconBadge.setAttribute('aria-label', `FraudGuard warning: ${detection.title || 'Potential manipulative signal'}`);
    iconBadge.textContent = '⚠';

    // 3. Attach tooltip hover & focus interactions
    const handleEnter = () => showTooltip(iconBadge, detection);
    const handleLeave = () => scheduleHideTooltip();

    iconBadge.addEventListener('mouseenter', handleEnter);
    iconBadge.addEventListener('mouseleave', handleLeave);
    iconBadge.addEventListener('focus', handleEnter);
    iconBadge.addEventListener('blur', handleLeave);
    iconBadge.addEventListener('click', (e) => {
      e.stopPropagation();
      e.preventDefault();
      showTooltip(iconBadge, detection);
    });

    // Also show tooltip when hovering the highlighted element directly
    element.addEventListener('mouseenter', () => showTooltip(element, detection));
    element.addEventListener('mouseleave', handleLeave);

    // 4. Safely attach warning icon adjacent to element without modifying element's internal text
    try {
      isFraudGuardMutating = true;
      if (element.parentNode) {
        element.parentNode.insertBefore(iconBadge, element.nextSibling);
      }
      isFraudGuardMutating = false;
    } catch (e) {
      isFraudGuardMutating = false;
      // If insertion fails due to unusual parent layout, the element outline remains intact
    }
  }

  /* ==========================================================================
     5. DOM SCANNER & MUTATION OBSERVER
     ========================================================================== */

  /**
   * Scans a root container for all candidate text elements and checkboxes
   */
  function scanContainer(root) {
    if (!root || isIgnoredOrSensitive(root)) return;

    // Scan text candidate elements
    if (root.matches && root.matches(CANDIDATE_SELECTOR)) {
      inspectElement(root);
    }

    if (root.querySelectorAll) {
      const candidates = root.querySelectorAll(CANDIDATE_SELECTOR);
      for (let i = 0; i < candidates.length; i++) {
        inspectElement(candidates[i]);
      }
    }

    // Scan pre-selected checkboxes & toggles
    scanCheckboxes(root);
  }

  /**
   * Debounce utility to prevent CPU thrashing on active e-commerce pages
   */
  function debounce(fn, waitMs) {
    let timeout = null;
    return function (...args) {
      if (timeout) clearTimeout(timeout);
      timeout = setTimeout(() => {
        fn.apply(this, args);
      }, waitMs);
    };
  }

  // Queue of newly added nodes during dynamic updates
  const pendingNodes = new Set();

  const processPendingNodes = debounce(() => {
    if (pendingNodes.size === 0) return;

    const nodesToProcess = Array.from(pendingNodes);
    pendingNodes.clear();

    nodesToProcess.forEach(node => {
      if (document.body.contains(node)) {
        scanContainer(node);
      }
    });
  }, 250);

  /**
   * Sets up MutationObserver to detect dynamically rendered elements (AJAX, hydration, SPA)
   */
  function setupMutationObserver() {
    const observer = new MutationObserver(mutations => {
      if (isFraudGuardMutating) return;

      let hasNewCandidates = false;

      for (let i = 0; i < mutations.length; i++) {
        const mutation = mutations[i];

        // Skip mutations caused by FraudGuard components
        if (mutation.target && mutation.target.closest && mutation.target.closest('[data-fraudguard-ignore="true"]')) {
          continue;
        }

        // Handle dynamically toggled checked state on checkboxes
        if (mutation.type === 'attributes') {
          if (mutation.target && (mutation.attributeName === 'checked' || mutation.attributeName === 'aria-checked')) {
            inspectSelectedCheckbox(mutation.target);
          }
          continue;
        }

        // Handle added DOM nodes
        if (mutation.addedNodes && mutation.addedNodes.length > 0) {
          for (let j = 0; j < mutation.addedNodes.length; j++) {
            const added = mutation.addedNodes[j];
            if (added.nodeType === Node.ELEMENT_NODE && !isIgnoredOrSensitive(added)) {
              pendingNodes.add(added);
              hasNewCandidates = true;
            }
          }
        }
      }

      if (hasNewCandidates) {
        processPendingNodes();
      }
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['checked', 'aria-checked']
    });

    // Cleanup on unload
    window.addEventListener('beforeunload', () => {
      observer.disconnect();
    });
  }

  /* ==========================================================================
     6. DOMAIN & SSL INTELLIGENCE REQUEST
     ========================================================================== */

  /**
   * Requests domain registration and SSL/TLS intelligence from the backend.
   * Executed once per page load. Never triggered on DOM mutations.
   */
  function requestDomainIntelligence() {
    const hostname = window.location.hostname;
    if (!hostname || hostname === 'localhost' || hostname === '127.0.0.1') {
      return;
    }

    try {
      if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
        chrome.runtime.sendMessage({ action: 'analyzeDomain', domain: hostname }, (response) => {
          if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.lastError) {
            // Gracefully handle backend or background worker offline state
            return;
          }

          if (response && response.success && response.data) {
            window.__FRAUDGUARD_STATE__.domainIntelligence = response.data;
            console.log('[FraudGuard] Domain analysis received');
            updateGlobalWidget();

            if (response.data.domain_characteristics) {
              const ageDays = response.data.domain_characteristics.domain_age_days;
              console.log(`[FraudGuard] Domain age: ${ageDays !== null && ageDays !== undefined ? ageDays + ' days' : 'Unknown'}`);
            }
            if (response.data.ssl) {
              console.log(`[FraudGuard] SSL valid: ${response.data.ssl.valid}`);
            }

            // Trigger scoring calculation
            requestScoreCalculation();
          }
        });
      }
    } catch (e) {
      // Ignore runtime errors if extension context invalidated
    }
  }

  /* ==========================================================================
     7. MACHINE LEARNING TEXT CLASSIFICATION REQUEST
     ========================================================================== */

  /**
   * Requests ML text classification from the FastAPI backend for detected text.
   * Runs asynchronously and enriches detection with prediction and confidence.
   */
  function requestMlAnalysis(detection) {
    if (!detection || !detection.message || !detection.message.trim()) {
      detection.mlStatus = 'skipped';
      return;
    }

    if (typeof chrome === 'undefined' || !chrome.runtime || !chrome.runtime.sendMessage) {
      detection.mlStatus = 'offline';
      return;
    }

    try {
      chrome.runtime.sendMessage({
        action: 'analyzeText',
        text: detection.message
      }, (response) => {
        if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.lastError) {
          detection.mlStatus = 'offline';
          return;
        }

        if (response && response.success && response.data) {
          detection.mlPrediction = response.data.prediction; // 'DARK_PATTERN' | 'NOT_DARK_PATTERN'
          detection.mlConfidence = response.data.confidence;
          detection.mlDarkPatternProb = response.data.dark_pattern_probability;
          detection.mlStatus = 'success';

          const pct = Math.round(detection.mlConfidence * 100);
          console.log(`[FraudGuard] ML Classification for "${detection.message.slice(0, 35)}...": ${detection.mlPrediction} (${pct}%)`);

          // Trigger scoring calculation and widget update
          requestScoreCalculation();
          updateGlobalWidget();

          // If tooltip is currently visible for this detection, dynamically re-render it
          if (activeTooltipDetection === detection && tooltipPortal && tooltipPortal.classList.contains('fraudguard-tooltip-visible')) {
            showTooltip(activeTooltipTarget, detection);
          }
        } else {
          detection.mlStatus = 'offline';
          updateGlobalWidget();
        }
      });
    } catch (e) {
      detection.mlStatus = 'offline';
      updateGlobalWidget();
    }
  }

  /* ==========================================================================
     8. INDEPENDENT FRAUDGUARD SCORING ENGINE REQUEST
     ========================================================================== */

  let scoreDebounceTimeout = null;

  /**
   * Triggers asynchronous calculation of independent Deceptive UI & Store Trust Scores.
   * Debounced to prevent CPU / network thrashing as detections stream in.
   */
  function requestScoreCalculation() {
    if (scoreDebounceTimeout) clearTimeout(scoreDebounceTimeout);

    scoreDebounceTimeout = setTimeout(() => {
      if (typeof chrome === 'undefined' || !chrome.runtime || !chrome.runtime.sendMessage) {
        window.__FRAUDGUARD_STATE__.scoreStatus = 'offline';
        window.__FRAUDGUARD_STATE__.riskStatus = 'offline';
        updateGlobalWidget();
        return;
      }

      window.__FRAUDGUARD_STATE__.scoreStatus = 'pending';
      window.__FRAUDGUARD_STATE__.riskStatus = 'pending';
      updateGlobalWidget();

      const payload = {
        detections: window.__FRAUDGUARD_STATE__.detections.map(d => ({
          category: d.category,
          severity: d.severity,
          message: d.message,
          mlPrediction: d.mlPrediction,
          mlConfidence: d.mlConfidence,
          mlDarkPatternProb: d.mlDarkPatternProb
        })),
        domain_intelligence: window.__FRAUDGUARD_STATE__.domainIntelligence
      };

      try {
        chrome.runtime.sendMessage({
          action: 'calculateScore',
          payload: payload
        }, (response) => {
          if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.lastError) {
            window.__FRAUDGUARD_STATE__.scoreStatus = 'offline';
            window.__FRAUDGUARD_STATE__.riskStatus = 'offline';
            updateGlobalWidget();
            return;
          }

          if (response && response.success && response.data) {
            window.__FRAUDGUARD_STATE__.scores = response.data;
            window.__FRAUDGUARD_STATE__.scoreStatus = 'success';

            if (response.data.risk_assessment) {
              window.__FRAUDGUARD_STATE__.riskAssessment = response.data.risk_assessment;
              window.__FRAUDGUARD_STATE__.riskStatus = 'success';
            }

            const scores = response.data;
            const trustStr = scores.store_trust_score !== null ? `${scores.store_trust_score}/100 (${scores.store_trust_level})` : 'INSUFFICIENT DATA';
            const riskStr = response.data.risk_assessment ? `${response.data.risk_assessment.overall_risk} RISK` : 'N/A';
            const uiSafetyStr = scores.ui_safety_score !== undefined ? `${scores.ui_safety_score}/100 (${scores.ui_safety_level})` : 'N/A';
            console.log(`[FraudGuard] Scores & Risk: Overall = ${riskStr}, UI Safety = ${uiSafetyStr}, Store Trust = ${trustStr}`);

            updateGlobalWidget();
          } else {
            window.__FRAUDGUARD_STATE__.scoreStatus = 'offline';
            window.__FRAUDGUARD_STATE__.riskStatus = 'offline';
            updateGlobalWidget();
          }
        });
      } catch (e) {
        window.__FRAUDGUARD_STATE__.scoreStatus = 'offline';
        window.__FRAUDGUARD_STATE__.riskStatus = 'offline';
        updateGlobalWidget();
      }
    }, 250);
  }

  /* ==========================================================================
     9. GLOBAL FRAUDGUARD WIDGET & DETAILED ANALYSIS PANEL
     ========================================================================== */

  let globalRootElement = null;
  let collapsedWidgetElement = null;
  let panelBackdropElement = null;
  let panelDrawerElement = null;
  let panelBodyElement = null;

  /**
   * Initializes the persistent floating global analysis widget and slide-in drawer.
   * Strictly injected once per page with data-fraudguard-ignore="true" to prevent
   * infinite MutationObserver cycles or DOM duplication.
   */
  function initGlobalWidget() {
    if (document.getElementById('fraudguard-global-root')) {
      globalRootElement = document.getElementById('fraudguard-global-root');
      collapsedWidgetElement = document.getElementById('fraudguard-widget-collapsed');
      panelBackdropElement = document.getElementById('fraudguard-panel-backdrop');
      panelDrawerElement = document.getElementById('fraudguard-panel-drawer');
      panelBodyElement = document.getElementById('fraudguard-panel-body');
      return;
    }

    globalRootElement = document.createElement('div');
    globalRootElement.id = 'fraudguard-global-root';
    globalRootElement.setAttribute('data-fraudguard-ignore', 'true');

    // 1. Floating Collapsed Capsule (Bottom-Right)
    collapsedWidgetElement = document.createElement('div');
    collapsedWidgetElement.id = 'fraudguard-widget-collapsed';
    collapsedWidgetElement.setAttribute('role', 'button');
    collapsedWidgetElement.setAttribute('tabindex', '0');
    collapsedWidgetElement.setAttribute('aria-label', 'Open FraudGuard Page Analysis');
    collapsedWidgetElement.addEventListener('click', toggleAnalysisPanel);
    collapsedWidgetElement.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        toggleAnalysisPanel();
      }
    });

    // 2. Backdrop Overlay
    panelBackdropElement = document.createElement('div');
    panelBackdropElement.id = 'fraudguard-panel-backdrop';
    panelBackdropElement.className = 'fg-backdrop-hidden';
    panelBackdropElement.addEventListener('click', closeAnalysisPanel);

    // 3. Slide-in Analysis Drawer
    panelDrawerElement = document.createElement('div');
    panelDrawerElement.id = 'fraudguard-panel-drawer';
    panelDrawerElement.className = 'fg-drawer-closed';
    panelDrawerElement.setAttribute('role', 'dialog');
    panelDrawerElement.setAttribute('aria-modal', 'true');
    panelDrawerElement.setAttribute('aria-label', 'FraudGuard Store & Page Analysis');

    const drawerHeader = document.createElement('div');
    drawerHeader.className = 'fg-panel-header';
    drawerHeader.innerHTML = `
      <div class="fg-panel-title-wrap">
        <span class="fg-panel-shield">🛡️</span>
        <div>
          <div class="fg-panel-title">FraudGuard</div>
          <div class="fg-panel-subtitle">Page & Store Analysis</div>
        </div>
      </div>
      <button class="fg-panel-close-btn" id="fraudguard-panel-close" aria-label="Close panel">✕</button>
    `;

    panelBodyElement = document.createElement('div');
    panelBodyElement.id = 'fraudguard-panel-body';
    panelBodyElement.className = 'fg-panel-body';

    panelDrawerElement.appendChild(drawerHeader);
    panelDrawerElement.appendChild(panelBodyElement);

    // Hook up close button
    const closeBtn = drawerHeader.querySelector('#fraudguard-panel-close');
    if (closeBtn) {
      closeBtn.addEventListener('click', closeAnalysisPanel);
    }

    // Keyboard support: Escape closes panel
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && window.__FRAUDGUARD_STATE__.isPanelOpen) {
        closeAnalysisPanel();
      }
    });

    globalRootElement.appendChild(collapsedWidgetElement);
    globalRootElement.appendChild(panelBackdropElement);
    globalRootElement.appendChild(panelDrawerElement);

    isFraudGuardMutating = true;
    document.body.appendChild(globalRootElement);
    isFraudGuardMutating = false;

    updateGlobalWidget();
  }

  function toggleAnalysisPanel() {
    if (window.__FRAUDGUARD_STATE__.isPanelOpen) {
      closeAnalysisPanel();
    } else {
      openAnalysisPanel();
    }
  }

  function openAnalysisPanel() {
    window.__FRAUDGUARD_STATE__.isPanelOpen = true;
    if (panelBackdropElement) {
      panelBackdropElement.classList.remove('fg-backdrop-hidden');
      panelBackdropElement.classList.add('fg-backdrop-visible');
    }
    if (panelDrawerElement) {
      panelDrawerElement.classList.remove('fg-drawer-closed');
      panelDrawerElement.classList.add('fg-drawer-open');
    }
    renderPanelBody();
  }

  function closeAnalysisPanel() {
    window.__FRAUDGUARD_STATE__.isPanelOpen = false;
    if (panelBackdropElement) {
      panelBackdropElement.classList.remove('fg-backdrop-visible');
      panelBackdropElement.classList.add('fg-backdrop-hidden');
    }
    if (panelDrawerElement) {
      panelDrawerElement.classList.remove('fg-drawer-open');
      panelDrawerElement.classList.add('fg-drawer-closed');
    }
  }

  /**
   * Refreshes the collapsed widget display and, if open, the detailed drawer.
   */
  function updateGlobalWidget() {
    if (!collapsedWidgetElement) {
      collapsedWidgetElement = document.getElementById('fraudguard-widget-collapsed');
    }
    if (!collapsedWidgetElement) return;

    const scores = window.__FRAUDGUARD_STATE__.scores;
    const scoreStatus = window.__FRAUDGUARD_STATE__.scoreStatus;
    const risk = window.__FRAUDGUARD_STATE__.riskAssessment || (scores ? scores.risk_assessment : null);

    let metricsHtml = '';
    let riskBadgeHtml = '';

    if (scoreStatus === 'success' && scores) {
      let trustVal = 'N/A';
      let trustClass = 'fg-val-insufficient';
      if (scores.store_trust_score !== null && scores.store_trust_score !== undefined) {
        trustVal = scores.store_trust_score;
        trustClass = `fg-val-${(scores.store_trust_level || 'medium').toLowerCase()}`;
      }

      const deceptiveVal = scores.deceptive_ui_score !== undefined ? scores.deceptive_ui_score : 0;
      const deceptiveClass = `fg-val-${(scores.deceptive_ui_level || 'low').toLowerCase()}`;

      if (risk && risk.overall_risk) {
        const rVal = risk.overall_risk.toUpperCase();
        const rClass = `fg-badge-${rVal.toLowerCase()}`;
        riskBadgeHtml = `<span class="fg-widget-risk-badge ${rClass}">${escapeHtml(rVal)} RISK</span>`;
      } else {
        riskBadgeHtml = `<span class="fg-widget-risk-badge fg-badge-insufficient">EVALUATING</span>`;
      }

      metricsHtml = `
        <div class="fg-widget-metrics">
          <div class="fg-widget-metric">
            <span class="fg-metric-label">Store Trust</span>
            <span class="fg-metric-val ${trustClass}">${escapeHtml(String(trustVal))}<span class="fg-metric-max">/100</span></span>
          </div>
          <div class="fg-widget-divider"></div>
          <div class="fg-widget-metric">
            <span class="fg-metric-label">Deceptive UI</span>
            <span class="fg-metric-val ${deceptiveClass}">${escapeHtml(String(deceptiveVal))}<span class="fg-metric-max">/100</span></span>
          </div>
        </div>
      `;
    } else if (scoreStatus === 'offline' || scoreStatus === 'failed') {
      riskBadgeHtml = `<span class="fg-widget-risk-badge fg-badge-insufficient">OFFLINE</span>`;
      metricsHtml = `
        <div class="fg-widget-metrics">
          <span class="fg-widget-status-text">⚠️ Scores Unavailable</span>
        </div>
      `;
    } else {
      riskBadgeHtml = `<span class="fg-widget-risk-badge fg-badge-insufficient">ANALYZING</span>`;
      metricsHtml = `
        <div class="fg-widget-metrics">
          <span class="fg-widget-status-text">⏳ Analyzing page...</span>
        </div>
      `;
    }

    collapsedWidgetElement.innerHTML = `
      <div class="fg-widget-header">
        <div class="fg-widget-brand-row">
          <span class="fg-widget-shield">🛡️</span>
          <span class="fg-widget-brand">FraudGuard</span>
        </div>
        ${riskBadgeHtml}
      </div>
      ${metricsHtml}
    `;

    if (window.__FRAUDGUARD_STATE__.isPanelOpen) {
      renderPanelBody();
    }
  }

  /**
   * Renders the complete analysis content inside the slide-in drawer.
   */
  function renderPanelBody() {
    const bodyEl = panelBodyElement || document.getElementById('fraudguard-panel-body');
    if (!bodyEl) return;

    const scores = window.__FRAUDGUARD_STATE__.scores;
    const scoreStatus = window.__FRAUDGUARD_STATE__.scoreStatus;
    const domIntel = window.__FRAUDGUARD_STATE__.domainIntelligence;
    const detections = window.__FRAUDGUARD_STATE__.detections || [];

    // --- 1. Overall Risk Data ---
    const risk = window.__FRAUDGUARD_STATE__.riskAssessment || (scores ? scores.risk_assessment : null);
    let riskLevelDisplay = 'ANALYZING';
    let riskClassSuffix = 'insufficient';
    let riskEmoji = '⏳';
    let riskGuidanceText = 'Analyzing page elements and domain intelligence...';
    let riskReasons = [];

    if (scoreStatus === 'success' && risk) {
      riskLevelDisplay = (risk.overall_risk || 'MEDIUM').toUpperCase() + ' RISK';
      riskClassSuffix = (risk.overall_risk || 'medium').toLowerCase();
      if (risk.overall_risk === 'LOW') {
        riskEmoji = '🟢';
      } else if (risk.overall_risk === 'HIGH') {
        riskEmoji = '🔴';
      } else {
        riskEmoji = '🟡';
      }
      riskGuidanceText = risk.risk_guidance || 'Review the findings before proceeding.';
      riskReasons = Array.isArray(risk.risk_reasons) ? risk.risk_reasons : [];
    } else if (scoreStatus === 'offline' || scoreStatus === 'failed') {
      riskLevelDisplay = 'OFFLINE';
      riskClassSuffix = 'insufficient';
      riskEmoji = '⚠️';
      riskGuidanceText = 'Backend service is offline. Overall risk cannot be determined.';
      riskReasons = [
        'ℹ Backend intelligence service is currently unreachable (port 8001).',
        'ℹ Page-level scoring and domain verification are offline.'
      ];
    } else {
      riskReasons = [
        '⏳ Scanning visible interface elements...',
        '⏳ Gathering domain WHOIS and SSL/TLS telemetry...'
      ];
    }

    const reasonsHtml = riskReasons.map(r => `
      <div class="fg-reason-item">
        <span>${escapeHtml(r)}</span>
      </div>
    `).join('');

    // --- 2. Score Summary Data ---
    let uiSafetyNum = '--';
    let uiSafetyLvl = 'ANALYZING';
    let uiSafetyBadgeClass = 'fg-badge-insufficient';

    let trustNum = '--';
    let trustLvl = 'ANALYZING';
    let trustBadgeClass = 'fg-badge-insufficient';

    if (scoreStatus === 'success' && scores) {
      if (scores.ui_safety_score !== undefined && scores.ui_safety_score !== null) {
        uiSafetyNum = scores.ui_safety_score;
      } else if (scores.deceptive_ui_score !== undefined && scores.deceptive_ui_score !== null) {
        uiSafetyNum = 100 - scores.deceptive_ui_score;
      } else {
        uiSafetyNum = 100;
      }
      const rawUiLvl = (scores.ui_safety_level || (uiSafetyNum <= 30 ? 'LOW' : (uiSafetyNum <= 75 ? 'MEDIUM' : 'HIGH'))).toUpperCase();
      uiSafetyLvl = rawUiLvl.includes('UI SAFETY') ? rawUiLvl : `${rawUiLvl} UI SAFETY`;
      const uiBase = rawUiLvl.replace(' UI SAFETY', '').toLowerCase();
      uiSafetyBadgeClass = `fg-badge-safe-${uiBase}`;

      if (scores.store_trust_score !== null && scores.store_trust_score !== undefined) {
        trustNum = scores.store_trust_score;
        const rawTrustLvl = (scores.store_trust_level || (trustNum <= 30 ? 'LOW' : (trustNum <= 75 ? 'MEDIUM' : 'HIGH'))).toUpperCase();
        trustLvl = rawTrustLvl.includes('TRUST') ? rawTrustLvl : `${rawTrustLvl} TRUST`;
        const trustBase = rawTrustLvl.replace(' TRUST', '').toLowerCase();
        trustBadgeClass = `fg-badge-safe-${trustBase}`;
      } else {
        trustNum = 'N/A';
        trustLvl = 'INSUFFICIENT DATA';
        trustBadgeClass = 'fg-badge-insufficient';
      }
    } else if (scoreStatus === 'offline' || scoreStatus === 'failed') {
      uiSafetyNum = 'N/A';
      uiSafetyLvl = 'OFFLINE';
      trustNum = 'N/A';
      trustLvl = 'OFFLINE';
    }

    // --- 3. Deceptive UI Findings List ---
    let findingsHtml = '';
    if (detections.length === 0) {
      findingsHtml = `
        <div style="font-size: 11.5px; color: #166534; background: #f0fdf4; border: 1px solid #86efac; padding: 10px 12px; border-radius: 6px;">
          ✅ No deceptive UI patterns detected on this page.
        </div>
      `;
    } else {
      findingsHtml = detections.map(d => {
        const cat = (d.category || 'UNKNOWN').toUpperCase().replace('-', '_');
        const sev = (d.severity || 'low').toUpperCase();
        const sevClass = `fg-badge-${sev.toLowerCase()}`;
        let mlTag = '';
        if (d.mlStatus === 'success' && d.mlPrediction) {
          const isDark = d.mlPrediction === 'DARK_PATTERN';
          const conf = Math.round((d.mlConfidence || 0) * 100);
          const color = isDark ? '#b91c1c' : '#166534';
          const label = isDark ? 'Dark Pattern' : 'Not Dark Pattern';
          mlTag = `<div class="fg-card-ml" style="color: ${color};">🤖 ML: ${label} (${conf}%)</div>`;
        } else if (d.mlStatus === 'pending') {
          mlTag = `<div class="fg-card-ml" style="color: #64748b;">🤖 ML: Analyzing...</div>`;
        }
        return `
          <div class="fg-detection-card">
            <div class="fg-card-meta">
              <span class="fg-card-category">${escapeHtml(cat)}</span>
              <span class="fg-badge-tag ${sevClass}">${escapeHtml(sev)}</span>
            </div>
            <div class="fg-card-quote">"${escapeHtml(d.message)}"</div>
            <div class="fg-card-explanation">${escapeHtml(d.explanation)}</div>
            ${mlTag}
          </div>
        `;
      }).join('');
    }

    // --- 4. Domain & Infrastructure Telemetry ---
    const currentHost = window.location.hostname || window.location.host || 'local-test-page';
    let domainAgeText = 'Unknown / Redacted';
    if (domIntel && domIntel.domain_characteristics && domIntel.domain_characteristics.domain_age_days !== null && domIntel.domain_characteristics.domain_age_days !== undefined) {
      const days = domIntel.domain_characteristics.domain_age_days;
      const yrs = (days / 365.25).toFixed(1);
      domainAgeText = `${days} days (~${yrs} yrs)${days < 30 ? ' ⚠️ (< 30 days)' : ''}`;
    } else if (domIntel && domIntel.whois && domIntel.whois.domain_age_days !== null && domIntel.whois.domain_age_days !== undefined) {
      const days = domIntel.whois.domain_age_days;
      const yrs = (days / 365.25).toFixed(1);
      domainAgeText = `${days} days (~${yrs} yrs)${days < 30 ? ' ⚠️ (< 30 days)' : ''}`;
    }

    let sslText = 'Not verified (HTTP / Offline)';
    if (domIntel && domIntel.ssl) {
      if (domIntel.ssl.valid) {
        sslText = `✅ Valid TLS (${domIntel.ssl.issuer || 'Trusted CA'})`;
      } else {
        sslText = `❌ Invalid / Expired (${domIntel.ssl.error || 'Untrusted'})`;
      }
    }

    let registrarText = 'Protected or Unavailable';
    if (domIntel && domIntel.whois && domIntel.whois.registrar) {
      registrarText = domIntel.whois.registrar;
    }

    let flagsText = 'None (Standard domain structure)';
    if (domIntel && domIntel.domain_characteristics && Array.isArray(domIntel.domain_characteristics.suspicious_structural_flags) && domIntel.domain_characteristics.suspicious_structural_flags.length > 0) {
      flagsText = domIntel.domain_characteristics.suspicious_structural_flags.join(', ');
    }

    // --- 5. ML Text Analysis Summary ---
    const evaluatedSnippets = detections.filter(d => d.mlStatus === 'success');
    const darkCount = evaluatedSnippets.filter(d => d.mlPrediction === 'DARK_PATTERN').length;
    const benignCount = evaluatedSnippets.filter(d => d.mlPrediction === 'NOT_DARK_PATTERN').length;

    // --- 6. Contributing Signals Breakdown (Separated by Score) ---
    const SIGNAL_LABEL_MAP = {
      'interface_design_safety': 'Interface Design Safety',
      'language_analysis_safety': 'Language Analysis Safety',
      'domain_age_days': 'Domain Age',
      'ssl_tls_health': 'SSL/TLS',
      'domain_structural_characteristics': 'Domain Structure',
      'whois_infrastructure': 'WHOIS / Registration'
    };

    function renderContributionChip(item) {
      const label = item.label || SIGNAL_LABEL_MAP[item.signal || item.name] || item.name || 'Signal';
      const pts = (item.contribution_points !== undefined) ? item.contribution_points : (item.points || 0);
      const ptsPrefix = pts > 0 ? '+' : '';
      const ptsColor = pts > 0 ? '#166534' : (pts < 0 ? '#b91c1c' : '#64748b');
      const evidenceText = item.evidence || item.details || item.reason || '';

      return `
        <div class="fg-signal-chip">
          <div style="display: flex; justify-content: space-between; align-items: center; font-weight: 700; margin-bottom: 3px;">
            <span style="color: #1e293b; font-size: 11.5px;">${escapeHtml(label)}</span>
            <span style="color: ${ptsColor}; font-weight: 800; font-size: 11.5px;">${ptsPrefix}${pts} pts</span>
          </div>
          ${evidenceText ? `<div style="font-size: 10.5px; color: #64748b; line-height: 1.35;"><strong style="color: #475569;">Evidence:</strong> ${escapeHtml(evidenceText)}</div>` : ''}
        </div>
      `;
    }

    // Extract UI Safety contributions
    let uiContributions = [];
    if (scores && Array.isArray(scores.ui_safety_contributions) && scores.ui_safety_contributions.length > 0) {
      uiContributions = scores.ui_safety_contributions;
    } else if (scores && scores.ui_safety_breakdown && Array.isArray(scores.ui_safety_breakdown.contributions)) {
      uiContributions = scores.ui_safety_breakdown.contributions;
    } else if (scores && Array.isArray(scores.signals)) {
      uiContributions = scores.signals.filter(s => s.name === 'interface_design_safety' || s.name === 'language_analysis_safety');
    }

    let uiSignalsHtml = '';
    if (scoreStatus === 'offline' || scoreStatus === 'failed') {
      uiSignalsHtml = `<div style="font-size: 11px; color: #64748b; font-style: italic; padding: 4px 0;">Backend offline. Scoring contributions unavailable.</div>`;
    } else if (uiContributions.length === 0) {
      uiSignalsHtml = `<div style="font-size: 11px; color: #166534; font-style: italic; padding: 4px 0;">Clean interface with no deceptive patterns detected (100 pts).</div>`;
    } else {
      uiSignalsHtml = uiContributions.map(renderContributionChip).join('');
    }

    // Extract Store Trust contributions
    let trustContributions = [];
    if (scores && Array.isArray(scores.store_trust_contributions) && scores.store_trust_contributions.length > 0) {
      trustContributions = scores.store_trust_contributions;
    } else if (scores && scores.store_trust_breakdown && Array.isArray(scores.store_trust_breakdown.contributions)) {
      trustContributions = scores.store_trust_breakdown.contributions;
    } else if (scores && Array.isArray(scores.signals)) {
      trustContributions = scores.signals.filter(s => s.name !== 'interface_design_safety' && s.name !== 'language_analysis_safety');
    }

    let trustSignalsHtml = '';
    if (scoreStatus === 'offline' || scoreStatus === 'failed') {
      trustSignalsHtml = `<div style="font-size: 11px; color: #64748b; font-style: italic; padding: 4px 0;">Backend offline. Store trust contributions unavailable.</div>`;
    } else if (trustContributions.length === 0) {
      trustSignalsHtml = `<div style="font-size: 11px; color: #64748b; font-style: italic; padding: 4px 0;">Domain intelligence unavailable for store trust evaluation.</div>`;
    } else {
      trustSignalsHtml = trustContributions.map(renderContributionChip).join('');
    }

    bodyEl.innerHTML = `
      <!-- Overall Risk Banner -->
      <div class="fg-risk-banner fg-risk-banner-${riskClassSuffix}">
        <div class="fg-risk-banner-top">
          <div class="fg-risk-title-wrap">
            <span class="fg-risk-tag">PAGE RISK ASSESSMENT</span>
            <span style="font-size: 11px; font-weight: 700; color: #475569;">Evidence-Based Indicator</span>
          </div>
          <span class="fg-risk-val-badge fg-badge-${riskClassSuffix}">
            ${riskEmoji} ${escapeHtml(riskLevelDisplay)}
          </span>
        </div>
        <div class="fg-risk-guidance">
          <strong>Guidance:</strong> ${escapeHtml(riskGuidanceText)}
        </div>
      </div>

      <!-- Section 1: Score Summary -->
      <div class="fg-section">
        <div class="fg-section-title">
          <span>Score Summary</span>
        </div>
        <div class="fg-scores-grid">
          <div class="fg-score-box">
            <span class="fg-score-tag">UI Safety Score</span>
            <div class="fg-score-num">${escapeHtml(String(uiSafetyNum))}<small>/100</small></div>
            <span class="fg-badge-tag ${uiSafetyBadgeClass}">${escapeHtml(uiSafetyLvl)}</span>
            <span class="fg-score-desc">Measures user interface safety and absence of deceptive patterns</span>
          </div>
          <div class="fg-score-box">
            <span class="fg-score-tag">Store Trust Score</span>
            <div class="fg-score-num">${escapeHtml(String(trustNum))}<small>/100</small></div>
            <span class="fg-badge-tag ${trustBadgeClass}">${escapeHtml(trustLvl)}</span>
            <span class="fg-score-desc">Measures domain age, infrastructure, registration and security evidence</span>
          </div>
        </div>
        <div class="fg-callout-note">
          <strong>⚖️ STORE TRUST-PRIORITY MODEL:</strong> Store Trust is the primary risk factor; UI Safety is the secondary factor. Higher Store Trust reflects safer domain characteristics, and higher UI Safety indicates fewer deceptive interface concerns. Lower UI Safety indicates stronger deceptive UI concerns. Critical security signals can override the normal matrix to High Risk.
        </div>
      </div>

      <!-- Why This Risk Level? -->
      <div class="fg-section">
        <div class="fg-section-title">
          <span>Why This Risk Level?</span>
          <span class="fg-section-count">${riskReasons.length}</span>
        </div>
        <div class="fg-why-section">
          ${reasonsHtml}
        </div>
      </div>

      <!-- Section 2: Deceptive UI Findings -->
      <div class="fg-section">
        <div class="fg-section-title">
          <span>Deceptive UI Findings</span>
          <span class="fg-section-count">${detections.length}</span>
        </div>
        <div style="display: flex; flex-direction: column; gap: 8px;">
          ${findingsHtml}
        </div>
      </div>

      <!-- Section 3: Domain & Store Intelligence -->
      <div class="fg-section">
        <div class="fg-section-title">
          <span>Domain & Infrastructure Intelligence</span>
        </div>
        <div class="fg-telemetry-list">
          <div class="fg-telemetry-item">
            <span class="fg-telemetry-label">Domain</span>
            <span class="fg-telemetry-val">${escapeHtml(currentHost)}</span>
          </div>
          <div class="fg-telemetry-item">
            <span class="fg-telemetry-label">Domain Age</span>
            <span class="fg-telemetry-val">${escapeHtml(domainAgeText)}</span>
          </div>
          <div class="fg-telemetry-item">
            <span class="fg-telemetry-label">SSL / TLS Status</span>
            <span class="fg-telemetry-val">${escapeHtml(sslText)}</span>
          </div>
          <div class="fg-telemetry-item">
            <span class="fg-telemetry-label">WHOIS Registrar</span>
            <span class="fg-telemetry-val">${escapeHtml(registrarText)}</span>
          </div>
          <div class="fg-telemetry-item">
            <span class="fg-telemetry-label">Structural Flags</span>
            <span class="fg-telemetry-val">${escapeHtml(flagsText)}</span>
          </div>
        </div>
      </div>

      <!-- Section 4: ML Dark-Pattern Text Analysis Summary -->
      <div class="fg-section">
        <div class="fg-section-title">
          <span>ML Text Classification Summary</span>
        </div>
        <div class="fg-telemetry-list">
          <div class="fg-telemetry-item">
            <span class="fg-telemetry-label">Evaluated Snippets</span>
            <span class="fg-telemetry-val">${evaluatedSnippets.length} / ${detections.length}</span>
          </div>
          <div class="fg-telemetry-item">
            <span class="fg-telemetry-label">Confirmed Dark Pattern</span>
            <span class="fg-telemetry-val" style="color: #b91c1c;">${darkCount}</span>
          </div>
          <div class="fg-telemetry-item">
            <span class="fg-telemetry-label">Benign / Non-Pattern</span>
            <span class="fg-telemetry-val" style="color: #166534;">${benignCount}</span>
          </div>
          <div class="fg-telemetry-item">
            <span class="fg-telemetry-label">Model Pipeline</span>
            <span class="fg-telemetry-val">TF-IDF + LogisticRegression</span>
          </div>
        </div>
      </div>

      <!-- Section 5: Contributing Signals — UI Safety Score -->
      <div class="fg-section">
        <div class="fg-section-title">
          <span>Contributing Signals — UI Safety Score</span>
          <span class="fg-section-count">${uiContributions.length}</span>
        </div>
        <div class="fg-signals-list">
          ${uiSignalsHtml}
        </div>
        <div class="fg-contribution-total-bar">
          <span class="fg-contrib-total-label">Total UI Safety Score</span>
          <span class="fg-contrib-total-val">${escapeHtml(String(uiSafetyNum))} / 100</span>
        </div>
      </div>

      <!-- Section 6: Contributing Signals — Store Trust Score -->
      <div class="fg-section">
        <div class="fg-section-title">
          <span>Contributing Signals — Store Trust Score</span>
          <span class="fg-section-count">${trustContributions.length}</span>
        </div>
        <div class="fg-signals-list">
          ${trustSignalsHtml}
        </div>
        <div class="fg-contribution-total-bar">
          <span class="fg-contrib-total-label">Total Store Trust Score</span>
          <span class="fg-contrib-total-val">${escapeHtml(String(trustNum))} / 100</span>
        </div>
      </div>

      <!-- Section 7: Action Controls -->
      <div class="fg-section" style="padding-top: 4px; display: flex; gap: 8px;">
        <button id="fraudguard-btn-rescan" style="flex: 1; padding: 9px 12px; background: #0f172a; color: #ffffff; border: none; border-radius: 6px; font-weight: 700; font-size: 11px; cursor: pointer;">🔄 Re-scan Page</button>
        <button id="fraudguard-btn-close-bottom" style="flex: 1; padding: 9px 12px; background: #f1f5f9; color: #334155; border: 1px solid #cbd5e1; border-radius: 6px; font-weight: 700; font-size: 11px; cursor: pointer;">Close Panel</button>
      </div>
    `;

    // Connect action buttons
    const rescanBtn = bodyEl.querySelector('#fraudguard-btn-rescan');
    if (rescanBtn) {
      rescanBtn.addEventListener('click', () => {
        scanContainer(document.body);
        requestDomainIntelligence();
        requestScoreCalculation();
      });
    }

    const closeBottomBtn = bodyEl.querySelector('#fraudguard-btn-close-bottom');
    if (closeBottomBtn) {
      closeBottomBtn.addEventListener('click', closeAnalysisPanel);
    }
  }

  /* ==========================================================================
     10. INITIALIZATION
     ========================================================================== */

  function initialize() {
    initTooltipPortal();
    initGlobalWidget();
    scanContainer(document.body);
    setupMutationObserver();
    requestDomainIntelligence();
    requestScoreCalculation();
  }

  // Ensure DOM is ready before starting scan
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initialize);
  } else {
    initialize();
  }

})();
