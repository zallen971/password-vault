// Tiny DOM helpers. Everything is built with createElement and text nodes;
// nothing in the app ever assigns HTML strings, so vault contents can never
// be interpreted as markup.

import { ICONS } from './icons.js';

const SVG_NS = 'http://www.w3.org/2000/svg';
// Properties that are read-only or behave differently from their attribute.
const ATTRIBUTE_ONLY = new Set(['list', 'form', 'for', 'role', 'width', 'height', 'viewBox', 'enterkeyhint', 'autocapitalize', 'autocorrect']);

function append(parent, children) {
  for (const child of children) {
    if (child == null || child === false || child === true) continue;
    if (Array.isArray(child)) append(parent, child);
    else parent.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
}

/**
 * h('button.btn.btn-primary', { type: 'submit', onclick }, 'Save')
 * The first argument is a tag with optional .classes and #id; props are optional.
 */
export function h(spec, props, ...children) {
  let tag = 'div';
  let id = '';
  const classes = [];
  for (const part of spec.split(/(?=[.#])/)) {
    if (part[0] === '.') classes.push(part.slice(1));
    else if (part[0] === '#') id = part.slice(1);
    else if (part) tag = part;
  }
  const el = document.createElement(tag);
  if (id) el.id = id;
  if (classes.length) el.className = classes.join(' ');

  const isProps = props != null && typeof props === 'object' && !(props instanceof Node) && !Array.isArray(props);
  if (!isProps) children.unshift(props);

  for (const [key, value] of Object.entries(isProps ? props : {})) {
    if (value == null) continue;
    if (key === 'class') {
      for (const name of String(value).split(/\s+/)) if (name) el.classList.add(name);
    } else if (key === 'style') {
      for (const [name, v] of Object.entries(value)) {
        if (name.startsWith('--')) el.style.setProperty(name, v);
        else el.style[name] = v;
      }
    } else if (key === 'dataset') {
      Object.assign(el.dataset, value);
    } else if (key.startsWith('on') && typeof value === 'function') {
      el.addEventListener(key.slice(2), value);
    } else if (key === 'innerHTML' || key === 'outerHTML') {
      throw new Error('HTML strings are not allowed');
    } else if (key.startsWith('aria-') || key.startsWith('data-')) {
      el.setAttribute(key, String(value));
    } else if (key in el && !ATTRIBUTE_ONLY.has(key)) {
      el[key] = value;
    } else if (value !== false) {
      el.setAttribute(key, value === true ? '' : String(value));
    }
  }
  append(el, children);
  return el;
}

/** Replaces everything inside `parent`. */
export function mount(parent, ...children) {
  parent.replaceChildren();
  append(parent, children);
  return parent;
}

const SHAPES = {
  c: ([cx, cy, r]) => ['circle', { cx, cy, r }],
  d: ([cx, cy]) => ['circle', { cx, cy, r: 1.1, fill: 'currentColor', stroke: 'none' }],
  r: ([x, y, width, height, rx]) => ['rect', { x, y, width, height, rx, ry: rx }],
  l: ([x1, y1, x2, y2]) => ['line', { x1, y1, x2, y2 }],
  p: (points) => ['polyline', { points: points.join(' ') }],
  g: (points) => ['polygon', { points: points.join(' ') }],
};

/** An inline SVG icon that inherits the current text color. */
export function icon(name, size = 16) {
  const shapes = ICONS[name];
  if (!shapes) throw new Error(`Unknown icon: ${name}`);
  const svg = document.createElementNS(SVG_NS, 'svg');
  const attrs = {
    class: 'icon',
    viewBox: '0 0 24 24',
    width: size,
    height: size,
    fill: 'none',
    stroke: 'currentColor',
    'stroke-width': 1.9,
    'stroke-linecap': 'round',
    'stroke-linejoin': 'round',
    'aria-hidden': 'true',
    focusable: 'false',
  };
  for (const [key, value] of Object.entries(attrs)) svg.setAttribute(key, value);
  for (const shape of shapes) {
    const [tag, shapeAttrs] = /^[Mm]/.test(shape) ? ['path', { d: shape }] : SHAPES[shape[0]](shape.slice(2).split(' '));
    const node = document.createElementNS(SVG_NS, tag);
    for (const [key, value] of Object.entries(shapeAttrs)) node.setAttribute(key, value);
    svg.append(node);
  }
  return svg;
}

/** Creates an SVG element: svg('circle', { cx: 12, cy: 12, r: 9 }). */
export function svg(tag, attrs = {}, ...children) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, String(value));
  append(node, children);
  return node;
}

/** A square button that shows only an icon; `label` is its accessible name. */
export function iconButton(name, label, { size = 16, ...props } = {}) {
  return h('button.icon-btn', { type: 'button', title: label, 'aria-label': label, ...props }, icon(name, size));
}

const HUES = [4, 24, 38, 142, 162, 187, 205, 221, 243, 262, 292, 330];

/** A stable color for a piece of text, so each item keeps its own tint. */
export function hueFor(text) {
  let hash = 0;
  for (const char of String(text)) hash = (hash * 31 + char.codePointAt(0)) >>> 0;
  return HUES[hash % HUES.length];
}
