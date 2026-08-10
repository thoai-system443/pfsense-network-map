import "@testing-library/jest-dom/vitest";

// React Flow measures its container on mount. jsdom has no ResizeObserver and
// reports every element as 0x0, so both need stubbing before any graph test.
class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
globalThis.ResizeObserver = ResizeObserverStub as unknown as typeof ResizeObserver;

Object.defineProperty(HTMLElement.prototype, "offsetWidth", {
  configurable: true,
  value: 1024,
});
Object.defineProperty(HTMLElement.prototype, "offsetHeight", {
  configurable: true,
  value: 768,
});
