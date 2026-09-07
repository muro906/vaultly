import "@testing-library/jest-dom/vitest";

import { cleanup } from "@testing-library/react";
import { afterEach, vi } from "vitest";

// Unmounts between tests so a component's timers and listeners cannot leak
// into the next one.
afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});
