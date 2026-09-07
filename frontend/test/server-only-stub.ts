// Stands in for the `server-only` package under test. That package exists to
// make a build fail if a server module is imported into a client bundle; it
// has no runtime behaviour to reproduce.
export {};
