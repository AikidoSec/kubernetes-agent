// Verbatim copy of pkg/config/dynamic/ext/ext.go from traefik/traefik v3.7.11 (MIT).
// Traefik's nested module path (github.com/traefik/traefik/dynamic/ext) does not match its
// location in the repo, so no proxy can resolve it and upstream satisfies it with a
// relative-path replace. Importing pkg/config/dynamic requires supplying our own copy.
package ext

// HTTP is a dynamic.HTTP extension.
type HTTP struct{}

// Router is a dynamic.Router extension.
type Router struct{}
