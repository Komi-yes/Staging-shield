package cmd

import "os"

// isTerminal reporta si el descriptor parece ser una terminal interactiva.
// Si lo es, podemos imprimir colores ANSI; si está redirigido a un archivo
// o a un pipe (p.ej. en CI), preferimos texto plano.
func isTerminal(f *os.File) bool {
	stat, err := f.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) != 0
}
