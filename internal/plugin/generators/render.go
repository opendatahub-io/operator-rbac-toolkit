package generators

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"
)

// templateFuncs provides custom functions available in all templates.
var templateFuncs = template.FuncMap{
	"commentBlock": commentBlock,
}

// templates is the parsed template set, initialized once at package load.
var templates = template.Must(
	template.New("").Funcs(templateFuncs).ParseFS(templatesFS,
		"templates/*.tmpl",
		"templates/webhook/*.tmpl",
	),
)

// commentBlock prefixes every line of s with "// ", suitable for embedding
// multi-line strings as Go comments.
func commentBlock(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = "\t\t// " + l
	}
	return strings.Join(lines, "\n")
}

// renderTemplate renders a named template from the cached template set.
func renderTemplate(name string, data interface{}) (string, error) {
	var buf bytes.Buffer
	if err := templates.ExecuteTemplate(&buf, name, data); err != nil {
		return "", fmt.Errorf("executing template %s: %w", name, err)
	}
	return buf.String(), nil
}
