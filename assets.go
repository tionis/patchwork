package main

import _ "embed"

//go:embed assets/index.html
var indexHtml string

//go:embed assets/water.css
var waterCss string

//go:embed assets/patchwork.sh
var patchworkSh string
