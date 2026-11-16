.PHONY: build test sample

build:
	mkdir -p _build build && ghc -O1 -isrc -outputdir _build -o build/yara-lint app/Main.hs

test: build
	mkdir -p _build/t && ghc -O0 -isrc -outputdir _build/t -o tests/spec tests/Spec.hs && ./tests/spec && bash tests/cli.sh

sample: build
	mkdir -p docs site
	bin/yara-lint examples > docs/sample-output.txt; true
	bin/yara-lint examples --tsv > docs/sample-output.tsv; true
	python3 scripts/site.py docs/sample-output.tsv site/index.html "yara-lint" "Lints YARA rule files for missing conditions, unreferenced and undefined strings, very short strings, match-all conditions, slow regexes and duplicate names. Haskell." "Synthetic data."
