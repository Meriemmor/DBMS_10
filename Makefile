# ============================================================
#  Makefile – DBMS_10 · Project Proposal for the Term Project
#  THGA Bochum · Stephan Bökelmann
#
#  Builds three PDFs into out/:
#    - dbms_10        the exercise (src/)
#    - proposal       the fill-in template (proposal-template/)
#    - documentation  the worked example (example-documentation/)
#
#  Requirement: TeX Live with latexmk (apt install latexmk texlive-full)
# ============================================================

LATEXMK  := latexmk
OUTDIR   := out

# -cd: latexmk changes into the source file's directory before building,
#      so \input and the style search path resolve. The output directory
#      ../out is relative to the source file and therefore always lands in
#      the repository-level out/.
LMKFLAGS := -pdf -interaction=nonstopmode -halt-on-error \
            -cd -output-directory=../$(OUTDIR)

# The style package lives in style/ and is found via an absolute TEXINPUTS
# path, regardless of which subdirectory the source file sits in.
TEXENV   := TEXINPUTS="$(CURDIR)/style:.:$$TEXINPUTS"

STYLE    := style/thga-db.sty

# Let make find each .tex by its basename across the source directories.
vpath %.tex src proposal-template documentation

## All documents to build (basename without .tex):
DOCS     := dbms_10 proposal documentation

ALL_PDF  := $(addprefix $(OUTDIR)/, $(addsuffix .pdf, $(DOCS)))

# ---- Main targets -------------------------------------------

.PHONY: all clean distclean help

all: $(ALL_PDF)

$(OUTDIR):
	mkdir -p $(OUTDIR)

# Generic rule: <basename>.tex (found via vpath) → out/<basename>.pdf
$(OUTDIR)/%.pdf: %.tex $(STYLE) | $(OUTDIR)
	$(TEXENV) $(LATEXMK) $(LMKFLAGS) $<

# ---- Clean up -----------------------------------------------

clean:
	rm -f $(addprefix $(OUTDIR)/, *.aux *.log *.fdb_latexmk *.fls *.out *.toc *.synctex.gz)

distclean:
	rm -rf $(OUTDIR)

# ---- Help ---------------------------------------------------

help:
	@echo "Available targets:"
	@echo "  all        – build all PDFs  (→ $(OUTDIR)/)"
	@echo "  clean      – remove auxiliary files, keep PDFs"
	@echo "  distclean  – remove everything including $(OUTDIR)/"
