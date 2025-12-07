# Find all directories that contain a Makefile (any depth)
ROOT := $(realpath ..)
SUBDIRS := $(filter-out $(CURDIR)/,$(sort \
	$(dir $(shell find $(ROOT) -name '[Mm]akefile'))))

.PHONY: all $(SUBDIRS) clean

all: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@

clean:
	@for d in $(SUBDIRS); do \
		$(MAKE) -C $$d clean || exit $$?; \
	done
	
	cargo clean
