# Find all directories that contain a Makefile (any depth)
SUBDIRS := $(filter-out ./,$(sort \
	$(dir $(shell find . -name Makefile -o -name makefile))))

.PHONY: all $(SUBDIRS) clean

all: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@

clean:
	@for d in $(SUBDIRS); do \
		$(MAKE) -C $$d clean || exit $$?; \
	done
	
	cargo clean
