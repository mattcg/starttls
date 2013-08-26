test: lib/*.js
	./node_modules/.bin/mocha \
		--reporter dot \
		--check-leaks \
		--ui tdd

.PHONY: test
