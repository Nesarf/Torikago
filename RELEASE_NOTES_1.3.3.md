# Torikago 1.3.3

The STIX output could not be imported by anything.

## What was wrong

A generated bundle was handed to the official `stix2` library for the first time:

```
InvalidValueError: Unexpected properties for Indicator: (x_torikago_source_file)
```

**The whole bundle was rejected.** STIX 2.1 permits custom properties, but requires them to be
declared by an `ExtensionDefinition` object in the same bundle; an undeclared `x_` property makes
that object invalid, and **one invalid object invalidates everything**. Every TIP importing this
output would have failed, and the failure would have looked like the TIP's problem.

**And all eighteen existing feed tests passed**, because they checked the shape this tool intends to
produce — is the event well-formed, do the hashes carry the right attribute types — and never asked
whether a consumer accepts the result.

## The fix

The property was written and **never read anywhere in the project**, so it did not warrant an
`ExtensionDefinition`. The same fact now travels in the indicator's `description`, a standard field:

```
description: url, extracted from TeachingFeeling.exe (cea484dc...)
```

`stix2` now parses the bundle: **257 objects, no errors**.

## And the check is now part of the suite

`test/test_feed_validation.py` validates output against the official library when it is installed,
and **skips when it is not**. `stix2` is not a dependency of this project and will not become one —
a security tool's dependency list is part of what a reader has to trust — so the check runs where it
can and costs nothing where it cannot. With `stix2` present: 12 tests pass. Without: 5 skip, 7 pass.

The MISP side is checked the same way, with the standard library's XML parser: the event parses, every
attribute carries the fields MISP requires, `to_ids` survives, and the event is unpublished.

## A test that asks the other question

The new tests ask *would a consumer accept this*, which is a different question from *is this the
shape I meant*. That distinction is the whole reason the defect survived eighteen tests, and it is
worth applying to any output format that leaves this tool for somewhere else.

## Testing

**165 tests** (was 153), green on Python 3.9, 3.12, 3.13 and 3.14.
