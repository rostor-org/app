-- Scripts will run on macOS and Linux too; the set of languages is a code
-- registry, not a schema rule.
ALTER TABLE scripts DROP CONSTRAINT scripts_language_check;
