all
# Multiple top level headers in the same document
exclude_rule 'MD025'

# Unordered list indentation style
exclude_rule 'MD004'
exclude_rule 'MD007'

# Code block style
exclude_rule 'MD046'

# Line length (too strict for spec docs)
exclude_rule 'MD013'
# Multiple consecutive blank lines
exclude_rule 'MD012'

rule 'MD029', 'ol-prefix' => :ordered
exclude_rule 'MD029'

# First line in file should be a top level header.
exclude_rule 'MD041'
