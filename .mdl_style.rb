all
# Multiple top level headers in the same document
exclude_rule 'MD025'

#rule 'MD004', 'ul-style' => :sublist
exclude_rule 'MD004'

rule 'MD029', 'ol-prefix' => :ordered
exclude_rule 'MD029'

exclude_rule 'MD046'

# First line in file should be a top level header.
# We set an explicit title for pdf and html
exclude_rule 'MD041'
