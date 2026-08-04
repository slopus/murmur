# Ratchet-tree encoding internals

Strict codec for the RFC `ratchet_tree` extension: a vector of optional leaf or
parent nodes. Leaf bytes are preserved exactly for tree-hash computation.
