# Component responsibility

Historical responsibility map for the pre-consolidation layout.

| Component | Responsible student | Implementation notes |
| --- | --- | --- |
| Shared/mixed generation and observed-subset construction | Van | Supporting prime generation and GCD checks use libraries |
| Public normalization and deduplication | Van | Validate public records and deduplicate by modulus |
| Euclidean GCD and pairwise scanner | Van | Euclidean GCD and pairwise comparisons |
| Extended GCD, inverse, private-exponent recovery | Van | Arithmetic and recovery validation |
| OAEP wrappers | Van | RSA construction, SHA-256 and OAEP primitives supplied by PyCryptodome |
| Auditor, fixtures and shared-prime demo | Van; joint integration boundary | Pipeline and demonstrations |
| Current tests and repository documentation | Owners of corresponding components | Component and integration checks |
| Batch GCD | Van | Product/remainder trees, raw classification, fallback and tests |
| Close-prime generation and Fermat | Krystal | No implementation present in this repository |
| Shared-prime experiment framework | Krystal lead; Van supplies shared-prime design | E1/E2/E3 supporting runner |
| Benchmark plots | Supporting infrastructure | CSV aggregation and Matplotlib plotting |
