The libu8ident library is feature complete, and the libu8ident_c library is now done.

- mktr39.c generates a single self-contained unitr39.h with embedded enums
  and structs. No private header dependencies.
- isTR39_start/cont return struct sc_tr39 pointers; check_buf uses
  tr39->sc, tr39->gc, tr39->scx directly. Greek confusables always enabled.
- u8ident-tr39.c is a single amalgam with zero preprocessor conditionals.
- u8ident_c.h provides the simplified public API for C compiler consumers.
- mk-tr39-amalgam.pl generates a single self-contained u8ident-tr39.c with
  no private header dependencies
