# Independent HTTP1 pull-reader producer admission

The pull reader previously used `Io.async`. With zero async capacity, the
producer could run inline and fill its bounded queue before construction
returned to the consumer. The reader now requires `Io.concurrent` admission.
A failed admission frees its allocation without invoking the parser or closing
the connection.

The integrated Debug scope passed 26 tests. The real 200-KiB upload exercises
100-continue, multiple chunks and a second request on the same connection with
both supported native test backends. Separate checks cover unavailable
concurrency without parser invocation, allocation cleanup, cancellation,
body-size limits, trailers and decoding. Scoped x86_64 Windows compilation
passed. Windows native execution remains for CI; compilation is not proof of
runtime behavior.

No dependency pin or CI budget changes are part of this feature.
