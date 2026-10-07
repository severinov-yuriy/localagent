---
name: pyspark
description: Practical PySpark engineering guidance
---
Treat Spark/Py4J output as noisy. Prefer built-in Spark expressions over Python UDFs where possible.
Check shuffle, skew, partitioning, cache lifetime and driver-side collection before changing code.
