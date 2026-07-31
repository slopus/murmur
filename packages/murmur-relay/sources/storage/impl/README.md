# Shared storage mechanics

The mutation planner simulates every operation against versions read inside the
backend transaction. A conflict therefore aborts before either backend writes
state, while both backends share append/replace/delete and capacity semantics.
