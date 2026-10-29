"""memory — SafeSC's required, local, read-only-to-agents memory (CLAUDE.md §3).

`SafeSCMemory` is the single owner: it opens the verdict store and the curated
known-attack corpus, hands agents a Strands `MemoryManager` (recall + injection, never an
add tool), and performs the one post-decision write.
"""

from safesc.memory.manager import MemoryInitError, SafeSCMemory, artifact_id, default_memory_dir

__all__ = ["MemoryInitError", "SafeSCMemory", "artifact_id", "default_memory_dir"]
