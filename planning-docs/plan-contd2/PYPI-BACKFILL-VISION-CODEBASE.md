# PyPI Backfill — Vision + Codebase

> **Goal:** Get both sisters to crates.io + PyPI parity

---

## Current State

| Sister | crates.io | PyPI | MCP |
|--------|-----------|------|-----|
| Memory | ✅ | ✅ | ✅ |
| Vision | ✅ | ❌ | ✅ |
| Codebase | ✅ | ❌ | ✅ |
| Identity | ✅ (ready) | ✅ (ready) | ✅ |

---

## Vision PyPI Package

### python/pyproject.toml

```toml
[build-system]
requires = ["setuptools>=61.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "agentic-vision"
version = "0.1.0"
description = "Binary web cartography for AI agents"
readme = "README.md"
license = {text = "MIT"}
authors = [{name = "Agentra Labs", email = "contact@agentralabs.tech"}]
classifiers = [
    "Development Status :: 4 - Beta",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.9",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Topic :: Software Development :: Libraries :: Python Modules",
    "Topic :: Scientific/Engineering :: Artificial Intelligence",
]
keywords = ["ai", "agents", "vision", "web", "cartography", "mcp"]
requires-python = ">=3.9"
dependencies = []

[project.optional-dependencies]
dev = ["pytest>=7.0", "pytest-cov>=4.0"]

[project.urls]
Homepage = "https://github.com/AgenticVision/agentic-vision"
Documentation = "https://github.com/AgenticVision/agentic-vision#readme"
Repository = "https://github.com/AgenticVision/agentic-vision"

[tool.setuptools.packages.find]
where = ["src"]

[tool.setuptools.package-data]
agentic_vision = ["*.so", "*.dylib", "*.dll"]
```

### python/src/agentic_vision/__init__.py

```python
"""AgenticVision - Binary web cartography for AI agents."""

__version__ = "0.1.0"

from .vision import (
    VisionGraph,
    capture,
    query,
    compare,
    diff,
    similar,
    health,
)

__all__ = [
    "__version__",
    "VisionGraph",
    "capture",
    "query", 
    "compare",
    "diff",
    "similar",
    "health",
]
```

### python/src/agentic_vision/_ffi.py

```python
"""FFI bindings to libagentic_vision."""

import ctypes
import os
import sys
from pathlib import Path
from typing import Optional

def _find_library() -> str:
    """Find the native library."""
    if sys.platform == "darwin":
        lib_name = "libagentic_vision.dylib"
    elif sys.platform == "win32":
        lib_name = "agentic_vision.dll"
    else:
        lib_name = "libagentic_vision.so"
    
    # Check package directory
    pkg_dir = Path(__file__).parent
    lib_path = pkg_dir / lib_name
    if lib_path.exists():
        return str(lib_path)
    
    # Check common install locations
    for search_path in [
        Path.home() / ".local" / "lib",
        Path("/usr/local/lib"),
        Path("/usr/lib"),
    ]:
        lib_path = search_path / lib_name
        if lib_path.exists():
            return str(lib_path)
    
    raise OSError(f"Cannot find {lib_name}. Install agentic-vision first.")

# Load library
_lib: Optional[ctypes.CDLL] = None

def _get_lib() -> ctypes.CDLL:
    global _lib
    if _lib is None:
        _lib = ctypes.CDLL(_find_library())
        _setup_functions(_lib)
    return _lib

def _setup_functions(lib: ctypes.CDLL) -> None:
    """Set up function signatures."""
    # avis_graph_new
    lib.avis_graph_new.argtypes = []
    lib.avis_graph_new.restype = ctypes.c_void_p
    
    # avis_graph_free
    lib.avis_graph_free.argtypes = [ctypes.c_void_p]
    lib.avis_graph_free.restype = None
    
    # avis_graph_open
    lib.avis_graph_open.argtypes = [ctypes.c_char_p]
    lib.avis_graph_open.restype = ctypes.c_void_p
    
    # avis_graph_save
    lib.avis_graph_save.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.avis_graph_save.restype = ctypes.c_int32
    
    # avis_capture
    lib.avis_capture.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.avis_capture.restype = ctypes.c_int64
    
    # avis_query
    lib.avis_query.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
    lib.avis_query.restype = ctypes.c_int32
    
    # avis_compare
    lib.avis_compare.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_char_p, ctypes.c_size_t]
    lib.avis_compare.restype = ctypes.c_int32
    
    # avis_capture_count
    lib.avis_capture_count.argtypes = [ctypes.c_void_p]
    lib.avis_capture_count.restype = ctypes.c_uint64
    
    # avis_health
    lib.avis_health.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]
    lib.avis_health.restype = ctypes.c_int32
```

### python/src/agentic_vision/vision.py

```python
"""High-level Vision API."""

import json
from pathlib import Path
from typing import Optional, Dict, Any, List
from ._ffi import _get_lib
import ctypes

class VisionGraph:
    """A vision graph for web cartography."""
    
    def __init__(self, path: Optional[str] = None):
        lib = _get_lib()
        if path and Path(path).exists():
            self._ptr = lib.avis_graph_open(path.encode('utf-8'))
            if not self._ptr:
                raise IOError(f"Failed to open vision graph: {path}")
        else:
            self._ptr = lib.avis_graph_new()
            if not self._ptr:
                raise MemoryError("Failed to create vision graph")
        self._path = path
    
    def __del__(self):
        if hasattr(self, '_ptr') and self._ptr:
            _get_lib().avis_graph_free(self._ptr)
    
    def save(self, path: Optional[str] = None) -> None:
        """Save graph to file."""
        save_path = path or self._path
        if not save_path:
            raise ValueError("No path specified")
        lib = _get_lib()
        rc = lib.avis_graph_save(self._ptr, save_path.encode('utf-8'))
        if rc != 0:
            raise IOError(f"Failed to save vision graph: {save_path}")
    
    def capture(self, url: str) -> int:
        """Capture a URL."""
        lib = _get_lib()
        result = lib.avis_capture(self._ptr, url.encode('utf-8'))
        if result < 0:
            raise RuntimeError(f"Capture failed: {url}")
        return result
    
    def query(self, url: str) -> Optional[Dict[str, Any]]:
        """Query a URL's capture."""
        lib = _get_lib()
        buf = ctypes.create_string_buffer(65536)
        rc = lib.avis_query(self._ptr, url.encode('utf-8'), buf, len(buf))
        if rc <= 0:
            return None
        return json.loads(buf.value.decode('utf-8'))
    
    def compare(self, capture_id1: int, capture_id2: int) -> Dict[str, Any]:
        """Compare two captures."""
        lib = _get_lib()
        buf = ctypes.create_string_buffer(65536)
        rc = lib.avis_compare(self._ptr, capture_id1, capture_id2, buf, len(buf))
        if rc <= 0:
            raise RuntimeError("Compare failed")
        return json.loads(buf.value.decode('utf-8'))
    
    @property
    def capture_count(self) -> int:
        """Get number of captures."""
        return _get_lib().avis_capture_count(self._ptr)
    
    def health(self) -> Dict[str, Any]:
        """Get health metrics."""
        lib = _get_lib()
        buf = ctypes.create_string_buffer(4096)
        rc = lib.avis_health(self._ptr, buf, len(buf))
        if rc <= 0:
            raise RuntimeError("Health check failed")
        return json.loads(buf.value.decode('utf-8'))


# Convenience functions
def capture(url: str, graph_path: str = "vision.avis") -> int:
    """Capture a URL to graph."""
    g = VisionGraph(graph_path)
    result = g.capture(url)
    g.save()
    return result

def query(url: str, graph_path: str = "vision.avis") -> Optional[Dict[str, Any]]:
    """Query a URL from graph."""
    g = VisionGraph(graph_path)
    return g.query(url)

def compare(id1: int, id2: int, graph_path: str = "vision.avis") -> Dict[str, Any]:
    """Compare two captures."""
    g = VisionGraph(graph_path)
    return g.compare(id1, id2)

def diff(url: str, graph_path: str = "vision.avis") -> Dict[str, Any]:
    """Get diff for URL (latest vs previous)."""
    g = VisionGraph(graph_path)
    # Implementation depends on FFI
    raise NotImplementedError("diff requires FFI extension")

def similar(url: str, graph_path: str = "vision.avis", limit: int = 10) -> List[Dict[str, Any]]:
    """Find similar captures."""
    g = VisionGraph(graph_path)
    # Implementation depends on FFI
    raise NotImplementedError("similar requires FFI extension")

def health(graph_path: str = "vision.avis") -> Dict[str, Any]:
    """Get graph health."""
    g = VisionGraph(graph_path)
    return g.health()
```

---

## Codebase PyPI Package

### python/pyproject.toml

```toml
[build-system]
requires = ["setuptools>=61.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "agentic-codebase"
version = "0.1.0"
description = "Semantic code compiler for AI agents"
readme = "README.md"
license = {text = "MIT"}
authors = [{name = "Agentra Labs", email = "contact@agentralabs.tech"}]
classifiers = [
    "Development Status :: 4 - Beta",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.9",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Topic :: Software Development :: Libraries :: Python Modules",
    "Topic :: Scientific/Engineering :: Artificial Intelligence",
]
keywords = ["ai", "agents", "codebase", "semantic", "analysis", "mcp"]
requires-python = ">=3.9"
dependencies = []

[project.optional-dependencies]
dev = ["pytest>=7.0", "pytest-cov>=4.0"]

[project.urls]
Homepage = "https://github.com/agentic-revolution/agentic-codebase"
Documentation = "https://github.com/agentic-revolution/agentic-codebase#readme"
Repository = "https://github.com/agentic-revolution/agentic-codebase"

[tool.setuptools.packages.find]
where = ["src"]

[tool.setuptools.package-data]
agentic_codebase = ["*.so", "*.dylib", "*.dll"]
```

### python/src/agentic_codebase/__init__.py

```python
"""AgenticCodebase - Semantic code compiler for AI agents."""

__version__ = "0.1.0"

from .codebase import (
    CodebaseGraph,
    compile_graph,
    query_structure,
    impact_analysis,
    coupling_analysis,
    test_gap,
    prophecy,
    health,
)

__all__ = [
    "__version__",
    "CodebaseGraph",
    "compile_graph",
    "query_structure",
    "impact_analysis",
    "coupling_analysis",
    "test_gap",
    "prophecy",
    "health",
]
```

### python/src/agentic_codebase/_ffi.py

```python
"""FFI bindings to libagentic_codebase."""

import ctypes
import os
import sys
from pathlib import Path
from typing import Optional

def _find_library() -> str:
    """Find the native library."""
    if sys.platform == "darwin":
        lib_name = "libagentic_codebase.dylib"
    elif sys.platform == "win32":
        lib_name = "agentic_codebase.dll"
    else:
        lib_name = "libagentic_codebase.so"
    
    # Check package directory
    pkg_dir = Path(__file__).parent
    lib_path = pkg_dir / lib_name
    if lib_path.exists():
        return str(lib_path)
    
    # Check common install locations
    for search_path in [
        Path.home() / ".local" / "lib",
        Path("/usr/local/lib"),
        Path("/usr/lib"),
    ]:
        lib_path = search_path / lib_name
        if lib_path.exists():
            return str(lib_path)
    
    raise OSError(f"Cannot find {lib_name}. Install agentic-codebase first.")

# Load library
_lib: Optional[ctypes.CDLL] = None

def _get_lib() -> ctypes.CDLL:
    global _lib
    if _lib is None:
        _lib = ctypes.CDLL(_find_library())
        _setup_functions(_lib)
    return _lib

def _setup_functions(lib: ctypes.CDLL) -> None:
    """Set up function signatures."""
    # acb_graph_new
    lib.acb_graph_new.argtypes = []
    lib.acb_graph_new.restype = ctypes.c_void_p
    
    # acb_graph_free
    lib.acb_graph_free.argtypes = [ctypes.c_void_p]
    lib.acb_graph_free.restype = None
    
    # acb_graph_open
    lib.acb_graph_open.argtypes = [ctypes.c_char_p]
    lib.acb_graph_open.restype = ctypes.c_void_p
    
    # acb_graph_save
    lib.acb_graph_save.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.acb_graph_save.restype = ctypes.c_int32
    
    # acb_compile
    lib.acb_compile.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.acb_compile.restype = ctypes.c_int32
    
    # acb_query
    lib.acb_query.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
    lib.acb_query.restype = ctypes.c_int32
    
    # acb_impact
    lib.acb_impact.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
    lib.acb_impact.restype = ctypes.c_int32
    
    # acb_coupling
    lib.acb_coupling.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]
    lib.acb_coupling.restype = ctypes.c_int32
    
    # acb_test_gap
    lib.acb_test_gap.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]
    lib.acb_test_gap.restype = ctypes.c_int32
    
    # acb_prophecy
    lib.acb_prophecy.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
    lib.acb_prophecy.restype = ctypes.c_int32
    
    # acb_unit_count
    lib.acb_unit_count.argtypes = [ctypes.c_void_p]
    lib.acb_unit_count.restype = ctypes.c_uint64
    
    # acb_health
    lib.acb_health.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]
    lib.acb_health.restype = ctypes.c_int32
```

### python/src/agentic_codebase/codebase.py

```python
"""High-level Codebase API."""

import json
from pathlib import Path
from typing import Optional, Dict, Any, List
from ._ffi import _get_lib
import ctypes

class CodebaseGraph:
    """A codebase graph for semantic analysis."""
    
    def __init__(self, path: Optional[str] = None):
        lib = _get_lib()
        if path and Path(path).exists():
            self._ptr = lib.acb_graph_open(path.encode('utf-8'))
            if not self._ptr:
                raise IOError(f"Failed to open codebase graph: {path}")
        else:
            self._ptr = lib.acb_graph_new()
            if not self._ptr:
                raise MemoryError("Failed to create codebase graph")
        self._path = path
    
    def __del__(self):
        if hasattr(self, '_ptr') and self._ptr:
            _get_lib().acb_graph_free(self._ptr)
    
    def save(self, path: Optional[str] = None) -> None:
        """Save graph to file."""
        save_path = path or self._path
        if not save_path:
            raise ValueError("No path specified")
        lib = _get_lib()
        rc = lib.acb_graph_save(self._ptr, save_path.encode('utf-8'))
        if rc != 0:
            raise IOError(f"Failed to save codebase graph: {save_path}")
    
    def compile(self, project_path: str) -> None:
        """Compile project into graph."""
        lib = _get_lib()
        rc = lib.acb_compile(self._ptr, project_path.encode('utf-8'))
        if rc != 0:
            raise RuntimeError(f"Compile failed: {project_path}")
    
    def query(self, query_str: str) -> Dict[str, Any]:
        """Query the codebase."""
        lib = _get_lib()
        buf = ctypes.create_string_buffer(65536)
        rc = lib.acb_query(self._ptr, query_str.encode('utf-8'), buf, len(buf))
        if rc <= 0:
            raise RuntimeError(f"Query failed: {query_str}")
        return json.loads(buf.value.decode('utf-8'))
    
    def impact_analysis(self, file_path: str) -> Dict[str, Any]:
        """Analyze impact of changing a file."""
        lib = _get_lib()
        buf = ctypes.create_string_buffer(65536)
        rc = lib.acb_impact(self._ptr, file_path.encode('utf-8'), buf, len(buf))
        if rc <= 0:
            raise RuntimeError(f"Impact analysis failed: {file_path}")
        return json.loads(buf.value.decode('utf-8'))
    
    def coupling_analysis(self) -> Dict[str, Any]:
        """Analyze coupling in codebase."""
        lib = _get_lib()
        buf = ctypes.create_string_buffer(65536)
        rc = lib.acb_coupling(self._ptr, buf, len(buf))
        if rc <= 0:
            raise RuntimeError("Coupling analysis failed")
        return json.loads(buf.value.decode('utf-8'))
    
    def test_gap(self) -> Dict[str, Any]:
        """Find test coverage gaps."""
        lib = _get_lib()
        buf = ctypes.create_string_buffer(65536)
        rc = lib.acb_test_gap(self._ptr, buf, len(buf))
        if rc <= 0:
            raise RuntimeError("Test gap analysis failed")
        return json.loads(buf.value.decode('utf-8'))
    
    def prophecy(self, question: str) -> Dict[str, Any]:
        """Ask a prophecy question about the codebase."""
        lib = _get_lib()
        buf = ctypes.create_string_buffer(65536)
        rc = lib.acb_prophecy(self._ptr, question.encode('utf-8'), buf, len(buf))
        if rc <= 0:
            raise RuntimeError(f"Prophecy failed: {question}")
        return json.loads(buf.value.decode('utf-8'))
    
    @property
    def unit_count(self) -> int:
        """Get number of code units."""
        return _get_lib().acb_unit_count(self._ptr)
    
    def health(self) -> Dict[str, Any]:
        """Get health metrics."""
        lib = _get_lib()
        buf = ctypes.create_string_buffer(4096)
        rc = lib.acb_health(self._ptr, buf, len(buf))
        if rc <= 0:
            raise RuntimeError("Health check failed")
        return json.loads(buf.value.decode('utf-8'))


# Convenience functions
def compile_graph(project_path: str, graph_path: str = "codebase.acb") -> CodebaseGraph:
    """Compile project into graph."""
    g = CodebaseGraph()
    g.compile(project_path)
    g.save(graph_path)
    return g

def query_structure(query: str, graph_path: str = "codebase.acb") -> Dict[str, Any]:
    """Query codebase structure."""
    g = CodebaseGraph(graph_path)
    return g.query(query)

def impact_analysis(file_path: str, graph_path: str = "codebase.acb") -> Dict[str, Any]:
    """Analyze impact of file change."""
    g = CodebaseGraph(graph_path)
    return g.impact_analysis(file_path)

def coupling_analysis(graph_path: str = "codebase.acb") -> Dict[str, Any]:
    """Get coupling analysis."""
    g = CodebaseGraph(graph_path)
    return g.coupling_analysis()

def test_gap(graph_path: str = "codebase.acb") -> Dict[str, Any]:
    """Find test gaps."""
    g = CodebaseGraph(graph_path)
    return g.test_gap()

def prophecy(question: str, graph_path: str = "codebase.acb") -> Dict[str, Any]:
    """Ask prophecy question."""
    g = CodebaseGraph(graph_path)
    return g.prophecy(question)

def health(graph_path: str = "codebase.acb") -> Dict[str, Any]:
    """Get graph health."""
    g = CodebaseGraph(graph_path)
    return g.health()
```

---

## Claude Code Instructions

Use this as the task for Claude Code to execute:

```
TASK: PyPI Backfill for Vision + Codebase

1. Vision PyPI Package
   - Create python/ directory in agentic-vision repo
   - Add pyproject.toml, __init__.py, _ffi.py, vision.py from spec above
   - Verify FFI function names match actual C API
   - Add tests/test_vision.py with basic tests
   - Build wheel: python -m build
   - Test locally: pip install dist/*.whl && python -c "import agentic_vision"
   - Publish: twine upload dist/*

2. Codebase PyPI Package  
   - Create python/ directory in agentic-codebase repo
   - Add pyproject.toml, __init__.py, _ffi.py, codebase.py from spec above
   - Verify FFI function names match actual C API
   - Add tests/test_codebase.py with basic tests
   - Build wheel: python -m build
   - Test locally: pip install dist/*.whl && python -c "import agentic_codebase"
   - Publish: twine upload dist/*

3. Integration Test (all 4)
   - pip install agentic-memory agentic-vision agentic-codebase agentic-identity
   - Create test script that imports all 4
   - Verify no conflicts
```

---

## After Backfill: Test All Together

```python
# test_all_sisters.py
import agentic_memory
import agentic_vision  
import agentic_codebase
import agentic_identity

print(f"Memory: {agentic_memory.__version__}")
print(f"Vision: {agentic_vision.__version__}")
print(f"Codebase: {agentic_codebase.__version__}")
print(f"Identity: {agentic_identity.__version__}")

# Quick functional test
mem = agentic_memory.MemoryGraph()
# vis = agentic_vision.VisionGraph()  
# code = agentic_codebase.CodebaseGraph()
# ident = agentic_identity.Identity("test-agent")

print("All sisters imported successfully!")
```
