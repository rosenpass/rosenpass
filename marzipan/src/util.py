from typing import Callable, Any, Tuple, List, TypeVar
from types import ModuleType as Module
from importlib import import_module
from dataclasses import dataclass

T = TypeVar('T')

def setup_exports() -> Tuple[List[str], Callable[[T], T]]:
    __all__ = []

    """
    Helper to provide an export() function with little boilerplate.

    ```
    from marzipan.util import setup_exports
    (__all__, export) = setup_exports()
    ```
    """
    def export(what: T) -> T:
        match what:
            case str():
                __all__.append(what)
            case object(__name__ = name):
                __all__.append(name)
            case _:
                raise TypeError(
                    f"Unsupported export type `{what}`: Export is neither `str` nor has it an attribute named `__name__`.")
        return what

    return (__all__, export)

(__all__, export) = setup_exports()
export(setup_exports)

@export
def attempt(fn):
    # TODO: Documentation tests
    """
    Call a function returning a tuple of (result, exception).

    The following example uses safe_call to implement a checked_divide
    function that returns None if the division by zero is caught.

    ```python
    try_divide = attempt(lambda a, b: a/b)

    def checked_divide(a, b):
        match try_divide(a, b):
            case (result, None):
                return result
            case (None, ZeroDivisionError()):
                return None
            case _:
                raise RuntimeError("Unreachable")

    assert(checked_divide(1, 0) == None)
    assert(checked_divide(0, 1) == 0)
    assert(checked_divide(1, 1) == 1)
    ```
    """
    def retfn(*args, **kwargs):
        try:
            return (fn(*args, **kwargs), None)
        except Exception as e:
            return (None, e)
    retfn.__name__ = f"try_{fn.__name__}"
    return retfn

@export
def scoped(fn: Callable[[], Any]) -> Any:
    """
    Scoped variable assignment.

    Just an alias for `call`. Use as a decorator to immediately call a function,
    assigning the return value to the function name.
    """
    return fn()

@export
def try_import(name : str) -> Tuple[Module | None, Exception | None]:
    return attempt(import_module)(name)

@dataclass(frozen=True)
class Pkgs:
    __mod__: Module | None
    __prefix__: str | None

    def __get__(self, k: str):
        return getattr(self, k)

    def __getattribute__(self, k: str):
        match k:
            case "__mod__" | "__prefix__" | "__class__":
                # Access the underlying module value
                return super().__getattribute__(k)

        match self:
            case Pkgs(None, None):
                # Import package from root
                return Pkgs(import_module(k), k)

        # Try importing a subpackage
        name = f"{self.__prefix__}.{k}"
        match try_import(name):
            case (child, None):
                # Imported subpackage
                return Pkgs(child, name)
            case (_, ModuleNotFoundError()):
                # No such module; access module property instead
                return getattr(self.__mod__, k)
            case (_, err):
                # Unknown error, pass error on
                raise err

@scoped
@export
def pkgs() -> Pkgs:
    """
    Global package scope.

    `pkgs.marzipan` imports the package `marzipan`
    """
    return Pkgs(None, None)
