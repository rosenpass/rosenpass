from collections.abc import Mapping
from typing import Any, Iterator


class AttrMap(Mapping):
    """
    Small wrapper so that dict values can be accessed as {ctx.foo}
    instead of only {ctx["foo"]} inside our custom format strings.
    """

    def __init__(self, mapping: Mapping[str, Any]):
        self._mapping = mapping

    def __getattr__(self, name: str) -> Any:
        try:
            return self._mapping[name]
        except KeyError:
            raise AttributeError(name) from None

    def __getitem__(self, name: str) -> Any:
        return self._mapping[name]

    def __contains__(self, key: object) -> bool:
        return key in self._mapping

    def __str__(self) -> str:
        return str(self._mapping)

    def __iter__(self) -> Iterator[Any]:
        return self._mapping.__iter__()

    def __len__(self) -> int:
        return len(self._mapping)
